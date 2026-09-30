"""Shared helpers for the direct-agentic-triage prototype.

Three atomic scripts build on this module: `cve_detect.py` (find/verify a
vulnerability), `cve_patch.py` (fix it), `cve_verify.py` (prove the fix
works). Each is runnable standalone and communicates with the next only via
a YAML report on disk -- no shared process, no CodeQL DB/LSP/vector DB.
See docs/DEV/readme-approach.md section 6 for the design this implements.
"""
import contextlib
import csv
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.config import QL_CODER_ROOT_DIR, CVES_PATH

TRIAGE_OUTPUT_DIR = os.path.join(QL_CODER_ROOT_DIR, "output", "triage")
_DATA_DIR = os.path.join(QL_CODER_ROOT_DIR, "data")

# Kept in sync with src/agent_backends/claude_backend.py's MODELS.
MODELS = {
    "sonnet-4": "claude-sonnet-4-20250514",
    "sonnet-4.5": "claude-sonnet-4-5-20250929",
    "sonnet-5": "claude-sonnet-5",
}

# Vars that would route the CLI to paid API billing instead of the local
# Claude Code subscription session -- same list as claude_cli_backend.py.
_STRIP_VARS_FOR_SUBSCRIPTION_AUTH = {
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
}

_SUFFIX_TO_LANGUAGE = {"": "java", "-py": "python", "-js": "javascript"}
_LANGUAGE_TO_SUFFIX = {v: k for k, v in _SUFFIX_TO_LANGUAGE.items()}


def find_cve_row(cve_id: str) -> Tuple[Optional[Dict], Optional[str]]:
    """Scan every data/project_info*.csv for cve_id, independent of whatever
    QLCODER_LANGUAGE happens to be set to right now.

    Returns (row, language); language is inferred from which CSV matched
    (no suffix -> java, -py -> python, -js -> javascript). (None, None) if
    the CVE isn't in QLCoder's seed data at all -- that's fine, it just
    means repo/commit info has to be supplied via --github-url/--commit.
    """
    for path in sorted(glob.glob(os.path.join(_DATA_DIR, "project_info*.csv"))):
        m = re.match(r"project_info(|-py|-js)\.csv$", os.path.basename(path))
        if not m:
            continue
        language = _SUFFIX_TO_LANGUAGE[m.group(1)]
        with open(path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("cve_id", "").strip() == cve_id:
                    return row, language
    return None, None


def find_fix_info_rows(cve_id: str, language: Optional[str]) -> List[Dict]:
    """Ground-truth fix location(s) for a CVE, if QLCoder already has them.

    Reporting/scoring only -- never fed into an agent prompt. The whole
    point of this prototype is testing whether the agent can find the
    vulnerability on its own from public CVE metadata; handing it the
    known fix location first would make that a no-op.
    """
    suffix = _LANGUAGE_TO_SUFFIX.get(language, "") if language else ""
    path = os.path.join(_DATA_DIR, f"fix_info{suffix}.csv")
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [row for row in csv.DictReader(f) if row.get("cve_id", "").strip() == cve_id]


def ensure_repo_checked_out(cve_id: str, row: Dict) -> Optional[str]:
    """Clone + checkout the CVE's repo at its buggy commit, reusing
    get_cve_repos.process_cve and its cves/<CVE-ID>/<repo_name> convention
    so triage output lines up with the rest of QLCoder's data layout.
    """
    from scripts.get_cve_repos import process_cve

    repo_name = row["github_repository_name"]
    repo_dir = os.path.join(CVES_PATH, cve_id, repo_name)
    if os.path.isdir(repo_dir):
        return repo_dir

    cve_info = {
        "github_username": row["github_username"],
        "github_repository_name": repo_name,
        "github_url": row["github_url"],
        "buggy_commit_id": row["buggy_commit_id"],
        "fix_commit_ids": row["fix_commit_ids"].split(";") if row.get("fix_commit_ids") else [],
    }
    return repo_dir if process_cve(cve_id, cve_info) else None


def get_head_commit(repo_dir: str) -> Optional[str]:
    """The repo's current HEAD commit SHA, or None if it can't be determined
    (e.g. not actually a git repo). Used to fill in `vulnerable_commit` when
    a caller supplies --repo-path without --commit -- leaving it unset
    would otherwise crash the later `git checkout None` in clone_local."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def clone_local(src_repo_dir: str, dest_dir: str, checkout_commit: str) -> bool:
    """Cheap local clone (`git clone <local-path>`) so patch/verify steps can
    mutate a separate working copy without touching the vulnerable checkout
    cve_detect.py reasoned about."""
    if os.path.isdir(dest_dir):
        return True
    try:
        subprocess.run(
            ["git", "clone", "--quiet", src_repo_dir, dest_dir],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["git", "checkout", "--quiet", checkout_commit],
            cwd=dest_dir, check=True, capture_output=True, text=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"  Error cloning {src_repo_dir} -> {dest_dir}: {e.stderr}")
        return False


SKILLS_SRC_DIR = os.path.join(QL_CODER_ROOT_DIR, "src", "skills")


def available_skill_names(step: str, language: Optional[str]) -> List[str]:
    """Names (`cve-<step>-common`, `cve-<step>-<language>`) of the skills that
    exist under src/skills/<step>/ for this language. Missing ones are skipped."""
    subs = ["common"] + ([language] if language else [])
    return [f"cve-{step}-{s}" for s in subs
            if os.path.isfile(os.path.join(SKILLS_SRC_DIR, step, s, "SKILL.md"))]


@contextlib.contextmanager
def skills_installed(step: str, language: Optional[str], cwd: str):
    """Copy src/skills/<step>/{common,<language>} into <cwd>/.claude/skills/
    for the duration of one agent call, then remove them.

    Claude Code only discovers `.claude/skills/<name>/SKILL.md`, so each
    source dir is copied under the `name:` in its SKILL.md frontmatter
    (cve-<step>-common, cve-<step>-<language>). `.claude/` is added to the
    checkout's local .git/info/exclude so the copies never show up in
    `git status` or in a patch diff. Yields the installed skill names.
    """
    installed = available_skill_names(step, language)
    skills_root = os.path.join(cwd, ".claude", "skills")
    had_claude_dir = os.path.isdir(os.path.join(cwd, ".claude"))
    for name in installed:
        sub = name[len(f"cve-{step}-"):]
        shutil.copytree(os.path.join(SKILLS_SRC_DIR, step, sub),
                        os.path.join(skills_root, name), dirs_exist_ok=True)
    if installed:
        _exclude_from_git(cwd, ".claude/")
    try:
        yield installed
    finally:
        for name in installed:
            shutil.rmtree(os.path.join(skills_root, name), ignore_errors=True)
        if installed and not had_claude_dir:
            shutil.rmtree(os.path.join(cwd, ".claude"), ignore_errors=True)


def _exclude_from_git(repo_dir: str, pattern: str) -> None:
    """Append `pattern` to the repo's local .git/info/exclude (never committed)."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--git-path", "info/exclude"],
            cwd=repo_dir, check=True, capture_output=True, text=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return  # not a git checkout; nothing to keep clean
    path = out if os.path.isabs(out) else os.path.join(repo_dir, out)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    existing = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
    if pattern not in existing.splitlines():
        with open(path, "a", encoding="utf-8") as f:
            f.write(("" if existing.endswith("\n") or not existing else "\n") + pattern + "\n")


def run_agent_cli(
    prompt: str,
    cwd: str,
    agent: str = "claude_cli",
    model: str = "sonnet-5",
    allowed_tools: str = "Read,Grep,Glob,Bash(git:*)",
    disallowed_tools: str = "",
    max_turns: int = 30,
    timeout: int = 1800,
    dry_run: bool = False,
    dry_run_stub_yaml: Optional[str] = None,
) -> Dict:
    """Invoke the `claude` CLI headless, single turn window. Mirrors
    src/agent_backends/claude_backend.py's execute_prompt, but synchronous,
    standalone, and deliberately without any MCP/CodeQL/Chroma wiring --
    that absence is the entire point of this prototype (see
    docs/DEV/readme-approach.md section 6).
    """
    if dry_run:
        print("--- dry-run: prompt that would be sent to the agent ---")
        print(prompt)
        print("--- end prompt ---")
        stub = dry_run_stub_yaml or (
            "vulnerable: unknown\nconfidence: 0\nreasoning: |\n  dry-run, agent not invoked.\n"
            "evidence: []\nsuggested_fix_locations: []\nnotes: dry-run"
        )
        return {
            "text": f"```yaml\n{stub}\n```",
            "stdout": "", "stderr": "", "returncode": 0, "usage": {},
        }

    cli_path = os.environ.get("CLAUDE_CODE_PATH", shutil.which("claude") or "claude")
    model_id = MODELS.get(model, model)
    cmd = [
        cli_path, "--print", "--output-format", "json",
        "--model", model_id, "--max-turns", str(max_turns),
        "--allowedTools", allowed_tools,
    ]
    if disallowed_tools:
        cmd += ["--disallowedTools", disallowed_tools]

    env = dict(os.environ)
    if agent == "claude_cli":
        env = {k: v for k, v in env.items() if k not in _STRIP_VARS_FOR_SUBSCRIPTION_AUTH}

    try:
        process = subprocess.run(
            cmd, input=prompt, cwd=cwd, env=env,
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        return {
            "text": "", "stdout": e.stdout or "", "stderr": e.stderr or "",
            "returncode": -1, "usage": {}, "error": f"agent CLI timed out after {timeout}s",
        }

    return {
        "text": extract_assistant_text(process.stdout),
        "stdout": process.stdout, "stderr": process.stderr,
        "returncode": process.returncode, "usage": {},
    }


def extract_assistant_text(stdout: str) -> str:
    """Pull the agent's final reply text out of `claude --print` output.

    `claude --print --output-format json` (what run_agent_cli actually
    uses) is NOT a list of turn events -- it's a single JSON object for the
    whole run, with the final assistant text in its `result` field. (A
    list-of-events shape only shows up under `--output-format
    stream-json`, which this codebase doesn't use; handled below too, only
    as a defensive fallback in case that ever changes.) Silently falling
    through to the raw JSON string on a shape mismatch is what caused a
    real bug here before: yaml.safe_load() happily parses JSON (it's a
    YAML subset), so a mis-detected shape doesn't fail loudly -- it just
    silently hands the CLI's own metadata dict back as if it were the
    agent's answer, with all the fields the caller expects simply absent.
    """
    try:
        data = json.loads(stdout)
    except Exception:
        return stdout
    if isinstance(data, dict):
        return data.get("result", stdout)
    if isinstance(data, list):
        parts = []
        for obj in data:
            if isinstance(obj, dict) and obj.get("type") == "assistant":
                blocks = obj.get("message", {}).get("content", [])
                parts += [b["text"] for b in blocks if isinstance(b, dict) and b.get("type") == "text"]
        if parts:
            return "\n\n".join(parts).strip()
    return stdout


_YAML_BLOCK_RE = re.compile(r"```ya?ml\s*\n(.*?)```", re.DOTALL)


def extract_yaml_block(text: str) -> Dict:
    """Pull the LAST fenced ```yaml block out of an agent's free-text reply.

    Last, not first: every prompt in this prototype asks the agent to end
    its reply with one, but across a concatenated multi-turn transcript
    (see extract_assistant_text) an agent occasionally quotes its own
    schema back while explaining the task before actually producing its
    real report later on, so the last match is the more reliable one.
    """
    matches = _YAML_BLOCK_RE.findall(text)
    candidate = matches[-1] if matches else text
    try:
        data = yaml.safe_load(candidate)
        if isinstance(data, dict):
            return data
    except yaml.YAMLError:
        pass
    return {"_parse_error": True, "_raw_text": text}


def write_report(path: str, data: Dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, width=100, allow_unicode=True)
    print(f"  Wrote {path}")


def load_report(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def default_report_path(cve_id: str, filename: str, iter_num: Optional[int] = None) -> str:
    """Default path for one of the cve-<n>-*.yaml reports.

    Pass iter_num for a stage that's looping over refinement attempts
    (currently cve_detect.py / cve_patch.py, via their --iter option) to
    get e.g. cve-3-fixes-iter-2.yaml instead of cve-3-fixes.yaml, so each
    attempt's report is kept rather than overwritten.
    """
    if iter_num is not None:
        name, ext = os.path.splitext(filename)
        filename = f"{name}-iter-{iter_num}{ext}"
    return os.path.join(TRIAGE_OUTPUT_DIR, cve_id, filename)


def read_file_lines(repo_dir: str, rel_path: str, lines: Optional[str]) -> str:
    """Read an inclusive 'start-end' line range straight off disk, for
    embedding the actual current code into an audit report. Deliberately
    never trusts an agent's own copy-pasted snippet -- this reads the real
    file so the report reflects what's really there.
    """
    abs_path = os.path.join(repo_dir, rel_path)
    if not os.path.isfile(abs_path):
        return f"(file not found: {rel_path})"
    with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
    if not lines:
        return "".join(all_lines)
    try:
        start_str, end_str = str(lines).split("-")
        start, end = int(start_str), int(end_str)
    except (ValueError, AttributeError):
        return "".join(all_lines)
    start = max(1, start)
    end = min(len(all_lines), end)
    return "".join(all_lines[start - 1:end])
