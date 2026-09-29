"""Shared helpers for the direct-agentic-triage prototype.

Three atomic scripts build on this module: `cve_detect.py` (find/verify a
vulnerability), `cve_patch.py` (fix it), `cve_verify.py` (prove the fix
works). Each is runnable standalone and communicates with the next only via
a YAML report on disk -- no shared process, no CodeQL DB/LSP/vector DB.
See docs/DEV/readme-approach.md section 6 for the design this implements.
"""
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
    """Pull the final assistant text out of `claude --output-format json` output."""
    try:
        objs = json.loads(stdout)
        if isinstance(objs, list):
            for obj in reversed(objs):
                if obj.get("type") == "assistant":
                    blocks = obj.get("message", {}).get("content", [])
                    parts = [b["text"] for b in blocks if b.get("type") == "text"]
                    if parts:
                        return "\n".join(parts).strip()
    except Exception:
        pass
    return stdout


_YAML_BLOCK_RE = re.compile(r"```ya?ml\s*\n(.*?)```", re.DOTALL)


def extract_yaml_block(text: str) -> Dict:
    """Pull the first fenced ```yaml block out of an agent's free-text reply.
    Every prompt in this prototype asks the agent to end its reply with one."""
    match = _YAML_BLOCK_RE.search(text)
    candidate = match.group(1) if match else text
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


def default_report_path(cve_id: str, filename: str) -> str:
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
