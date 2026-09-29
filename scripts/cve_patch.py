#!/usr/bin/env python3
"""(b) cve_patch.py -- direct agentic triage, step 2: patch.

Given `cve_findings.yaml` from cve_detect.py, ask a coding agent to actually
fix each finding -- either a dependency-version bump (if it points at a
third-party library) or a direct source-code change -- working on a fresh
local clone of the checked-out repo so the original vulnerable checkout
cve_detect.py reasoned about is left untouched.

Output is `cve_patch.yaml`: one entry per fix, each with a name, a
description, and the *actual* on-disk code at that location after the
agent's edit (read straight from the patched file, never the agent's own
copy-pasted snippet) -- so the complete set of changes can be reviewed in
one YAML file, plus the full unified diff for completeness. Second of three
reports (cve_findings.yaml -> cve_patch.yaml -> cve_verified.yaml).

Usage:
    python3 scripts/cve_patch.py --report output/triage/CVE-2026-27825/cve_findings.yaml
    python3 scripts/cve_patch.py --report .../cve_findings.yaml --dry-run
"""
import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts import triage_common as tc

PROMPT_TEMPLATE = """You are fixing real, confirmed security findings directly in this codebase.
A prior triage pass already reviewed the code and reported these findings:

## Findings (from prior triage)

CVE: {cve_id}
Overall verdict: vulnerable={overall_vulnerable} (confidence={overall_confidence})

{findings_block}

## Your task

For each finding above that you confirm is real:
1. Read the cited location yourself to confirm it.
2. Fix it with the smallest correct change:
   - If the vulnerable code lives in a third-party dependency (not this
     repo's own source), bump the pinned version in the appropriate
     manifest (requirements.txt/pyproject.toml/package.json/pom.xml/etc.)
     to the first version that fixes it, if you can determine one from
     public knowledge; otherwise fix the code directly.
   - Otherwise, edit the source directly. Do not refactor unrelated code.
3. Do NOT commit your changes -- leave them as uncommitted working-tree
   edits; the caller will capture `git diff` itself.

If a finding turns out to be a false positive on closer reading, say so in
its entry instead of forcing a fix -- do not invent unnecessary changes.

## Required output format

End your reply with exactly one fenced YAML block, one entry per finding
you acted on (skip findings you concluded were false positives, and say why
in `notes`):

```yaml
patch_strategy: dependency_upgrade | code_change | mixed | unable_to_fix
fixes:
  - finding_id: <id from the findings above>
    fix_name: <short, human-readable name for this fix>
    fix_description: |
      <what you changed and why, in your own words>
    file: <relative path to the fixed file>
    lines: "<start>-<end>"
      # the line range of the FIXED code in this file, after your edit --
      # the caller will read exactly these lines back off disk for the
      # audit report, so make sure the range is accurate post-edit.
confidence: <0-100 integer, your honest confidence the fix is correct and sufficient>
notes: <caveats, false positives skipped and why, things you couldn't verify, etc.>
```
"""


def format_findings_block(findings: list) -> str:
    if not findings:
        return "(no findings listed)"
    lines = []
    for f in findings:
        lines.append(
            f"- id: {f.get('id')}\n"
            f"  file: {f.get('file')}\n"
            f"  lines: {f.get('lines')}\n"
            f"  description: {f.get('description')}\n"
            f"  confidence: {f.get('confidence')}"
        )
    return "\n".join(lines)


def build_prompt(cve_id: str, detect_report: dict) -> str:
    return PROMPT_TEMPLATE.format(
        cve_id=cve_id,
        overall_vulnerable=detect_report.get("overall_vulnerable", "unknown"),
        overall_confidence=detect_report.get("overall_confidence", "?"),
        findings_block=format_findings_block(detect_report.get("findings") or []),
    )


def capture_diff(repo_dir: str) -> str:
    try:
        result = subprocess.run(
            ["git", "diff"], cwd=repo_dir, capture_output=True, text=True, check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"(error capturing diff: {e.stderr})"


_DRY_RUN_STUB = (
    "patch_strategy: unable_to_fix\nfixes: []\nconfidence: 0\nnotes: dry-run"
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report", required=True, help="Path to cve_findings.yaml")
    parser.add_argument("--force", action="store_true", help="Patch even if cve_findings.yaml says not vulnerable")
    parser.add_argument("--agent", choices=["claude", "claude_cli"], default="claude_cli")
    parser.add_argument("--model", default="sonnet-5")
    parser.add_argument("--max-turns", type=int, default=40)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--output", help="Report path (default: output/triage/<CVE-ID>/cve_patch.yaml)")
    parser.add_argument("--dry-run", action="store_true", help="Build the prompt but don't call the agent")
    args = parser.parse_args(argv)

    detect_report = tc.load_report(args.report)
    cve_id = detect_report["cve_id"]
    output_path = args.output or tc.default_report_path(cve_id, "cve_patch.yaml")

    verdict = detect_report.get("overall_vulnerable")
    if verdict not in (True, "true", "unknown") and not args.force:
        print(f"cve_findings.yaml says vulnerable={verdict!r} for {cve_id} -- nothing to patch.")
        print("Pass --force to patch anyway.")
        tc.write_report(output_path, {
            "cve_id": cve_id, "generated_at": tc.timestamp(),
            "skipped": True, "reason": f"cve_findings.yaml verdict was vulnerable={verdict!r}",
        })
        return

    src_repo_dir = detect_report["repo_dir"]
    patched_repo_dir = src_repo_dir.rstrip("/") + "-patched"
    print(f"[1/4] Cloning {src_repo_dir} -> {patched_repo_dir} (isolated working copy)...")
    if not tc.clone_local(src_repo_dir, patched_repo_dir, detect_report["vulnerable_commit"]):
        print("  Error: could not create patch working copy.")
        sys.exit(1)

    print(f"[2/4] Asking the agent ({args.agent}/{args.model}) to fix {len(detect_report.get('findings') or [])} finding(s)...")
    prompt = build_prompt(cve_id, detect_report)
    result = tc.run_agent_cli(
        prompt, cwd=patched_repo_dir, agent=args.agent, model=args.model,
        allowed_tools="Read,Grep,Glob,Edit,Write,Bash(git:*)",
        max_turns=args.max_turns, timeout=args.timeout, dry_run=args.dry_run,
        dry_run_stub_yaml=_DRY_RUN_STUB,
    )
    if result.get("error"):
        print(f"  Error: {result['error']}")

    patch_info = tc.extract_yaml_block(result["text"])

    print(f"[3/4] Reading the actual fixed code off disk for each fix (never trusting the agent's own copy)...")
    fixes = []
    for fix in (patch_info.get("fixes") or []):
        fixed_code = (
            tc.read_file_lines(patched_repo_dir, fix["file"], fix.get("lines"))
            if not args.dry_run and fix.get("file")
            else "(dry-run: no changes made)"
        )
        fixes.append({
            "finding_id": fix.get("finding_id"),
            "fix_name": fix.get("fix_name"),
            "fix_description": fix.get("fix_description"),
            "file": fix.get("file"),
            "lines": fix.get("lines"),
            "fixed_code": fixed_code,
        })

    diff = capture_diff(patched_repo_dir) if not args.dry_run else "(dry-run: no changes made)"

    print(f"[4/4] Writing report...")
    report = {
        "cve_id": cve_id,
        "generated_at": tc.timestamp(),
        "agent": args.agent,
        "model": args.model,
        "dry_run": args.dry_run,
        "findings_report_path": args.report,
        "vulnerable_repo_dir": src_repo_dir,
        "patched_repo_dir": patched_repo_dir,
        "vulnerable_commit": detect_report["vulnerable_commit"],
        "patch_strategy": patch_info.get("patch_strategy", "unknown"),
        "fixes": fixes,
        "confidence": patch_info.get("confidence"),
        "notes": patch_info.get("notes"),
        "full_diff": diff,
        "_agent_raw": {"returncode": result["returncode"], "stderr": result["stderr"][-2000:]},
    }
    tc.write_report(output_path, report)

    print(f"\nPatch strategy: {report['patch_strategy']}, {len(fixes)} fix(es)")
    print(f"Patched repo: {patched_repo_dir}")
    print(f"Next: python3 scripts/cve_verify.py --report {output_path}")


if __name__ == "__main__":
    main()
