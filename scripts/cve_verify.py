#!/usr/bin/env python3
"""(3/verify) cve_verify.py -- direct agentic triage, step 3: verify.

Given `cve-3-fixes.yaml` from cve_patch.py, ask a coding agent to write one or
more minimal regression tests (ideally one per fix) that reproduce the
underlying vulnerability, then run each test against *both* the original
vulnerable checkout and the patched working copy. A fix is only reported
EFFECTIVE for a given test if that test actually fails on the vulnerable
checkout (demonstrating the bug) and passes clean on the patched one --
a test that doesn't fail on either side is reported INCONCLUSIVE, not
silently treated as a pass.

Output is `cve-4-tests.yaml`: the whole test suite listed one-by-one with
PASS/FAILED results per side, plus an overall verdict. Fourth of five
reports (cve-1-metadata.yaml -> cve-2-findings.yaml -> cve-3-fixes.yaml ->
cve-4-tests.yaml -> cve-5-pipeline.yaml) forming a complete, auditable
trace of the detect/patch/verify work on this CVE.

Usage:
    python3 scripts/cve_verify.py --in output/triage/CVE-2026-27825/cve-3-fixes.yaml
    python3 scripts/cve_verify.py --in .../cve-3-fixes.yaml --dry-run
"""
import argparse
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts import triage_common as tc

PROMPT_TEMPLATE = """You are writing regression tests that prove whether security fixes
actually work. Do not modify any source file -- only add new test file(s).

## Context

CVE: {cve_id}
Patch strategy already applied in this working copy: {patch_strategy}

Fixes already applied here:
{fixes_block}

Full diff already applied here:
```diff
{diff}
```

## Your task

Write one new, minimal, self-contained test file per fix above (or one
combined file covering all of them if that's more natural for this
codebase) that:
- Exercises the vulnerable code path directly (calls the affected
  function/endpoint with an input that would trigger the original
  vulnerability).
- Is written so that it FAILS (non-zero exit, failing assertion, or raised
  exception you assert on) when run against the vulnerable (pre-patch)
  version of this code, and PASSES when run against this patched version.
  Think of each as a regression test for one specific fix, not a general
  test suite.
- Uses this repo's existing test framework/conventions if one is
  detectable (e.g. pytest, jest, mocha, JUnit); otherwise write the
  simplest standalone script that works (e.g. a plain Python script using
  `assert`, executed directly).
- Needs no network access and no unavailable external services.

For each test file, determine the exact shell command to run just that one
test (not the whole suite), runnable from this directory.

## Required output format

End your reply with exactly one fenced YAML block, one entry per test file
you wrote:

```yaml
tests:
  - name: <short, human-readable name for this test>
    targets_finding_id: <finding_id from the fixes above this test targets, or null>
    file: <relative path to the new test file>
    command: <exact shell command to run just this test, from repo root>
    language: <e.g. python, javascript, java>
notes: <anything the verifier should know, e.g. required env vars>
```
"""


def format_fixes_block(fixes: list) -> str:
    if not fixes:
        return "(no fixes listed)"
    lines = []
    for fx in fixes:
        lines.append(
            f"- finding_id: {fx.get('finding_id')}\n"
            f"  fix_name: {fx.get('fix_name')}\n"
            f"  file: {fx.get('file')}\n"
            f"  lines: {fx.get('lines')}\n"
            f"  fix_description: {fx.get('fix_description')}"
        )
    return "\n".join(lines)


def build_prompt(cve_id: str, patch_report: dict) -> str:
    diff = patch_report.get("full_diff") or ""
    return PROMPT_TEMPLATE.format(
        cve_id=cve_id,
        patch_strategy=patch_report.get("patch_strategy", "unknown"),
        fixes_block=format_fixes_block(patch_report.get("fixes") or []),
        diff=diff[:8000] + ("\n... (truncated)" if len(diff) > 8000 else ""),
    )


def run_test(repo_dir: str, test_command: str, timeout: int = 300) -> dict:
    try:
        result = subprocess.run(
            test_command, shell=True, cwd=repo_dir,
            capture_output=True, text=True, timeout=timeout,
        )
        return {
            "exit_code": result.returncode,
            "stdout_tail": result.stdout[-3000:],
            "stderr_tail": result.stderr[-3000:],
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout_tail": "", "stderr_tail": f"timed out after {timeout}s"}


_VERDICT_RANK = {"FIX_FAILED": 0, "INCONCLUSIVE": 1, "EFFECTIVE": 2}

_DRY_RUN_STUB = "tests: []\nnotes: dry-run"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--in", dest="input_path", required=True, help="Path to a cve-3-fixes.yaml report")
    parser.add_argument("--agent", choices=["claude", "claude_cli"], default="claude_cli")
    parser.add_argument("--model", default="sonnet-5")
    parser.add_argument("--max-turns", type=int, default=30)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--test-timeout", type=int, default=300, help="Per-run timeout for executing each generated test")
    parser.add_argument("--out", dest="output_path", help="Report path (default: output/triage/<CVE-ID>/cve-4-tests.yaml)")
    parser.add_argument("--dry-run", action="store_true", help="Build the prompt but don't call the agent or run tests")
    args = parser.parse_args(argv)

    patch_report = tc.load_report(args.input_path)
    cve_id = patch_report["cve_id"]
    output_path = args.output_path or tc.default_report_path(cve_id, "cve-4-tests.yaml")

    if patch_report.get("skipped"):
        print(f"cve-3-fixes.yaml for {cve_id} was skipped ({patch_report.get('reason')}) -- nothing to verify.")
        tc.write_report(output_path, {
            "cve_id": cve_id, "generated_at": tc.timestamp(),
            "skipped": True, "reason": "upstream patch step was skipped",
        })
        return

    patched_repo_dir = patch_report["patched_repo_dir"]
    vulnerable_repo_dir = patch_report["vulnerable_repo_dir"]

    print(f"[1/4] Asking the agent ({args.agent}/{args.model}) to write regression test(s)...")
    prompt = build_prompt(cve_id, patch_report)
    result = tc.run_agent_cli(
        prompt, cwd=patched_repo_dir, agent=args.agent, model=args.model,
        allowed_tools="Read,Grep,Glob,Write,Bash",
        max_turns=args.max_turns, timeout=args.timeout, dry_run=args.dry_run,
        dry_run_stub_yaml=_DRY_RUN_STUB,
    )
    if result.get("error"):
        print(f"  Error: {result['error']}")

    test_plan = tc.extract_yaml_block(result["text"])
    test_entries = test_plan.get("tests") or []

    if args.dry_run:
        tc.write_report(output_path, {
            "cve_id": cve_id, "generated_at": tc.timestamp(), "dry_run": True,
            "tests": [], "overall_verdict": "NO_TESTS", "notes": test_plan.get("notes"),
        })
        print(f"\nDry run complete: {output_path}")
        return

    if not test_entries:
        print("  Error: agent did not produce any usable test entries.")
        tc.write_report(output_path, {
            "cve_id": cve_id, "generated_at": tc.timestamp(),
            "tests": [], "overall_verdict": "NO_TESTS",
            "notes": "agent output did not include a parseable tests: list",
        })
        sys.exit(1)

    print(f"[2/4] Running {len(test_entries)} test(s) against both checkouts...")
    tests_report = []
    for entry in test_entries:
        test_file = entry.get("file")
        test_command = entry.get("command")
        name = entry.get("name") or test_file
        if not test_file or not test_command:
            tests_report.append({**entry, "verdict": "SKIPPED", "notes": "missing file/command"})
            continue

        print(f"  - {name}")
        src_test_path = os.path.join(patched_repo_dir, test_file)
        dest_test_path = os.path.join(vulnerable_repo_dir, test_file)
        if not os.path.isfile(src_test_path):
            tests_report.append({**entry, "verdict": "SKIPPED", "notes": f"test file not found: {test_file}"})
            continue

        os.makedirs(os.path.dirname(dest_test_path) or ".", exist_ok=True)
        shutil.copyfile(src_test_path, dest_test_path)

        print(f"    pre-patch ({vulnerable_repo_dir})...")
        pre = run_test(vulnerable_repo_dir, test_command, timeout=args.test_timeout)
        print(f"    post-patch ({patched_repo_dir})...")
        post = run_test(patched_repo_dir, test_command, timeout=args.test_timeout)

        try:
            os.remove(dest_test_path)
        except OSError:
            pass

        pre_result = "FAILED" if pre["exit_code"] != 0 else "PASS"
        post_result = "PASS" if post["exit_code"] == 0 else "FAILED"
        if pre_result == "FAILED" and post_result == "PASS":
            verdict = "EFFECTIVE"
        elif pre_result == "PASS":
            verdict = "INCONCLUSIVE"
        else:
            verdict = "FIX_FAILED"

        tests_report.append({
            "name": name,
            "targets_finding_id": entry.get("targets_finding_id"),
            "file": test_file,
            "command": test_command,
            "pre_patch_result": pre_result,
            "post_patch_result": post_result,
            "verdict": verdict,
            "pre_patch_output_tail": pre["stdout_tail"] + pre["stderr_tail"],
            "post_patch_output_tail": post["stdout_tail"] + post["stderr_tail"],
        })

    print(f"[3/4] Computing overall verdict...")
    verdicts = [t["verdict"] for t in tests_report if t.get("verdict") in _VERDICT_RANK]
    overall_verdict = min(verdicts, key=lambda v: _VERDICT_RANK[v]) if verdicts else "NO_TESTS"

    print(f"[4/4] Writing report...")
    report = {
        "cve_id": cve_id,
        "generated_at": tc.timestamp(),
        "agent": args.agent,
        "model": args.model,
        "in_path": args.input_path,
        "tests": tests_report,
        "overall_verdict": overall_verdict,
        "notes": test_plan.get("notes"),
    }
    tc.write_report(output_path, report)

    print(f"\nTests: " + ", ".join(f"{t['name']}={t.get('verdict', '?')}" for t in tests_report))
    print(f"Overall verdict: {overall_verdict}")


if __name__ == "__main__":
    main()
