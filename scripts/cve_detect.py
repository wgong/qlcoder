#!/usr/bin/env python3
"""(a) cve_detect.py -- direct agentic triage, step 1: detect.

Given a CVE ID, fetch its public metadata from the National Vulnerability
Database, locate (or clone) the affected repo at its vulnerable commit, and
ask a coding agent to directly read the code and judge whether the described
vulnerability is actually present and reachable -- no CodeQL database, no
CodeQL LSP server, no vector DB. Only the CVE's own public description/CWE
is given to the agent as a hint of *what* to look for; the known fix
location (if QLCoder already has it in fix_info*.csv) is never shown to the
agent, so its finding is a genuine independent judgment, not a lookup.

Output is `cve_findings.yaml` -- one entry per finding, each with the exact
file path and affected line(s) -- the first of three reports
(cve_findings.yaml -> cve_patch.yaml -> cve_verified.yaml) meant to form a
complete, auditable trace of the detect/patch/verify work on this CVE.
See docs/DEV/readme-approach.md section 6 for the design this implements.

Usage:
    python3 scripts/cve_detect.py --cve-id CVE-2026-27825
    python3 scripts/cve_detect.py --cve-id CVE-2026-27825 --dry-run
    python3 scripts/cve_detect.py --cve-id CVE-9999-00000 \\
        --github-url https://github.com/org/repo --commit <sha>
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts import triage_common as tc
from scripts.cves_fetcher import fetch_cve_from_nvd, create_cve_metadata

PROMPT_TEMPLATE = """You are performing a security triage review, reading real source code
directly -- there is no static-analysis tool involved. Judge for yourself
whether the described vulnerability is genuinely present and reachable in
this exact codebase, at this exact commit.

## CVE metadata (from the National Vulnerability Database)

CVE ID: {cve_id}
Description: {description}
CWE: {cwe_ids} ({cwe_descriptions})
CVSS severity: {cvss_severity}

## Your task

The repository at the current working directory is checked out at the
commit believed to be vulnerable. You do NOT know in advance which file or
function is affected -- find that out yourself by reading the code,
informed by the CVE description and CWE class above.

1. Search the codebase for code that matches the vulnerability class
   described above (use Grep/Glob/Read; you also have read-only `git`
   access via Bash for history/blame if useful).
2. Decide whether the vulnerability is genuinely present and reachable
   (not just superficially similar code that's actually safe).
3. Record every distinct location that's part of the vulnerability as its
   own finding, each with an exact file path and line range -- if the
   vulnerability spans more than one file/function, list each one
   separately rather than folding them into one finding.
4. Rate your confidence honestly, per finding -- say so plainly if the
   evidence at a given location is weak or ambiguous.

Do not attempt to fix anything in this step -- detection only.

## Required output format

End your reply with exactly one fenced YAML block, matching this schema
exactly (a list under `findings`, one entry per distinct location; empty
list if you conclude nothing is actually vulnerable):

```yaml
overall_vulnerable: true | false | unknown
overall_confidence: <0-100 integer, your honest self-assessed confidence>
reasoning: |
  <your overall reasoning, in your own words>
findings:
  - id: 1
    file: <relative path>
    lines: "<start>-<end>"
    vulnerable: true | false
    description: |
      <what's wrong at this exact location, and why it matters>
    confidence: <0-100 integer>
notes: <anything else worth flagging -- e.g. "only reachable via internal API", caveats, etc.>
```
"""


def build_prompt(cve_id: str, nvd_metadata: dict) -> str:
    return PROMPT_TEMPLATE.format(
        cve_id=cve_id,
        description=nvd_metadata.get("description") or "(no NVD description available)",
        cwe_ids=nvd_metadata.get("cwe_ids") or "(unknown)",
        cwe_descriptions=nvd_metadata.get("cwe_descriptions") or "",
        cvss_severity=nvd_metadata.get("cvss_v31_severity") or nvd_metadata.get("cvss_v2_severity") or "(unknown)",
    )


_DRY_RUN_STUB = (
    "overall_vulnerable: unknown\noverall_confidence: 0\nreasoning: |\n  dry-run, agent not invoked.\n"
    "findings: []\nnotes: dry-run"
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cve-id", required=True)
    parser.add_argument("--github-url", help="Override/supply repo URL if the CVE isn't in project_info*.csv")
    parser.add_argument("--commit", help="Override/supply the vulnerable commit SHA")
    parser.add_argument("--repo-path", help="Use an already-checked-out repo instead of cloning")
    parser.add_argument("--agent", choices=["claude", "claude_cli"], default="claude_cli")
    parser.add_argument("--model", default="sonnet-5")
    parser.add_argument("--max-turns", type=int, default=30)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--output", help="Report path (default: output/triage/<CVE-ID>/cve_findings.yaml)")
    parser.add_argument("--dry-run", action="store_true", help="Build the prompt but don't call the agent")
    args = parser.parse_args(argv)

    cve_id = args.cve_id
    output_path = args.output or tc.default_report_path(cve_id, "cve_findings.yaml")

    print(f"[1/4] Fetching NVD metadata for {cve_id}...")
    nvd_raw = fetch_cve_from_nvd(cve_id)
    nvd_metadata = create_cve_metadata(cve_id, nvd_raw)
    if not nvd_raw:
        print(f"  Warning: NVD lookup failed or returned nothing for {cve_id}; "
              f"continuing with whatever repo info is available.")

    print(f"[2/4] Looking up repo/commit info...")
    row, language = tc.find_cve_row(cve_id)
    if row:
        print(f"  Found in QLCoder seed data (language={language}): {row['github_url']}")
    github_url = args.github_url or (row["github_url"] if row else None)
    commit = args.commit or (row["buggy_commit_id"] if row else None)

    repo_dir = args.repo_path
    if not repo_dir:
        if row:
            repo_dir = tc.ensure_repo_checked_out(cve_id, row)
        elif github_url and commit:
            repo_name = github_url.rstrip("/").split("/")[-1]
            row = {
                "github_username": github_url.rstrip("/").split("/")[-2],
                "github_repository_name": repo_name,
                "github_url": github_url,
                "buggy_commit_id": commit,
                "fix_commit_ids": "",
            }
            repo_dir = tc.ensure_repo_checked_out(cve_id, row)
        else:
            print("  Error: CVE not in project_info*.csv and no --github-url/--commit given.")
            sys.exit(1)

    if not repo_dir or not os.path.isdir(repo_dir):
        print(f"  Error: could not obtain a checked-out repo for {cve_id}.")
        sys.exit(1)
    print(f"  Repo ready at: {repo_dir}")

    print(f"[3/4] Asking the agent ({args.agent}/{args.model}) to triage the code directly...")
    prompt = build_prompt(cve_id, nvd_metadata)
    result = tc.run_agent_cli(
        prompt, cwd=repo_dir, agent=args.agent, model=args.model,
        allowed_tools="Read,Grep,Glob,Bash(git:*)",
        max_turns=args.max_turns, timeout=args.timeout, dry_run=args.dry_run,
        dry_run_stub_yaml=_DRY_RUN_STUB,
    )
    if result.get("error"):
        print(f"  Error: {result['error']}")

    analysis = tc.extract_yaml_block(result["text"])

    print(f"[4/4] Writing report...")
    known_fix_hints = tc.find_fix_info_rows(cve_id, language)
    report = {
        "cve_id": cve_id,
        "generated_at": tc.timestamp(),
        "agent": args.agent,
        "model": args.model,
        "dry_run": args.dry_run,
        "repo_dir": repo_dir,
        "github_url": github_url,
        "vulnerable_commit": commit,
        "nvd_metadata": nvd_metadata,
        "overall_vulnerable": analysis.get("overall_vulnerable", "unknown"),
        "overall_confidence": analysis.get("overall_confidence"),
        "reasoning": analysis.get("reasoning"),
        "findings": analysis.get("findings") or [],
        "notes": analysis.get("notes"),
        "_known_fix_hints_not_shown_to_agent": [
            {"file": r.get("file"), "class": r.get("class"), "method": r.get("method")}
            for r in known_fix_hints
        ],
        "_agent_raw": {"returncode": result["returncode"], "stderr": result["stderr"][-2000:]},
    }
    tc.write_report(output_path, report)

    verdict = report["overall_vulnerable"]
    confidence = report["overall_confidence"]
    n_findings = len(report["findings"])
    print(f"\nVerdict: vulnerable={verdict} (confidence={confidence}), {n_findings} finding(s)")
    print(f"Next: python3 scripts/cve_patch.py --report {output_path}")


if __name__ == "__main__":
    main()
