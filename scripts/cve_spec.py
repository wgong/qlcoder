#!/usr/bin/env python3
"""(0/spec) cve_spec.py -- direct agentic triage, step 0: spec.

Given a CVE ID, gather the deterministic, non-agentic groundwork the rest
of the pipeline needs: NVD metadata, repo/commit resolution, and a
checked-out vulnerable-commit working copy. No agent call happens in this
step at all -- it's pure data-gathering, kept separate from cve_detect.py's
actual analysis so that step can focus purely on reading code.

Output is `cve-1-metadata.yaml`, consumed by cve_detect.py (step 1) via
--spec instead of each downstream stage re-deriving this itself. First of
five reports (cve-1-metadata.yaml -> cve-2-findings.yaml -> cve-3-fixes.yaml
-> cve-4-tests.yaml -> cve-5-pipeline.yaml) forming a complete, auditable
trace of the detect/patch/verify work on this CVE.
See docs/DEV/readme-approach.md section 6 for the design this implements.

Usage:
    python3 scripts/cve_spec.py --cve-id CVE-2026-27825
    python3 scripts/cve_spec.py --cve-id CVE-9999-00000 \\
        --github-url https://github.com/org/repo --commit <sha>
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts import triage_common as tc
from scripts.cves_fetcher import fetch_cve_from_nvd, create_cve_metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cve-id", required=True)
    parser.add_argument("--github-url", help="Override/supply repo URL if the CVE isn't in project_info*.csv")
    parser.add_argument("--commit", help="Override/supply the vulnerable commit SHA")
    parser.add_argument("--repo-path", help="Use an already-checked-out repo instead of cloning")
    parser.add_argument("--out", dest="output_path",
                         help="Report path (default: output/triage/<CVE-ID>/cve-1-metadata.yaml)")
    args = parser.parse_args(argv)

    cve_id = args.cve_id
    output_path = args.output_path or tc.default_report_path(cve_id, "cve-1-metadata.yaml")

    print(f"[1/3] Fetching NVD metadata for {cve_id}...")
    nvd_raw = fetch_cve_from_nvd(cve_id)
    nvd_metadata = create_cve_metadata(cve_id, nvd_raw)
    if not nvd_raw:
        print(f"  Warning: NVD lookup failed or returned nothing for {cve_id}; "
              f"continuing with whatever repo info is available.")

    print(f"[2/3] Resolving repo/commit and checking out the vulnerable commit...")
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

    if not commit:
        commit = tc.get_head_commit(repo_dir)
        if commit:
            print(f"  No commit resolved from CSV/--commit; using repo's current HEAD: {commit[:12]}")

    print(f"[3/3] Writing spec...")
    known_fix_hints = tc.find_fix_info_rows(cve_id, language)
    report = {
        "cve_id": cve_id,
        "generated_at": tc.timestamp(),
        "language": language,
        "github_url": github_url,
        "vulnerable_commit": commit,
        "repo_dir": repo_dir,
        "nvd_metadata": nvd_metadata,
        "_known_fix_hints_not_shown_to_agent": [
            {"file": r.get("file"), "class": r.get("class"), "method": r.get("method")}
            for r in known_fix_hints
        ],
    }
    tc.write_report(output_path, report)

    print(f"\nSpec ready: {output_path}")
    print(f"Next: python3 scripts/cve_detect.py --in {output_path}")


if __name__ == "__main__":
    main()
