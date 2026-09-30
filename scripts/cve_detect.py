#!/usr/bin/env python3
"""(1/detect) cve_detect.py -- direct agentic triage, step 1: detect.

Given `cve-1-metadata.yaml` from cve_spec.py, ask a coding agent to directly
read the code (already checked out at the vulnerable commit by the spec
step) and judge whether the described vulnerability is actually present and
reachable -- no CodeQL database, no CodeQL LSP server, no vector DB. Only
the CVE's own public description/CWE (from the spec) is given to the agent
as a hint of *what* to look for; the known fix location (if QLCoder already
has it in fix_info*.csv) is carried through the spec but never shown to the
agent, so its finding is a genuine independent judgment, not a lookup.

Output is `cve-2-findings.yaml` -- one entry per finding, each with the
exact file path and affected line(s). Second of five reports
(cve-1-metadata.yaml -> cve-2-findings.yaml -> cve-3-fixes.yaml ->
cve-4-tests.yaml -> cve-5-pipeline.yaml) forming a complete, auditable
trace of the detect/patch/verify work on this CVE.
See docs/DEV/readme-approach.md section 6 for the design this implements.

Usage:
    python3 scripts/cve_detect.py --in output/triage/CVE-2026-27825/cve-1-metadata.yaml
    python3 scripts/cve_detect.py --in .../cve-1-metadata.yaml --dry-run
    python3 scripts/cve_detect.py --in .../cve-1-metadata.yaml --iter 2
    python3 scripts/cve_detect.py --in .../cve-1-metadata.yaml --max-iters 3
"""
import argparse
import contextlib
import os
import sys
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts import triage_common as tc

_INTRO = """You are performing a security triage review, reading real source code
directly -- there is no static-analysis tool involved. Judge for yourself
whether the described vulnerability is genuinely present and reachable in
this exact codebase, at this exact commit.

"""

_CVE_METADATA = """## CVE metadata (from the National Vulnerability Database)

CVE ID: {cve_id}
Description: {description}
CWE: {cwe_ids} ({cwe_descriptions})
CVSS severity: {cvss_severity}

"""

_TASK = """## Your task

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

"""

# With --skills the methodology lives in src/skills/detect/**/SKILL.md; the
# prompt keeps only the task framing and the output schema, which code
# parses and validates.
_SKILL_TASK = """## Your task

The repository at the current working directory is checked out at the
commit believed to be vulnerable. You do NOT know in advance which file or
function is affected.

Before doing anything else, load and follow these skills with the Skill
tool: {skill_names}. They describe the method, the {language} specifics, and
what to avoid (in particular, do not look for the upstream fix). Detection
only -- do not modify any file.

"""

_OUTPUT_FORMAT = """## Required output format

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


_RETRY_NOTE_TEMPLATE = """
## Note: this is a retry

Your previous attempt was rejected: {issue}
Please try again, making sure to end your reply with exactly one fenced
```yaml block matching the schema below, with a decisive `overall_vulnerable`
(true or false, not "unknown" unless the evidence is genuinely too weak to
call either way).
"""


PROMPT_TEMPLATE = _INTRO + _CVE_METADATA + _TASK + _OUTPUT_FORMAT
SKILL_PROMPT_TEMPLATE = _INTRO + _CVE_METADATA + _SKILL_TASK + _OUTPUT_FORMAT


def build_prompt(cve_id: str, nvd_metadata: dict, retry_issue: Optional[str] = None,
                 skill_names: Optional[List[str]] = None, language: Optional[str] = None) -> str:
    template = SKILL_PROMPT_TEMPLATE if skill_names else PROMPT_TEMPLATE
    prompt = template.format(
        cve_id=cve_id,
        description=nvd_metadata.get("description") or "(no NVD description available)",
        cwe_ids=nvd_metadata.get("cwe_ids") or "(unknown)",
        cwe_descriptions=nvd_metadata.get("cwe_descriptions") or "",
        cvss_severity=nvd_metadata.get("cvss_v31_severity") or nvd_metadata.get("cvss_v2_severity") or "(unknown)",
        skill_names=", ".join(f"`{n}`" for n in skill_names or []),
        language=language or "language-specific",
    )
    if retry_issue:
        prompt = _RETRY_NOTE_TEMPLATE.format(issue=retry_issue) + "\n" + prompt
    return prompt


def _attempt_issue(analysis: dict) -> Optional[str]:
    """Why this attempt's output isn't usable yet, or None if it's fine."""
    if analysis.get("_parse_error"):
        return "your reply did not include a fenced ```yaml block matching the required schema"
    if analysis.get("overall_vulnerable") not in (True, False, "true", "false"):
        return "overall_vulnerable was left as \"unknown\" or missing"
    return None


_DRY_RUN_STUB = (
    "overall_vulnerable: unknown\noverall_confidence: 0\nreasoning: |\n  dry-run, agent not invoked.\n"
    "findings: []\nnotes: dry-run"
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--in", dest="input_path", required=True,
                         help="Path to a cve-1-metadata.yaml report (see scripts/cve_spec.py)")
    parser.add_argument("--agent", choices=["claude", "claude_cli"], default="claude_cli")
    parser.add_argument("--model", default="sonnet-5")
    parser.add_argument("--max-turns", type=int, default=30)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--iter", dest="iter_num", type=int, default=None,
                         help="Refinement-attempt number; suffixes the default --out path with -iter-<N>")
    parser.add_argument("--max-iters", type=int, default=1,
                         help="Retry the agent call up to N times if its reply doesn't parse or leaves "
                              "overall_vulnerable as 'unknown' (default: 1, no retry)")
    parser.add_argument("--out", dest="output_path",
                         help="Report path (default: output/triage/<CVE-ID>/cve-2-findings.yaml, "
                              "or .../cve-2-findings-iter-<N>.yaml with --iter)")
    parser.add_argument("--skills", action="store_true",
                         help="Give the agent the detect skills from src/skills/detect (common + the CVE's "
                              "language) instead of the long inline methodology prompt")
    parser.add_argument("--dry-run", action="store_true", help="Build the prompt but don't call the agent")
    args = parser.parse_args(argv)

    spec = tc.load_report(args.input_path)
    cve_id = spec["cve_id"]
    output_path = args.output_path or tc.default_report_path(cve_id, "cve-2-findings.yaml", args.iter_num)

    repo_dir = spec.get("repo_dir")
    if not repo_dir or not os.path.isdir(repo_dir):
        print(f"  Error: --in's repo_dir does not exist: {repo_dir!r}. Re-run scripts/cve_spec.py.")
        sys.exit(1)
    print(f"  Repo: {repo_dir}")
    max_attempts = 1 if args.dry_run else args.max_iters
    language = spec.get("language")
    nvd_metadata = spec.get("nvd_metadata") or {}
    attempts_log = []
    analysis, result, retry_issue = {}, {}, None
    for attempt in range(1, max_attempts + 1):
        print(f"[1/2] Asking the agent ({args.agent}/{args.model}) to triage the code directly "
              f"(attempt {attempt}/{max_attempts})...")
        # A dry run only names the skills; it never writes into the checkout.
        skills_ctx = (tc.skills_installed("detect", language, repo_dir)
                      if args.skills and not args.dry_run else contextlib.nullcontext(
                          tc.available_skill_names("detect", language) if args.skills else []))
        with skills_ctx as skill_names:
            if args.skills and attempt == 1:
                print(f"  Skills: {', '.join(skill_names) or '(none found)'} (language={language})")
            prompt = build_prompt(cve_id, nvd_metadata, retry_issue, skill_names or None, language)
            result = tc.run_agent_cli(
                prompt, cwd=repo_dir, agent=args.agent, model=args.model,
                allowed_tools="Read,Grep,Glob,Bash(git:*)" + (",Skill" if skill_names else ""),
                max_turns=args.max_turns, timeout=args.timeout, dry_run=args.dry_run,
                dry_run_stub_yaml=_DRY_RUN_STUB,
            )
        if result.get("error"):
            print(f"  Error: {result['error']}")

        analysis = tc.extract_yaml_block(result["text"])
        retry_issue = _attempt_issue(analysis)
        attempts_log.append({
            "attempt": attempt, "parsed_ok": not analysis.get("_parse_error"),
            "overall_vulnerable": analysis.get("overall_vulnerable"),
        })
        if retry_issue is None:
            break
        if attempt < max_attempts:
            print(f"  Attempt {attempt} was inconclusive ({retry_issue}); retrying...")

    print(f"[2/2] Writing report...")
    report = {
        "cve_id": cve_id,
        "generated_at": tc.timestamp(),
        "agent": args.agent,
        "model": args.model,
        "dry_run": args.dry_run,
        "in_path": args.input_path,
        "repo_dir": repo_dir,
        "github_url": spec.get("github_url"),
        "vulnerable_commit": spec.get("vulnerable_commit"),
        "nvd_metadata": spec.get("nvd_metadata"),
        "overall_vulnerable": analysis.get("overall_vulnerable", "unknown"),
        "overall_confidence": analysis.get("overall_confidence"),
        "reasoning": analysis.get("reasoning"),
        "findings": analysis.get("findings") or [],
        "notes": analysis.get("notes"),
        "attempts": attempts_log,
        "_known_fix_hints_not_shown_to_agent": spec.get("_known_fix_hints_not_shown_to_agent") or [],
        "_agent_raw": {"returncode": result["returncode"], "stderr": result["stderr"][-2000:]},
    }
    tc.write_report(output_path, report)

    verdict = report["overall_vulnerable"]
    confidence = report["overall_confidence"]
    n_findings = len(report["findings"])
    print(f"\nVerdict: vulnerable={verdict} (confidence={confidence}), {n_findings} finding(s)")
    print(f"Next: python3 scripts/cve_patch.py --in {output_path}")


if __name__ == "__main__":
    main()
