#!/usr/bin/env python3
"""cve_secure.py -- click CLI orchestrating the direct-agentic-triage prototype.

Wraps cve_detect.py / cve_patch.py / cve_verify.py (see
docs/DEV/readme-approach.md section 6 for the design). Each unit can be run
on its own (`detect`/`patch`/`verify`, one-to-one with the underlying
script's own argparse options, same translation pattern src/cli.py uses for
the CodeQL pipeline's scripts) or chained as a full pipeline (`pipeline`),
which runs cve_detect -> cve_patch -> cve_verify back-to-back using each
stage's own default report path (output/triage/<CVE-ID>/cve_findings.yaml
-> cve_patch.yaml -> cve_verified.yaml), stopping early if an earlier stage
fails or reports the CVE isn't actually vulnerable (unless --force).

Usage:
    python3 scripts/cve_secure.py --help
    python3 scripts/cve_secure.py pipeline --cve-id CVE-2026-27825
    python3 scripts/cve_secure.py pipeline --cve-id CVE-2026-27825 --dry-run
    python3 scripts/cve_secure.py detect --cve-id CVE-2026-27825
    python3 scripts/cve_secure.py patch --report output/triage/CVE-2026-27825/cve_findings.yaml
    python3 scripts/cve_secure.py verify --report output/triage/CVE-2026-27825/cve_patch.yaml
"""
import os
import sys

import click

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scripts import cve_detect, cve_patch, cve_verify
from scripts import triage_common as tc

_AGENT_OPTION = click.option("--agent", type=click.Choice(["claude", "claude_cli"]), default="claude_cli",
                             help="Coding-agent backend to invoke")
_MODEL_OPTION = click.option("--model", default="sonnet-5", help="Model alias (see triage_common.MODELS)")
_MAX_TURNS_OPTION = click.option("--max-turns", type=int, default=None, help="Override the stage's default --max-turns")
_TIMEOUT_OPTION = click.option("--timeout", type=int, default=None, help="Override the stage's default agent-CLI timeout (s)")
_DRY_RUN_OPTION = click.option("--dry-run", is_flag=True, help="Build prompts but don't call the agent (or run tests)")


def _run_stage(name: str, fn, argv: list) -> None:
    """Call a stage script's own main(argv), the same unmodified function
    `python3 scripts/cve_detect.py ...` would run, translating a SystemExit
    with a non-zero code into a clean pipeline abort instead of a traceback."""
    click.echo(f"\n=== {name} ===")
    try:
        fn(argv)
    except SystemExit as e:
        code = e.code or 0
        if code not in (0, None):
            click.echo(f"Stage '{name}' exited with code {code}; stopping pipeline.", err=True)
            sys.exit(code)


@click.group()
def cli():
    """Direct agentic triage: detect -> patch -> verify, no CodeQL DB/LSP/vector DB.

    Each command wraps its underlying scripts/cve_*.py one-to-one; see that
    script's own --help for the canonical option reference.
    """


# --- detect (scripts/cve_detect.py) -------------------------------------

@cli.command("detect")
@click.option("--cve-id", required=True)
@click.option("--github-url", default=None, help="Override/supply repo URL if the CVE isn't in project_info*.csv")
@click.option("--commit", default=None, help="Override/supply the vulnerable commit SHA")
@click.option("--repo-path", default=None, help="Use an already-checked-out repo instead of cloning")
@_AGENT_OPTION
@_MODEL_OPTION
@_MAX_TURNS_OPTION
@_TIMEOUT_OPTION
@click.option("--output", default=None, help="Report path (default: output/triage/<CVE-ID>/cve_findings.yaml)")
@_DRY_RUN_OPTION
def detect_cmd(cve_id, github_url, commit, repo_path, agent, model, max_turns, timeout, output, dry_run):
    """(a) Fetch NVD metadata + triage the code directly -> cve_findings.yaml"""
    argv = _detect_argv(cve_id, github_url, commit, repo_path, agent, model, max_turns, timeout, output, dry_run)
    cve_detect.main(argv)


# --- patch (scripts/cve_patch.py) ---------------------------------------

@cli.command("patch")
@click.option("--report", required=True, help="Path to cve_findings.yaml")
@click.option("--force", is_flag=True, help="Patch even if cve_findings.yaml says not vulnerable")
@_AGENT_OPTION
@_MODEL_OPTION
@_MAX_TURNS_OPTION
@_TIMEOUT_OPTION
@click.option("--output", default=None, help="Report path (default: output/triage/<CVE-ID>/cve_patch.yaml)")
@_DRY_RUN_OPTION
def patch_cmd(report, force, agent, model, max_turns, timeout, output, dry_run):
    """(b) Fix each finding on an isolated clone -> cve_patch.yaml"""
    argv = _patch_argv(report, force, agent, model, max_turns, timeout, output, dry_run)
    cve_patch.main(argv)


# --- verify (scripts/cve_verify.py) -------------------------------------

@cli.command("verify")
@click.option("--report", required=True, help="Path to cve_patch.yaml")
@_AGENT_OPTION
@_MODEL_OPTION
@_MAX_TURNS_OPTION
@_TIMEOUT_OPTION
@click.option("--test-timeout", type=int, default=300, help="Per-run timeout for executing each generated test")
@click.option("--output", default=None, help="Report path (default: output/triage/<CVE-ID>/cve_verified.yaml)")
@_DRY_RUN_OPTION
def verify_cmd(report, agent, model, max_turns, timeout, test_timeout, output, dry_run):
    """(c) Write + run regression tests on both checkouts -> cve_verified.yaml"""
    argv = _verify_argv(report, agent, model, max_turns, timeout, test_timeout, output, dry_run)
    cve_verify.main(argv)


# --- pipeline (all three, chained) --------------------------------------

@cli.command("pipeline")
@click.option("--cve-id", required=True)
@click.option("--github-url", default=None, help="Override/supply repo URL if the CVE isn't in project_info*.csv")
@click.option("--commit", default=None, help="Override/supply the vulnerable commit SHA")
@click.option("--repo-path", default=None, help="Use an already-checked-out repo instead of cloning")
@click.option("--force", is_flag=True, help="Run patch/verify even if cve_findings.yaml says not vulnerable")
@_AGENT_OPTION
@_MODEL_OPTION
@_MAX_TURNS_OPTION
@_TIMEOUT_OPTION
@click.option("--test-timeout", type=int, default=300, help="Per-run timeout for executing each generated test")
@click.option("--stop-after", type=click.Choice(["detect", "patch", "verify"]), default="verify",
              help="Run only up through this stage")
@_DRY_RUN_OPTION
def pipeline_cmd(cve_id, github_url, commit, repo_path, force, agent, model, max_turns, timeout,
                  test_timeout, stop_after, dry_run):
    """Run detect -> patch -> verify back-to-back for one CVE.

    Each stage's own gating still applies: patch/verify decline to run (and
    write a `skipped: true` report) if the previous stage didn't confirm a
    vulnerability, unless --force. The three reports land at their default
    paths under output/triage/<CVE-ID>/, forming one auditable trace.
    """
    findings_path = tc.default_report_path(cve_id, "cve_findings.yaml")
    patch_path = tc.default_report_path(cve_id, "cve_patch.yaml")

    _run_stage("detect", cve_detect.main, _detect_argv(
        cve_id, github_url, commit, repo_path, agent, model, max_turns, timeout, None, dry_run,
    ))
    if stop_after == "detect":
        return

    _run_stage("patch", cve_patch.main, _patch_argv(
        findings_path, force, agent, model, max_turns, timeout, None, dry_run,
    ))
    if stop_after == "patch":
        return

    _run_stage("verify", cve_verify.main, _verify_argv(
        patch_path, agent, model, max_turns, timeout, test_timeout, None, dry_run,
    ))

    click.echo(f"\nDone. Reports:")
    click.echo(f"  {findings_path}")
    click.echo(f"  {patch_path}")
    click.echo(f"  {tc.default_report_path(cve_id, 'cve_verified.yaml')}")


# --- argv builders (translate click-parsed values into each script's own
#     argparse argv, so cve_detect.py/cve_patch.py/cve_verify.py's actual
#     logic runs unmodified either way) -------------------------------------

def _detect_argv(cve_id, github_url, commit, repo_path, agent, model, max_turns, timeout, output, dry_run):
    argv = ["--cve-id", cve_id, "--agent", agent, "--model", model]
    if github_url:
        argv += ["--github-url", github_url]
    if commit:
        argv += ["--commit", commit]
    if repo_path:
        argv += ["--repo-path", repo_path]
    if max_turns is not None:
        argv += ["--max-turns", str(max_turns)]
    if timeout is not None:
        argv += ["--timeout", str(timeout)]
    if output:
        argv += ["--output", output]
    if dry_run:
        argv.append("--dry-run")
    return argv


def _patch_argv(report, force, agent, model, max_turns, timeout, output, dry_run):
    argv = ["--report", report, "--agent", agent, "--model", model]
    if force:
        argv.append("--force")
    if max_turns is not None:
        argv += ["--max-turns", str(max_turns)]
    if timeout is not None:
        argv += ["--timeout", str(timeout)]
    if output:
        argv += ["--output", output]
    if dry_run:
        argv.append("--dry-run")
    return argv


def _verify_argv(report, agent, model, max_turns, timeout, test_timeout, output, dry_run):
    argv = ["--report", report, "--agent", agent, "--model", model, "--test-timeout", str(test_timeout)]
    if max_turns is not None:
        argv += ["--max-turns", str(max_turns)]
    if timeout is not None:
        argv += ["--timeout", str(timeout)]
    if output:
        argv += ["--output", output]
    if dry_run:
        argv.append("--dry-run")
    return argv


if __name__ == "__main__":
    cli()
