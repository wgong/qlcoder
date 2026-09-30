#!/usr/bin/env python3
"""cve_coder.py -- click CLI orchestrating the direct-agentic-triage prototype.

Wraps cve_spec.py / cve_detect.py / cve_patch.py / cve_verify.py (see
docs/DEV/readme-approach.md section 6 for the design). Each unit can be run
on its own (`spec`/`detect`/`patch`/`verify`, one-to-one with the
underlying script's own argparse options, same translation pattern
src/cli.py uses for the CodeQL pipeline's scripts) or chained as a full
pipeline (`pipeline`), which runs all four back-to-back using each stage's
own default report path:

    cve-1-metadata.yaml -> cve-2-findings.yaml -> cve-3-fixes.yaml -> cve-4-tests.yaml

then writes a fifth summary report, `cve-5-pipeline.yaml`, tying all four
together with an overall status -- so a single run leaves one complete,
auditable trace of the detect/patch/verify work on the CVE.

Every stage but `spec` takes a generic `--in`/`--out` pair (matching the
underlying scripts) rather than stage-specific flag names -- `spec` and
`pipeline` are the only two that take `--cve-id` as their input, since
they're the ones with no earlier report to chain from. `detect`/`patch`
(and `pipeline`, which passes it through to both) also take `--iter <N>`
for re-running a refinement attempt without overwriting the previous one's
report (e.g. `cve-3-fixes-iter-2.yaml`).

Usage:
    python3 scripts/cve_coder.py --help
    python3 scripts/cve_coder.py pipeline --cve-id CVE-2026-27825
    python3 scripts/cve_coder.py pipeline --cve-id CVE-2026-27825 --dry-run
    python3 scripts/cve_coder.py spec --cve-id CVE-2026-27825
    python3 scripts/cve_coder.py detect --in output/triage/CVE-2026-27825/cve-1-metadata.yaml
    python3 scripts/cve_coder.py patch --in output/triage/CVE-2026-27825/cve-2-findings.yaml
    python3 scripts/cve_coder.py verify --in output/triage/CVE-2026-27825/cve-3-fixes.yaml
    python3 scripts/cve_coder.py patch --in .../cve-2-findings.yaml --iter 2
"""
import os
import sys

import click

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scripts import cve_spec, cve_detect, cve_patch, cve_verify
from scripts import triage_common as tc

_AGENT_OPTION = click.option("--agent", type=click.Choice(["claude", "claude_cli"]), default="claude_cli",
                             help="Coding-agent backend to invoke")
_MODEL_OPTION = click.option("--model", default="sonnet-5", help="Model alias (see triage_common.MODELS)")
_MAX_TURNS_OPTION = click.option("--max-turns", type=int, default=None, help="Override the stage's default --max-turns")
_TIMEOUT_OPTION = click.option("--timeout", type=int, default=None, help="Override the stage's default agent-CLI timeout (s)")
_SKILLS_OPTION = click.option("--skills", is_flag=True,
                               help="Detect step: use the skills in src/skills/detect (common + the CVE's language) "
                                    "instead of the long inline prompt")
_DRY_RUN_OPTION = click.option("--dry-run", is_flag=True, help="Build prompts but don't call the agent (or run tests)")
_ITER_OPTION = click.option("--iter", "iter_num", type=int, default=None,
                             help="Refinement-attempt number; suffixes the default --out path with -iter-<N>")
_MAX_ITERS_OPTION = click.option("--max-iters", type=int, default=1,
                                  help="Retry this stage's agent call up to N times if its output isn't usable "
                                       "(default: 1, no retry)")

_STAGE_FILENAMES = {
    "spec": "cve-1-metadata.yaml",
    "detect": "cve-2-findings.yaml",
    "patch": "cve-3-fixes.yaml",
    "verify": "cve-4-tests.yaml",
}


def _run_stage(name: str, fn, argv: list) -> bool:
    """Call a stage script's own main(argv), the same unmodified function
    `python3 scripts/cve_<stage>.py ...` would run, translating a SystemExit
    with a non-zero code into a clean False return instead of a traceback
    or an abrupt process exit -- the caller decides whether/how to still
    write a pipeline summary before stopping."""
    click.echo(f"\n=== {name} ===")
    try:
        fn(argv)
        return True
    except SystemExit as e:
        code = e.code or 0
        if code not in (0, None):
            click.echo(f"Stage '{name}' exited with code {code}.", err=True)
            return False
        return True


@click.group()
def cli():
    """Direct agentic triage: spec -> detect -> patch -> verify, no CodeQL DB/LSP/vector DB.

    Each command wraps its underlying scripts/cve_*.py one-to-one; see that
    script's own --help for the canonical option reference.
    """


# --- spec (scripts/cve_spec.py) -----------------------------------------
# Exception to the --in/--out convention: spec has no earlier report to
# chain from, so its input is --cve-id, same as pipeline's.

@cli.command("spec")
@click.option("--cve-id", required=True)
@click.option("--github-url", default=None, help="Override/supply repo URL if the CVE isn't in project_info*.csv")
@click.option("--commit", default=None, help="Override/supply the vulnerable commit SHA")
@click.option("--repo-path", default=None, help="Use an already-checked-out repo instead of cloning")
@click.option("--out", "out_path", default=None, help="Report path (default: output/triage/<CVE-ID>/cve-1-metadata.yaml)")
def spec_cmd(cve_id, github_url, commit, repo_path, out_path):
    """(0) Fetch NVD metadata + resolve/checkout the repo -> cve-1-metadata.yaml"""
    argv = _spec_argv(cve_id, github_url, commit, repo_path, out_path)
    cve_spec.main(argv)


# --- detect (scripts/cve_detect.py) -------------------------------------

@cli.command("detect")
@click.option("--in", "in_path", required=True, help="Path to a cve-1-metadata.yaml report")
@_AGENT_OPTION
@_MODEL_OPTION
@_MAX_TURNS_OPTION
@_TIMEOUT_OPTION
@_ITER_OPTION
@_MAX_ITERS_OPTION
@click.option("--out", "out_path", default=None,
              help="Report path (default: output/triage/<CVE-ID>/cve-2-findings.yaml, or .../-iter-<N>.yaml with --iter)")
@_SKILLS_OPTION
@_DRY_RUN_OPTION
def detect_cmd(in_path, agent, model, max_turns, timeout, iter_num, max_iters, out_path, skills, dry_run):
    """(1) Triage the code directly, using the spec -> cve-2-findings.yaml"""
    argv = _detect_argv(in_path, agent, model, max_turns, timeout, iter_num, out_path, dry_run,
                        max_iters=max_iters, skills=skills)
    cve_detect.main(argv)


# --- patch (scripts/cve_patch.py) ---------------------------------------

@cli.command("patch")
@click.option("--in", "in_path", required=True, help="Path to a cve-2-findings.yaml report")
@click.option("--force", is_flag=True, help="Patch even if cve-2-findings.yaml says not vulnerable")
@click.option("--feedback", "feedback_path", default=None,
              help="Path to a prior cve-4-tests.yaml (failed verification) to seed this attempt with")
@_AGENT_OPTION
@_MODEL_OPTION
@_MAX_TURNS_OPTION
@_TIMEOUT_OPTION
@_ITER_OPTION
@_MAX_ITERS_OPTION
@click.option("--out", "out_path", default=None,
              help="Report path (default: output/triage/<CVE-ID>/cve-3-fixes.yaml, or .../-iter-<N>.yaml with --iter)")
@_DRY_RUN_OPTION
def patch_cmd(in_path, force, feedback_path, agent, model, max_turns, timeout, iter_num, max_iters, out_path, dry_run):
    """(2) Fix each finding on an isolated clone -> cve-3-fixes.yaml"""
    argv = _patch_argv(in_path, force, agent, model, max_turns, timeout, iter_num, out_path, dry_run,
                        max_iters=max_iters, feedback_path=feedback_path)
    cve_patch.main(argv)


# --- verify (scripts/cve_verify.py) -------------------------------------

@cli.command("verify")
@click.option("--in", "in_path", required=True, help="Path to a cve-3-fixes.yaml report")
@_AGENT_OPTION
@_MODEL_OPTION
@_MAX_TURNS_OPTION
@_TIMEOUT_OPTION
@click.option("--test-timeout", type=int, default=300, help="Per-run timeout for executing each generated test")
@click.option("--out", "out_path", default=None, help="Report path (default: output/triage/<CVE-ID>/cve-4-tests.yaml)")
@_DRY_RUN_OPTION
def verify_cmd(in_path, agent, model, max_turns, timeout, test_timeout, out_path, dry_run):
    """(3) Write + run regression tests on both checkouts -> cve-4-tests.yaml"""
    argv = _verify_argv(in_path, agent, model, max_turns, timeout, test_timeout, out_path, dry_run)
    cve_verify.main(argv)


# --- pipeline (all four, chained) ---------------------------------------
# Exception to the --in/--out convention, same as spec: pipeline's input is
# --cve-id, since it starts the chain from scratch.

@cli.command("pipeline")
@click.option("--cve-id", required=True)
@click.option("--github-url", default=None, help="Override/supply repo URL if the CVE isn't in project_info*.csv")
@click.option("--commit", default=None, help="Override/supply the vulnerable commit SHA")
@click.option("--repo-path", default=None, help="Use an already-checked-out repo instead of cloning")
@click.option("--force", is_flag=True, help="Run patch/verify even if cve-2-findings.yaml says not vulnerable")
@_AGENT_OPTION
@_MODEL_OPTION
@_MAX_TURNS_OPTION
@_TIMEOUT_OPTION
@_ITER_OPTION
@click.option("--max-iters", type=int, default=1,
              help="Max patch+verify rounds to attempt if verify doesn't come back EFFECTIVE (also caps "
                   "cve_detect.py's own internal retry for a decisive answer). Default: 1 (single pass, "
                   "identical to the pre-round-loop behavior). Round outputs are suffixed -iter-<round>; "
                   "cannot be combined with --iter when > 1, since the round loop owns that numbering.")
@click.option("--test-timeout", type=int, default=300, help="Per-run timeout for executing each generated test")
@click.option("--stop-after", type=click.Choice(["spec", "detect", "patch", "verify"]), default="verify",
              help="Run only up through this stage")
@_SKILLS_OPTION
@_DRY_RUN_OPTION
def pipeline_cmd(cve_id, github_url, commit, repo_path, force, agent, model, max_turns, timeout,
                  iter_num, max_iters, test_timeout, stop_after, skills, dry_run):
    """Run spec -> detect -> (patch -> verify)+ for one CVE, then write cve-5-pipeline.yaml.

    Each stage's own gating still applies: patch/verify decline to run (and
    write a `skipped: true` report) if an earlier stage didn't confirm a
    vulnerability, unless --force. With --max-iters 1 (the default) this is
    a single spec -> detect -> patch -> verify pass, --iter (if given)
    labeling the whole run. With --max-iters > 1, patch and verify are
    looped as a round: if a round's verify doesn't come back EFFECTIVE and
    rounds remain, the next round's patch is re-run seeded with that
    round's verify failure (via cve_patch.py's --feedback), until verify
    comes back EFFECTIVE or rounds run out. The reports land at their
    default paths under output/triage/<CVE-ID>/, forming one auditable
    trace.
    """
    if max_iters > 1 and iter_num is not None:
        raise click.UsageError("--iter and --max-iters > 1 can't be combined -- the round loop owns "
                                "the -iter-<N> numbering when --max-iters > 1.")

    paths = {"spec": tc.default_report_path(cve_id, _STAGE_FILENAMES["spec"])}
    ran = []

    ok = _run_stage("spec", cve_spec.main, _spec_argv(cve_id, github_url, commit, repo_path, None))
    ran.append("spec")
    if not ok:
        _write_pipeline_summary(cve_id, paths, ran, stop_after)
        sys.exit(1)
    if stop_after == "spec":
        _write_pipeline_summary(cve_id, paths, ran, stop_after)
        return

    paths["detect"] = tc.default_report_path(cve_id, _STAGE_FILENAMES["detect"], iter_num)
    ok = _run_stage("detect", cve_detect.main, _detect_argv(
        paths["spec"], agent, model, max_turns, timeout, iter_num, None, dry_run, max_iters=max_iters,
        skills=skills,
    ))
    ran.append("detect")
    if not ok:
        _write_pipeline_summary(cve_id, paths, ran, stop_after)
        sys.exit(1)
    if stop_after == "detect":
        _write_pipeline_summary(cve_id, paths, ran, stop_after)
        return

    rounds_run = 0
    feedback_path = None
    patch_ok = verify_ok = True
    for round_num in range(1, max_iters + 1):
        round_iter = round_num if max_iters > 1 else iter_num
        label = f"patch (round {round_num}/{max_iters})" if max_iters > 1 else "patch"
        patch_path = tc.default_report_path(cve_id, _STAGE_FILENAMES["patch"], round_iter)
        patch_ok = _run_stage(label, cve_patch.main, _patch_argv(
            paths["detect"], force, agent, model, max_turns, timeout, round_iter, None, dry_run,
            feedback_path=feedback_path,
        ))
        rounds_run = round_num
        paths["patch"] = patch_path  # only the latest round's paths are kept in the trace
        if not patch_ok or stop_after == "patch":
            break

        verify_path = tc.default_report_path(cve_id, _STAGE_FILENAMES["verify"], round_iter if max_iters > 1 else None)
        label = f"verify (round {round_num}/{max_iters})" if max_iters > 1 else "verify"
        verify_ok = _run_stage(label, cve_verify.main, _verify_argv(
            patch_path, agent, model, max_turns, timeout, test_timeout, verify_path, dry_run,
        ))
        paths["verify"] = verify_path
        if not verify_ok:
            break

        verify_report = tc.load_report(verify_path) if os.path.isfile(verify_path) else {}
        if verify_report.get("skipped") or verify_report.get("overall_verdict") == "EFFECTIVE":
            break
        feedback_path = verify_path  # seed the next round's patch with this round's failure

    ran = [s for s in ("spec", "detect", "patch", "verify") if s in paths]
    if not (patch_ok and verify_ok):
        _write_pipeline_summary(cve_id, paths, ran, stop_after, rounds_run=rounds_run)
        sys.exit(1)
    _write_pipeline_summary(cve_id, paths, ran, stop_after, rounds_run=rounds_run)


# --- cve-5-pipeline.yaml: summary of the whole run ----------------------

def _summarize_stage(stage: str, path: str) -> dict:
    if not os.path.isfile(path):
        return {"path": path, "ran": False}
    data = tc.load_report(path) or {}
    summary = {"path": path, "ran": True, "skipped": bool(data.get("skipped"))}
    if stage == "spec":
        summary.update({
            "github_url": data.get("github_url"),
            "vulnerable_commit": data.get("vulnerable_commit"),
            "repo_dir": data.get("repo_dir"),
        })
    elif stage == "detect":
        summary.update({
            "overall_vulnerable": data.get("overall_vulnerable"),
            "overall_confidence": data.get("overall_confidence"),
            "findings_count": len(data.get("findings") or []),
        })
    elif stage == "patch":
        summary.update({
            "patch_strategy": data.get("patch_strategy"),
            "fixes_count": len(data.get("fixes") or []),
        })
    elif stage == "verify":
        summary.update({
            "overall_verdict": data.get("overall_verdict"),
            "tests_count": len(data.get("tests") or []),
        })
    return summary


def _overall_status(stages: dict, ran: list, stop_after: str) -> str:
    if "verify" in ran:
        if stages["patch"].get("skipped") or stages["verify"].get("skipped"):
            return "SKIPPED_NOT_VULNERABLE"
        return stages["verify"].get("overall_verdict") or "UNKNOWN"
    if "patch" in ran and stages["patch"].get("skipped"):
        return "SKIPPED_NOT_VULNERABLE"
    return f"STOPPED_AFTER_{stop_after.upper()}"


def _write_pipeline_summary(cve_id: str, paths: dict, ran: list, stop_after: str, rounds_run: int = 0) -> None:
    click.echo(f"\n=== pipeline summary ===")
    stages = {stage: _summarize_stage(stage, paths[stage]) for stage in ran}
    summary = {
        "cve_id": cve_id,
        "generated_at": tc.timestamp(),
        "stages_run": ran,
        "stop_after": stop_after,
        "rounds_run": rounds_run,
        **stages,
        "overall_status": _overall_status(stages, ran, stop_after),
    }
    summary_path = tc.default_report_path(cve_id, "cve-5-pipeline.yaml")
    tc.write_report(summary_path, summary)

    click.echo(f"\nDone. Reports:")
    for stage in ran:
        click.echo(f"  {paths[stage]}")
    click.echo(f"  {summary_path}")
    click.echo(f"\nOverall status: {summary['overall_status']}")


# --- argv builders (translate click-parsed values into each script's own
#     argparse argv, so cve_spec.py/cve_detect.py/cve_patch.py/cve_verify.py's
#     actual logic runs unmodified either way) ---------------------------

def _spec_argv(cve_id, github_url, commit, repo_path, out_path):
    argv = ["--cve-id", cve_id]
    if github_url:
        argv += ["--github-url", github_url]
    if commit:
        argv += ["--commit", commit]
    if repo_path:
        argv += ["--repo-path", repo_path]
    if out_path:
        argv += ["--out", out_path]
    return argv


def _detect_argv(in_path, agent, model, max_turns, timeout, iter_num, out_path, dry_run, max_iters=None,
                 skills=False):
    argv = ["--in", in_path, "--agent", agent, "--model", model]
    if max_turns is not None:
        argv += ["--max-turns", str(max_turns)]
    if timeout is not None:
        argv += ["--timeout", str(timeout)]
    if iter_num is not None:
        argv += ["--iter", str(iter_num)]
    if max_iters is not None:
        argv += ["--max-iters", str(max_iters)]
    if out_path:
        argv += ["--out", out_path]
    if skills:
        argv.append("--skills")
    if dry_run:
        argv.append("--dry-run")
    return argv


def _patch_argv(in_path, force, agent, model, max_turns, timeout, iter_num, out_path, dry_run,
                 max_iters=None, feedback_path=None):
    argv = ["--in", in_path, "--agent", agent, "--model", model]
    if force:
        argv.append("--force")
    if feedback_path:
        argv += ["--feedback", feedback_path]
    if max_turns is not None:
        argv += ["--max-turns", str(max_turns)]
    if timeout is not None:
        argv += ["--timeout", str(timeout)]
    if iter_num is not None:
        argv += ["--iter", str(iter_num)]
    if max_iters is not None:
        argv += ["--max-iters", str(max_iters)]
    if out_path:
        argv += ["--out", out_path]
    if dry_run:
        argv.append("--dry-run")
    return argv


def _verify_argv(in_path, agent, model, max_turns, timeout, test_timeout, out_path, dry_run):
    argv = ["--in", in_path, "--agent", agent, "--model", model, "--test-timeout", str(test_timeout)]
    if max_turns is not None:
        argv += ["--max-turns", str(max_turns)]
    if timeout is not None:
        argv += ["--timeout", str(timeout)]
    if out_path:
        argv += ["--out", out_path]
    if dry_run:
        argv.append("--dry-run")
    return argv


if __name__ == "__main__":
    cli()
