#!/usr/bin/env python3
"""Consolidated click CLI for QLCoder.

This is a NEW, additive entry point — every existing `scripts/*.py` and
`src/ql_agent.py` script keeps working exactly as documented in the README
and TUTORIAL. Each subcommand here defines click options that mirror the
corresponding script's argparse options 1:1, translates the click-parsed
values back into an argv list, and calls that script's own (unmodified)
`main(argv)` function. That means the actual logic executed is identical
either way — this file is a thin, testable translation layer, not a
reimplementation — so you can validate parity by running the same inputs
through both entry points and diffing the output.

Usage:
    python3 src/cli.py --help
    python3 src/cli.py run --cve-id CVE-2025-27818 --adapter claude_cli --model claude-sonnet-5
    python3 src/cli.py get-cve-repos --cve CVE-2025-27818
"""

import asyncio
import os
import sys

import click

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scripts import (  # noqa: E402
    build_codeql_dbs,
    codeql_docs_fetcher,
    cves_fetcher,
    cwe_fetcher,
    delete_cve_analysis_collections,
    get_cve_repos,
)


@click.group()
def cli():
    """QLCoder consolidated CLI.

    Each command wraps an existing script/entry point one-to-one; see that
    script's own --help (e.g. `python3 scripts/get_cve_repos.py --help`)
    for the canonical option reference.
    """


# --- run (src/ql_agent.py) ---------------------------------------------

@cli.command("run")
@click.option("--cve-id", required=True, help="CVE identifier")
@click.option("--vuln-db", default=None, help="Path to vulnerable CodeQL database")
@click.option("--fixed-db", default=None, help="Path to fixed CodeQL database")
@click.option("--diff", default=None, help="Path to fix commit diff file")
@click.option("--output-dir", default="output", help="Output directory")
@click.option("--max-iteration", default=5, type=int, help="Max iterations")
@click.option("--cache-phase-output/--no-cache-phase-output", default=True,
              help="Cache phase output (default: on)")
@click.option("--model", default="sonnet-4",
              help="Model alias or full model id (e.g. sonnet-4.5, claude-sonnet-5)")
@click.option("--agent", "--adapter", "agent", default="claude",
              type=click.Choice(["claude", "claude_cli", "gemini", "codex"]),
              help="Agent backend ('claude_cli'/'--adapter claude_cli' forces "
                   "Claude Code subscription/session auth instead of ANTHROPIC_API_KEY)")
@click.option("--ablation-mode", default="full",
              type=click.Choice(["full", "no_tools", "no_lsp", "no_docs", "no_ast"]),
              help="Ablation mode (default: full)")
def run_cmd(cve_id, vuln_db, fixed_db, diff, output_dir, max_iteration,
            cache_phase_output, model, agent, ablation_mode):
    """Run the QLCoder iterative query-synthesis pipeline for a CVE.

    Equivalent to: python3 src/ql_agent.py --cve-id ...
    """
    # Import lazily: ql_agent.py does argparse-time work (MODELS lookups,
    # config imports) that's cheaper to defer until this subcommand runs.
    import ql_agent

    argv = ["--cve-id", cve_id, "--output-dir", output_dir,
            "--max-iteration", str(max_iteration),
            "--model", model, "--agent", agent,
            "--ablation-mode", ablation_mode]
    if vuln_db:
        argv += ["--vuln-db", vuln_db]
    if fixed_db:
        argv += ["--fixed-db", fixed_db]
    if diff:
        argv += ["--diff", diff]
    argv.append("--cache-phase-output" if cache_phase_output else "--no-cache-phase-output")

    asyncio.run(ql_agent.main(argv))


# --- get-cve-repos (scripts/get_cve_repos.py) ---------------------------

@cli.command("get-cve-repos")
@click.option("--cve", default=None, help="Process a single CVE (e.g., CVE-2018-9159)")
@click.option("--cves", default=None, help="Process multiple CVEs, comma-separated")
@click.option("--cve-file", default=None, help="Process CVEs from a file (one CVE ID per line)")
@click.option("--all", "all_cves", is_flag=True, default=False,
              help="Process all CVEs in project_info.csv")
@click.option("--force", is_flag=True, default=False,
              help="Regenerate diffs even if they already exist")
def get_cve_repos_cmd(cve, cves, cve_file, all_cves, force):
    """Clone CVE repos and generate fix diffs.

    Equivalent to: python3 scripts/get_cve_repos.py ...
    Exactly one of --cve / --cves / --cve-file / --all is required.
    """
    selected = [v for v in (cve, cves, cve_file, all_cves) if v]
    if len(selected) != 1:
        raise click.UsageError("Exactly one of --cve, --cves, --cve-file, --all is required.")

    argv = []
    if cve:
        argv += ["--cve", cve]
    elif cves:
        argv += ["--cves", cves]
    elif cve_file:
        argv += ["--cve-file", cve_file]
    elif all_cves:
        argv.append("--all")
    if force:
        argv.append("--force")

    get_cve_repos.main(argv)


# --- build-dbs (scripts/build_codeql_dbs.py) -----------------------------

@cli.command("build-dbs")
@click.option("--cve-dir", default=None, help="Path to CVE directory (default: data/../cves)")
@click.option("--cve-id", default=None, help="Specific CVE ID to process")
@click.option("--parallel", is_flag=True, default=False, help="Enable parallel processing")
@click.option("--max-workers", default=4, type=int, help="Maximum number of parallel workers")
def build_dbs_cmd(cve_dir, cve_id, parallel, max_workers):
    """Build vulnerable/fixed CodeQL databases (--build-mode=none).

    Equivalent to: python3 scripts/build_codeql_dbs.py ...
    """
    argv = ["--max-workers", str(max_workers)]
    if cve_dir:
        argv += ["--cve-dir", cve_dir]
    if cve_id:
        argv += ["--cve-id", cve_id]
    if parallel:
        argv.append("--parallel")

    build_codeql_dbs.main(argv)


# --- fetch-cves (scripts/cves_fetcher.py) --------------------------------

@cli.command("fetch-cves")
@click.option("--api-key", default=None, help="NVD API key (optional, helps with rate limiting)")
@click.option("--batch-size", default=50, type=int, help="Number of CVEs per batch")
@click.option("--test", is_flag=True, default=False, help="Test with only first 3 CVEs")
@click.option("--delay", default=0.6, type=float, help="Delay between API requests in seconds")
@click.option("--descriptions-file", default=None,
              help="Fetch CVE descriptions and save to this JSON file instead of populating Chroma")
def fetch_cves_cmd(api_key, batch_size, test, delay, descriptions_file):
    """Populate the CVE-description RAG collection from NVD.

    Equivalent to: python3 scripts/cves_fetcher.py ...
    """
    argv = ["--batch-size", str(batch_size), "--delay", str(delay)]
    if api_key:
        argv += ["--api-key", api_key]
    if test:
        argv.append("--test")
    if descriptions_file:
        argv += ["--descriptions-file", descriptions_file]

    cves_fetcher.main(argv)


# --- fetch-cwe (scripts/cwe_fetcher.py) ----------------------------------

@cli.command("fetch-cwe")
@click.option("--workers", default=4, type=int, help="Number of concurrent workers")
def fetch_cwe_cmd(workers):
    """Fetch CWE data and store in ChromaDB.

    Equivalent to: python3 scripts/cwe_fetcher.py ...
    """
    cwe_fetcher.main(["--workers", str(workers)])


# --- fetch-docs (scripts/codeql_docs_fetcher.py) -------------------------

@cli.command("fetch-docs")
@click.option("--data-dir", default=None, help="ChromaDB data directory")
@click.option("--workers", default=8, type=int, help="Number of parallel workers")
@click.option("--local-codeql-library-path", default=None,
              help="Path to local CodeQL queries and libraries")
@click.option("--local-codeql-security-pack-path", default=None,
              help="Path to local CodeQL security queries")
def fetch_docs_cmd(data_dir, workers, local_codeql_library_path, local_codeql_security_pack_path):
    """Fetch CodeQL documentation and store in ChromaDB.

    Equivalent to: python3 scripts/codeql_docs_fetcher.py ...
    """
    argv = ["--workers", str(workers)]
    if data_dir:
        argv += ["--data-dir", data_dir]
    if local_codeql_library_path:
        argv += ["--local-codeql-library-path", local_codeql_library_path]
    if local_codeql_security_pack_path:
        argv += ["--local-codeql-security-pack-path", local_codeql_security_pack_path]

    codeql_docs_fetcher.main(argv)


# --- delete-collections (scripts/delete_cve_analysis_collections.py) -----

@cli.command("delete-collections")
@click.option("--confirm", is_flag=True, default=False,
              help="Actually delete collections (without this flag, runs in dry-run mode)")
@click.option("--db-path", default=None, help="Path to Chroma database")
def delete_collections_cmd(confirm, db_path):
    """Delete cve_analysis_* Chroma collections left over from QLCoder runs.

    Equivalent to: python3 scripts/delete_cve_analysis_collections.py ...
    """
    argv = []
    if confirm:
        argv.append("--confirm")
    if db_path:
        argv += ["--db-path", db_path]

    delete_cve_analysis_collections.main(argv)


if __name__ == "__main__":
    cli(prog_name="qlcoder")
