# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

QLCoder is a research framework that drives coding-agent CLIs (Claude Code, Gemini CLI, Codex) to iteratively synthesize CodeQL queries that detect a given CVE. Given a CVE's vulnerable/fixed CodeQL databases and fix diff, it runs a multi-phase pipeline that produces, tests, and refines a CodeQL path-query until it flags the vulnerable version and not the fixed version.

## Running the pipeline

Entry point is `src/ql_agent.py`, wrapped by `run_cve.sh` for the Docker workflow:

```sh
./run_cve.sh CVE-2025-27818 --model sonnet-4.5 --max-iteration 10
# equivalent native invocation:
python3 src/ql_agent.py --cve-id CVE-2025-27818 \
  --vuln-db cves/CVE-2025-27818/CVE-2025-27818-vul \
  --fixed-db cves/CVE-2025-27818/CVE-2025-27818-fix \
  --diff cves/CVE-2025-27818/CVE-2025-27818.diff \
  --model sonnet-4.5 --max-iteration 10
```

Key `ql_agent.py` flags: `--agent` (`claude` default, `claude_cli`, `gemini`, `codex`), `--model`, `--ablation-mode` (`full`, `no_tools`, `no_lsp`, `no_docs`, `no_ast`), `--max-iteration`, `--output-dir`.

Prerequisite scripts (run before the pipeline, or via `docker compose run --rm app ...`):
- `scripts/get_cve_repos.py` — clones the CVE repo at the buggy commit and generates the fix diff (CVE must be listed in `data/project_info.csv`)
- `scripts/build_codeql_dbs.py` — builds the vulnerable/fixed CodeQL databases (`--build-mode=none`, no build toolchain needed)
- `scripts/cves_fetcher.py`, `scripts/codeql_docs_fetcher.py`, `scripts/cwe_fetcher.py` — populate the ChromaDB RAG collections (docs/CWE fetchers are one-time; `cves_fetcher.py` re-run after adding CVEs)
- `scripts/delete_cve_analysis_collections.py` — cleans up per-run Chroma collections left over from QLCoder runs

ChromaDB must be reachable: either `docker compose up -d` (HTTP client, `CHROMA_HOST` set) or `chroma run --path data/chroma_db` for native/local runs (PersistentClient). `src/config.py`'s `get_chroma_client()` picks the client type based on whether `CHROMA_HOST` is set.

There is no automated test suite in this repo — validation is done by running the pipeline end-to-end against a CVE and inspecting the generated query/results in `output/`.

## Configuration

All paths and external tool locations are centralized in `src/config.py`, driven by `.env` (see `.env.example`). Notable ones: `CODEQL_HOME`/`CODEQL_PATH`, `CODEQL_LSP_MCP_PATH` (path to the [codeql-lsp-mcp](https://github.com/neuralprogram/codeql-lsp-mcp) server), `SECURITY_QLPACK_PATH`/`LIBRARY_QLPACK_PATH` (version-dependent CodeQL qlpack paths), and Chroma connection settings. `--agent claude_cli` strips `ANTHROPIC_API_KEY`/`ANTHROPIC_BASE_URL` so the `claude` CLI bills against a Claude Code subscription instead of the API key.

## Architecture

### Pipeline phases (`src/ql_agent.py`, class `QLAgentIterative`)

1. **Setup** (`_run_setup_phases`) — prepares the working directory, qlpack, and workspace for the chosen backend.
2. **AST extraction** (`ast_extraction.py`, `run_phase2`) — parses the fix diff to find changed lines, runs CodeQL AST-extraction queries (`src/queries/fetch_class_locs.ql`, `fetch_func_locs.ql`) against both DBs via `run_codeql_query_with_bqrs`, filters nodes to the diff's changed lines, and caches results per-CVE in the `cve_ast_cache` Chroma collection (`AST_CACHE`) so re-runs skip re-extraction (`check_phase2_cache`). Skipped entirely under `--ablation-mode no_ast`.
3. **Iterative query synthesis** (`_run_iterative_phase3`) — for each iteration: builds a prompt (initial or refinement, via the active `AgentBackend`), executes it through the agent CLI (`_execute_single_context_window`), compiles/runs the resulting query against both DBs, and evaluates it (`_test_iteration_query`).
4. **Evaluation & feedback loop** — `query_subagents_evaluation.py`'s `EvaluationCalculator`/`ParallelQueryExecutor` run the query against the vulnerable and fixed DBs in parallel and compare results against ground truth from `evaluation.py`'s `QueryEvaluator` (method-level recall/precision using `CodeLocation`s parsed from the diff). `_is_iteration_successful` and `_generate_feedback` decide whether to stop or produce a refinement prompt for the next iteration.
5. **Metadata/metrics** — `_save_metadata`, `_update_metrics_with_query`, `_create_cost_usage_summary` write iteration results, the final query, and token/cost accounting to `output/`.

`QLAgentIterativeCLI` (also in `ql_agent.py`) is the thin CLI wrapper (`discover_cve_paths`, `analyze_vulnerability`) that `main()` drives.

### Agent backend abstraction (`src/agent_backends/`)

`AgentBackend` (in `__init__.py`) is an ABC that each coding-agent CLI implements: `execute_prompt`, `setup_workspace` (MCP config / settings files), `get_tool_prefix` (e.g. Claude uses `mcp__chroma__`/`mcp__codeql__`; Gemini/Codex use no prefix), `parse_usage` (token/cost parsing from CLI stdout), and `create_refinement_prompt`. `create_backend(agent_type, model, logger, ablation_mode)` is the factory. Implementations: `claude_backend.py` (uses `ANTHROPIC_API_KEY`), `claude_cli_backend.py` (subclasses Claude backend, strips API key env vars to force Claude Code subscription auth), `gemini_backend.py`, `codex_backend.py`. Each backend pairs with a `*_prompts.py` module containing its prompt templates (`claude_prompts.py`, `gemini_prompts.py`, `codex_prompts.py`); `prompt_helpers.py` holds shared prompt-building logic. Gemini's backend returns two prompts (step2 + step3) for iteration 1 via `get_phase3_prompts`; other backends return one.

Ablation modes (`full`, `no_tools`, `no_lsp`, `no_docs`, `no_ast`) gate which tools/context are exposed to the agent and are enforced both in prompt construction and in `AgentBackend.__init__`'s validation against `ABLATION_MODES`.

### Data layer

- `src/data_types.py` — `VulnAnalysisTask` (per-CVE run config: DB paths, diff, model, ablation mode, cache collection names) and `IterationResult` (per-iteration outcome: compilation/execution success, recall/precision counts, eval results).
- ChromaDB collections: `nist_cve_cache` (`NVD_CACHE`, CVE descriptions), `cve_ast_cache` (`AST_CACHE`, extracted AST nodes), plus per-run `cve_analysis_<cve>_<run_id>` collections created during phase 3 for RAG retrieval within a single analysis (cleaned up via `scripts/delete_cve_analysis_collections.py`).
- `data/project_info.csv` / `data/fix_info.csv` — CVE/project metadata (adapted from CWE-Bench-Java), consumed by `scripts/get_cve_repos.py`.
- `cves/<CVE-ID>/` (created by the retrieval scripts, not checked in) — cloned repo checkouts, fix diffs, and the vulnerable/fixed CodeQL databases (`<CVE-ID>-vul`, `<CVE-ID>-fix`) that the pipeline reads.

### Query templates

`src/queries/` holds the CodeQL query templates (`fetch_class_locs.ql`, `fetch_func_locs.ql`) used for AST extraction in phase 2; `qlpack.yml` at the repo root defines the QL pack these run under (copied into each run's working directory as `qlpack_source` in `ql_agent.py`).
