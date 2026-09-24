# Dev Plan

## Task #1 — Migrate CLI entry points from argparse to click

**Status:** deferred, not started.

**Why deferred:** touches every script's argument handling; doing it alongside the
`--adapter`/model-passthrough change (see below) risked regressing the CLI right
when we need it working for day-to-day use. Splitting it into its own change lets
each one be tested in isolation.

**Scope — 7 argparse-based entry points:**
- `src/ql_agent.py` — main pipeline entry point, wrapped by `run_cve.sh`. Highest
  priority: this is where `--agent`/`--adapter` and `--model` live, and where the
  SPL.py-style adapter conventions (`spl/cli.py`, `spl/adapters/`) were used as the
  reference.
- `scripts/get_cve_repos.py`
- `scripts/build_codeql_dbs.py`
- `scripts/cves_fetcher.py`
- `scripts/cwe_fetcher.py`
- `scripts/codeql_docs_fetcher.py`
- `scripts/delete_cve_analysis_collections.py`

**Decision needed before starting:** convert just `src/ql_agent.py`, or all 7
scripts for a consistent CLI across the repo (more files touched, more surface to
test). Ask before picking — this was explicitly punted on 2026-09-23.

**Notes for whoever picks this up:**
- `click` is already available in the dev environment but not yet declared in
  `environment.yml` or the `Dockerfile`'s pip install list — add it there.
- Keep `run_cve.sh`'s `"$@"` passthrough compatible — it forwards raw flags to
  `python3 src/ql_agent.py`, so whatever flag names/behavior click ends up with
  need to stay consistent with what `run_cve.sh` and the README document.
- The `--model` argument was deliberately changed (2026-09-23) to accept
  free-form strings instead of a fixed `choices=[...]` list, so new model names
  (e.g. `claude-sonnet-5`) don't require a code change — preserve that
  passthrough behavior in the click version rather than reintroducing an enum.
- `--agent`/`--adapter` currently share one `dest` via argparse's
  `add_argument("--agent", "--adapter", ...)` for backward compatibility; click's
  equivalent is multiple `param_decls` on one `click.option(...)`.

## Task #2 — Add `--adapter claude_cli --model claude-sonnet-5` support (subscription billing)

**Status:** done (2026-09-23).

**What changed:**
- `src/ql_agent.py` — `--agent` now accepts `--adapter` as an alias for the same
  `dest` (`add_argument("--agent", "--adapter", dest="agent", ...)`). `--model`
  dropped its hardcoded `choices=[...]` list and now accepts any string, so new
  model ids (e.g. `claude-sonnet-5`) work without a code change. Removed the
  dead, unused, stale top-of-file `MODELS` dict that duplicated
  `claude_backend.py`'s.
- `src/agent_backends/claude_backend.py` — added `"sonnet-5": "claude-sonnet-5"`
  to the `MODELS` alias map; unrecognized strings already pass straight through
  to the `claude` CLI's own `--model` flag via `MODELS.get(self.model, self.model)`.
- `src/agent_backends/claude_cli_backend.py` — unchanged; it already stripped
  `ANTHROPIC_API_KEY`/`ANTHROPIC_BASE_URL`/session-guard vars before invoking
  `claude`, which is what makes subscription billing work once `--adapter
  claude_cli` is selected.
- `README.md` — documented the `--adapter` alias, the `sonnet-5` alias, and a
  `--adapter claude_cli --model claude-sonnet-5` usage example.

**Verified:** `python3 -m py_compile` on both edited files; `--help` output
shows the `--adapter` alias; a direct `argparse.parse_args(['--adapter',
'claude_cli', '--model', 'claude-sonnet-5', ...])` test resolves to
`agent='claude_cli', model='claude-sonnet-5'`.

## Task #3 — Write `docs/GUIDE/TUTORIAL.md`

**Status:** done (2026-09-23).

Step-by-step guide covering both Docker and native (Linux) setup paths, using
`CVE-2025-27818` (already in `data/project_info.csv`) as the worked example.
Includes a dedicated section on Claude Code subscription billing (Task #2),
a model/agent reference table, ablation-mode reference, Chroma
cleanup, and a troubleshooting section. See
[`../GUIDE/TUTORIAL.md`](../GUIDE/TUTORIAL.md).
