# Dev Plan

## Task #1 — Consolidated click CLI wrapping existing scripts

**Status:** implemented (2026-09-25), pending user validation.

**Approach taken (revised from the original "migrate to click" framing):** to
avoid any regression risk, none of the 7 existing argparse-based entry points
were replaced or deprecated. Every one keeps working exactly as before,
standalone (`python3 scripts/get_cve_repos.py ...`, `python3
src/ql_agent.py ...`, `run_cve.sh ...`). A new, additive `src/cli.py` click CLI
sits alongside them: each click subcommand defines options that mirror the
underlying script's argparse options 1:1, translates the click-parsed values
back into an `argv` list, and calls that script's own **unmodified** `main(argv)`
function. So the click CLI and the original script share the exact same
implementation — click is only a translation layer — which is what makes
side-by-side parity testing meaningful rather than trusting a
reimplementation.

**What changed:**
- Added `argv=None` parameter to `main()` in all 7 entry points (a
  behavior-preserving change: `parser.parse_args(argv)` with `argv=None`
  defaults to `sys.argv[1:]`, identical to before):
  `src/ql_agent.py`, `scripts/get_cve_repos.py`, `scripts/build_codeql_dbs.py`,
  `scripts/cwe_fetcher.py`, `scripts/codeql_docs_fetcher.py`,
  `scripts/cves_fetcher.py` (also extracted its bare `if __name__ ==
  "__main__":` block into a proper `main(argv=None)` function),
  `scripts/delete_cve_analysis_collections.py`.
- Added `scripts/__init__.py` (empty) so `scripts` is an importable package.
- New `src/cli.py` — click group `cli` with 7 subcommands: `run`,
  `get-cve-repos`, `build-dbs`, `fetch-cves`, `fetch-cwe`, `fetch-docs`,
  `delete-collections`. Usage: `python3 src/cli.py <command> --help`.
- `environment.yml` / `Dockerfile` — added `click` as a pip dependency.

**Bug found and fixed as a prerequisite (unrelated to click):**
`scripts/delete_cve_analysis_collections.py` was missing the
`sys.path.insert(...)` line that its 5 sibling scripts all have, so
`from src.config import ...` raised `ModuleNotFoundError: No module named
'src'` when run natively without `PYTHONPATH` set — confirmed broken before
the fix, confirmed fixed after. Added the same `sys.path.insert(0,
os.path.dirname(os.path.dirname(os.path.abspath(__file__))))` line the
other scripts use.

**Bug found, NOT fixed (out of scope for this task, flagged for later):**
in the same file, `get_all_collections()` and `delete_cve_analysis_collections()`
both do `client = get_chroma_client` (missing `()`) instead of
`client = get_chroma_client()` — assigns the function object itself instead of
calling it, so `client.list_collections()` / `client.delete_collection(...)`
fail with `AttributeError`. Confirmed via `python3 -m py_compile` +
`--help`/dry-run smoke tests that this pre-existing bug reproduces identically
through both the direct script and the new click command (`Error getting
collections: 'function' object has no attribute 'list_collections'`) — i.e.
parity holds, but the underlying feature is currently non-functional either
way until this is fixed.

**Verified:**
- `python3 -m py_compile` clean on all 7 edited files plus `src/cli.py`.
- All 7 scripts' own `--help` still exits 0 with unchanged usage text
  (standalone invocation unaffected).
- `python3 src/cli.py --help` and every subcommand's `--help` render with
  options matching the source script's argparse options.
- Parity spot-checks: `get-cve-repos` with no flags gives the same
  "exactly one required" error (exit 2) via both click and the raw script;
  `delete-collections` dry-run output is byte-for-byte identical between
  `python3 src/cli.py delete-collections` and
  `python3 scripts/delete_cve_analysis_collections.py` (including the
  bug above reproducing the same way).

**Not done / left for the user to validate:** the actual network/DB-touching
commands (`get-cve-repos` cloning a real repo, `build-dbs`, `fetch-cves`,
`fetch-cwe`, `fetch-docs`, and the real `run` pipeline) were only `--help`-
and dry-run-tested, not run end-to-end, since that means live network calls,
CodeQL DB builds, and Chroma writes — exactly the side-by-side validation
the user asked to do themselves.

**`qlcoder` binary added (2026-09-25):** `bin/qlcoder` is a plain bash wrapper
(`exec python3 "$REPO_ROOT/src/cli.py" "$@"`), symlinked into `~/.local/bin`
so `qlcoder <command>` works from anywhere. Deliberately **not** a `pip
install -e .` console-script entry point like `spl3` in `SPL.py` — this
machine's shared conda env already has other projects editable-installed
with equally generic top-level module names, and this repo's own code
already imports itself as bare top-level modules (`config`, `utils`,
`data_types`, ... — see the `except ImportError:` fallback in
`src/ql_agent.py`), so a real entry point here would risk colliding with
another project's editable install in the same env. The wrapper always
resolves its own symlink target, so it tracks the working tree (`git pull`
takes effect immediately, no reinstall step). `cli(prog_name="qlcoder")` was
set in `src/cli.py` so `--help` shows `qlcoder ...` instead of `cli.py ...`
regardless of which of the two invocation styles is used.

**Original "migrate to click" idea, still open if wanted later:**
replacing/deprecating the argparse scripts entirely (rather than keeping both)
was explicitly ruled out for now — revisit only if the user decides the
duplication (one argparse `main()` + one click wrapper per script) isn't worth
carrying long-term.

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
