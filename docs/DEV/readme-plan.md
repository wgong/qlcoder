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

## Task #4 — Fix Kafka CVE convergence/timeout, make Java hardcoding configurable, add Python support

**Status:** done (2026-09-29). JavaScript/Node.js deferred (see bottom).

**Motivation:** a real run against a Kafka CVE (`CVE-2025-27818`, large
multi-module Maven project) took ~8 min/iteration and failed to converge
after 5 iterations. Investigating that surfaced that the framework's
"Java" support wasn't actually configurable — it was hardcoded throughout
(qlpack dependency, AST-extraction query templates, evaluation-logic file
filters, DB-build script, agent prompts) — blocking the user's ask to add
Python/Node.js support, since they're more familiar with those languages
and wanted faster iteration than large Java codebases allow.

### 4a. Iteration timeout/convergence fix

`src/query_subagents_evaluation.py`'s CodeQL subprocess calls (`query run`,
`bqrs decode`, `database analyze`, `database cleanup`) had **no timeouts** —
unlike the separate (and not actually used in the iteration loop)
`evaluation.py` path, which does use 300s timeouts. A hanging/slow `codeql`
invocation on a large DB could therefore silently consume the whole
iteration with no ceiling.

**What changed:**
- Added a shared `_run_subprocess(cmd, timeout, step_name)` helper in
  `query_subagents_evaluation.py` wrapping every CodeQL subprocess call in
  `asyncio.wait_for`, killing the process on timeout instead of hanging:
  `QUERY_RUN_TIMEOUT=600`, `BQRS_DECODE_TIMEOUT=120`,
  `SARIF_ANALYZE_TIMEOUT=1800`, `CACHE_CLEANUP_TIMEOUT=120`.
- Dropped the forced `--rerun` flag on `codeql database analyze` — each
  iteration's query differs anyway (different compiled digest), so
  `--rerun` wasn't buying correctness, only cost.
- `QueryExecutionSubagent.cleanup_database_cache` (renamed from private
  `_cleanup_database_cache`) is no longer called after every single
  iteration — clearing the CodeQL evaluator cache that often forced full
  cold-cache re-evaluation on every iteration. New module function
  `cleanup_databases_after_run(vuln_db_path, fixed_db_path, logger)` runs it
  once, after the whole iteration loop ends (both the success and
  max-iterations exit paths of `_run_iterative_phase3` in `src/ql_agent.py`).

**Verified:** unit-level (timeouts fire and kill the process, cache-cleanup
call sites moved correctly, syntax/import checks); **not** verified against
a real Kafka run in this session (no CodeQL bundle exercised end-to-end
here) — the user should confirm the speedup on their next real run.

### 4b. Language support made configurable (`src/config.py`)

**What changed:**
- `LANGUAGE` (`"java"` default, `"python"`, `"javascript"`) is now a single
  process-wide constant, computed once from environment at import time
  (`_detect_language()`), instead of being hardcoded as `"java"` string
  literals scattered across the codebase.
- `.env` config: `QLCODER_LANGUAGE` (explicit language selector) and
  `QLPACK_PATH` (base dir holding your CodeQL bundle's per-language
  qlpacks) are now the primary, explicit knobs. `SECURITY_QLPACK_PATH`/
  `LIBRARY_QLPACK_PATH` are optional — left blank, they're **auto-derived**
  from `QLCODER_LANGUAGE` + `QLPACK_PATH` via a new `_find_qlpack_subpath()`
  helper that auto-detects whichever qlpack `<version>` is actually
  installed (no more manual `ls .../java-queries/` + copy-paste); setting
  either path explicitly still overrides the derivation, for non-standard
  CodeQL installs. `.env.example` and the user's own `.env` updated to the
  new format.
- `PROJECT_INFO`/`FIX_INFO` now resolve to `data/project_info.csv` /
  `data/fix_info.csv` (java, unsuffixed, unchanged), `data/project_info-py.csv`
  / `data/fix_info-py.csv` (python), or `-js.csv` (javascript, not yet
  created) based on `LANGUAGE`.
- `qlpack.yml` now declares `codeql/java-all`, `codeql/python-all`, and
  `codeql/javascript-all` as dependencies unconditionally — simpler than
  per-language qlpack files, and harmless since CodeQL only resolves the
  library a given query actually `import`s, and every official CodeQL
  bundle ships all three locally (no registry/network access needed for
  `codeql pack install`).
- `src/queries/fetch_class_locs.ql`/`fetch_func_locs.ql` renamed to
  `..._java.ql`; new `..._python.ql` variants added (CodeQL Python's
  `Class`/`Function` library classes). `src/evaluation.py`'s
  `_load_project_structure` now runs `fetch_class_locs_{LANGUAGE}.ql`.
  **Not yet compile-tested against a real CodeQL Python DB** — flagged as
  the one step that can't be verified by reading code alone.
- `src/ast_extraction.py`'s dynamically-built diff-AST query templatized:
  `import java`/`@id java/...` → `import {LANGUAGE}`/`@id {LANGUAGE}/...`.
- `src/evaluation.py` / `src/query_subagents_evaluation.py`: replaced
  `.java`-only suffix checks (`_is_test_file`, `_extract_fixed_locations`,
  `_format_location`/`_format_location_simple`) with a
  `LANGUAGE_EXTENSIONS` set keyed by `LANGUAGE` (`(".java",)` /
  `(".py",)` / `(".js", ".jsx", ".ts", ".tsx")`).
- `scripts/build_codeql_dbs.py`: `--language` flag to `codeql database
  create` now uses `LANGUAGE` instead of a literal `"java"`;
  `find_project_source_directory` generalized to also recognize
  `pyproject.toml`/`setup.py`/`requirements.txt` (python) and
  `package.json` (javascript, untested) project roots, alongside the
  existing Maven/Gradle markers; `db-java` on-disk naming convention →
  `db-{LANGUAGE}`.
- Agent prompts (`src/agent_backends/prompt_helpers.py` +
  `claude_prompts.py`/`codex_prompts.py`/`gemini_prompts.py`): the
  Java-only example query skeletons (`import java`,
  `semmle.code.java.dataflow.DataFlow`), the hardcoded `codeql_java_stdlib`
  RAG collection name, and "List ONLY the Java files" wording are now
  derived from `LANGUAGE` (`STDLIB_COLLECTION`, `DATAFLOW_IMPORT`,
  `LANGUAGE_LABEL` in `prompt_helpers.py`), with a Python query skeleton
  (`semmle.code.python.dataflow.new.DataFlow`/`TaintTracking`) added.
  JavaScript skeleton not yet added (only `DATAFLOW_IMPORT`'s javascript
  entry exists as a placeholder).
- `scripts/codeql_docs_fetcher.py`: `DOC_SOURCES`-equivalent
  (`_LANGUAGE_GUIDE_URLS`) now has a verified Python entry (4 real,
  HTTP-200-checked CodeQL docs-site URLs) alongside the existing Java one;
  no javascript entry yet.

**Bug found and fixed as a prerequisite (unrelated to language support):**
`data/project_info.csv` had been reformatted with column-aligned padding
(spaces around every field) in a recent commit, which silently broke
`csv.DictReader` lookups in both `scripts/get_cve_repos.py` and
`scripts/build_codeql_dbs.py` (`row['cve_id']` raised `KeyError` — confirmed
broken before the fix, confirmed fixed after). Stripped back to plain CSV,
matching `data/fix_info.csv`'s existing style; no data lost (confirmed via
`git diff` showing only whitespace changes).

**Verified:**
- `python3 src/cli.py --help` and every subcommand's `--help` still render
  cleanly; `import config`/`agent_backends.*` succeed with both default
  (java) and `QLCODER_LANGUAGE=python` set.
- Ran the actual prompt-building functions (e.g. `claude_prompts.phase3_full`)
  end-to-end with a real `VulnAnalysisTask` under both `LANGUAGE=java` and
  `LANGUAGE=python` and confirmed the rendered prompt text switches
  correctly (`import java`/`semmle.code.java...` vs `import
  python`/`semmle.code.python...`, `codeql_java_stdlib` vs
  `codeql_python_stdlib`).
- `_find_qlpack_subpath` auto-version-detection tested against the user's
  real, already-installed CodeQL bundle (`~/codeql/qlpacks/codeql/`) —
  correctly resolved `java-queries/1.6.1`, `java-all/7.4.0`,
  `python-queries/1.6.1`, `python-all/4.0.11` by listing what's actually
  installed, including correct `~`-expansion (a real bug caught during this
  verification: `os.path.isdir` doesn't expand `~`, fixed with
  `os.path.expanduser`).
- `data/project_info-py.csv`/`data/fix_info-py.csv` load cleanly via
  `pd.read_csv`/`csv.DictReader` and round-trip through
  `get_cve_repos.load_project_info()`.

**Not done / deferred:**
- End-to-end pipeline run against a real Python CVE (`qlcoder run --cve-id
  CVE-2026-27825`) — needs a live CodeQL Python DB build + agent CLI call,
  not exercised in this session.
- End-to-end pipeline run against a real JavaScript CVE (`qlcoder run
  --cve-id CVE-2017-16042`), same reason.
- `fetch_class_locs_javascript.ql`/`fetch_func_locs_javascript.ql` (CodeQL
  `ClassDefinition`/`Function`) not yet compile-tested against a real CodeQL
  JavaScript DB — same category of risk as the Python query variants in 4b,
  but JS's AST has more node variety, so more likely to need iteration.

### 4b-js. JavaScript/Node.js support (2026-09-29)

**Status:** implemented, same day as 4b, pending end-to-end validation
alongside 4b's Python path (see `../GUIDE/TUTORIAL-js.md`'s own
troubleshooting section). Originally scoped for hand-off to a teammate
(see the now-superseded note in `../GUIDE/TUTORIAL-js.md`'s git history);
user asked to just implement it directly instead once the Python path
(4a-4d) was done, since the same plumbing generalized cleanly.

Filled in the JS-specific pieces the language-agnostic plumbing from 4b
didn't cover on its own:
- `src/queries/fetch_class_locs_javascript.ql`/`fetch_func_locs_javascript.ql`
  — `import javascript`, `ClassDefinition`/`Function` library classes,
  modeled on the `_python.ql` variants' shape.
- `src/agent_backends/prompt_helpers.py` — `_query_skeleton_javascript()`
  (`semmle.javascript.dataflow.DataFlow`/`TaintTracking`/
  `RemoteFlowSources`) and `_source_sink_taint_examples_javascript()`
  (Node.js/Express-flavored source/sink examples: `req.query`/`body`,
  `child_process.exec`, `fs.readFile`, `eval`/`vm.runInContext`), following
  the same `if LANGUAGE == "..."` branch pattern the Python variants use.
- `scripts/codeql_docs_fetcher.py`'s `_LANGUAGE_GUIDE_URLS["javascript"]` —
  6 URLs, each individually HTTP-200-verified against the live CodeQL docs
  site before adding (one guessed slug, `analyzing-data-flow-in-javascript`,
  404'd and was swapped for the real one,
  `analyzing-data-flow-in-javascript-and-typescript`).
- `data/project_info-js.csv` + `data/fix_info-js.csv` — 2 CVEs, verified via
  GitHub's advisory/commits API the same way the Python set was: small
  (`tj/node-growl` CVE-2017-16042, CWE-78 command injection, tiny
  single-file npm package, `exec()` → `spawn()` fix) and complex
  (`parse-community/parse-server` CVE-2022-24760, CWE-1321 prototype
  pollution → RCE, sizable Node.js backend framework, fix spans
  `RestWrite.js`'s request-handling constructor + a new `Utils.js` guard
  function).

**Known limitation carried over from 4b, not JS-specific:** `growl` and
`RestWrite` are top-level CommonJS functions with no enclosing class, so
their `fix_info-js.csv` rows have an empty `class` field —
`evaluation.py`'s `_extract_fixed_locations` requires both `class` and
`method` non-null, so these two rows are currently excluded from
recall/precision scoring (only the `Utils.objectContainsKeyValue` row for
CVE-2022-24760 counts). Two Python rows (`litellm`, `RestrictedPython`) have
the identical gap. Not fixed here — flagged to the user as something to
generalize (e.g. match on file+method alone when class is empty) if it
turns out to matter once real runs are validated.

**Verified:** same battery as 4b, re-run per-language across `java`/
`python`/`javascript` in one pass — `config.LANGUAGE`/`PROJECT_INFO`/
`FIX_INFO` resolve correctly for all three; both AST-extraction query files
exist and are found via `f"fetch_{...}_locs_{LANGUAGE}.ql"` for all three;
`claude_prompts.phase3_full` renders the correct `import javascript`/
`semmle.javascript...`/`codeql_javascript_stdlib` text end-to-end;
`get_cve_repos.load_project_info()` round-trips both new CSV rows under
`QLCODER_LANGUAGE=javascript`. **Not** verified: an actual `codeql database
create --language javascript` + full `qlcoder run` against either CVE (no
CodeQL bundle exercised end-to-end in this session).

### 4c. Python CVE seed data (10 CVEs, verified against GitHub's advisory API)

`data/project_info-py.csv` + `data/fix_info-py.csv` — small (`mcp-atlassian`
path traversal, `RestrictedPython` sandbox escape, `mnemosyne` JWT bypass),
medium (`streamlink`, `opencve` SSRF), and large/complex (`saltstack/salt`
auth bypass, `lmdeploy` pickle RCE, `litellm` SSRF, `nautobot`/`open-webui`
authz bypass) codebases, spanning CWE-22/78/502/862/863/918/1321/347/693.
Every CVE's repo, buggy/fix commit SHAs, and CWE were checked against
GitHub's advisory API and/or NVD directly (not recalled from training data).

### 4d. Write `docs/GUIDE/TUTORIAL-py.md`

**Status:** done (2026-09-29), pending user validation.

Python counterpart to `TUTORIAL.md`: `qlcoder` CLI throughout (no direct
`python3 scripts/...` invocations), a plain `venv` + new root
`requirements.txt` instead of `environment.yml`/conda (matching the user's
own already-validated native setup), `CVE-2026-27825` (mcp-atlassian) as the
primary fast-iteration walkthrough with `CVE-2020-11651` (Salt) as the
stress-test follow-up, and the new `QLCODER_LANGUAGE`/`QLPACK_PATH` `.env`
config from 4b. See [`../GUIDE/TUTORIAL-py.md`](../GUIDE/TUTORIAL-py.md).
