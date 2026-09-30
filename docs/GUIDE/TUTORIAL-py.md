# QLCoder Tutorial — Python

This walks through trying out QLCoder end-to-end against **Python** CVEs,
natively on Linux, using the `qlcoder` consolidated CLI throughout. It's the
Python counterpart to [`TUTORIAL.md`](TUTORIAL.md) (Java, Docker + native) —
read that one first if you haven't set up QLCoder before; this doc only
covers what's different for Python.

QLCoder drives a coding-agent CLI (Claude Code by default) through a pipeline
that: clones the CVE's repo, builds "vulnerable" and "fixed" CodeQL
databases, extracts the AST of the fix diff, then iteratively writes and
tests a CodeQL query until it flags the vulnerable code and not the fixed
code. None of that changes for Python — only the CodeQL language pack, the
CVE metadata CSVs, and the query templates involved.

## How QLCoder picks Python instead of Java

There's no `--language` flag. Set `QLCODER_LANGUAGE=python` and
`QLPACK_PATH=~/codeql/qlpacks/codeql` in `.env` (Section 4 below) and
everything else follows automatically: `SECURITY_QLPACK_PATH`/
`LIBRARY_QLPACK_PATH` are auto-derived from those two (QLCoder finds
whichever `<version>` is installed under `QLPACK_PATH/python-queries/` and
`QLPACK_PATH/python-all/` for you — no manual `ls`/version lookup needed),
and so are the AST-extraction queries, the CVE metadata CSVs
(`data/project_info-py.csv`/`data/fix_info-py.csv` instead of the Java
`project_info.csv`/`fix_info.csv`), and the agent prompts. See
`src/config.py`'s `_detect_language`/`_find_qlpack_subpath` for the details.

## 0. Prerequisites

Same as `TUTORIAL.md` Section 0, except:

1. **A CodeQL bundle** — the same bundle covers every language CodeQL
   supports, so nothing extra to download; you're just pointing at a
   different subdirectory inside it (Section 2 below).
2. **The [codeql-lsp-mcp](https://github.com/neuralprogram/codeql-lsp-mcp)
   server**, cloned and built (`npm install && npm run build`) — unchanged.
3. **An agent CLI or API key** — unchanged (see `TUTORIAL.md` Section 0.3).
4. **The CVE you want must be in `data/project_info-py.csv`.**
   `CVE-2026-27825` (small, fast to iterate on) and `CVE-2020-11651`
   (large/complex, a stress test) are already there; check with:
   ```sh
   grep "CVE-XXXX-YYYYY" data/project_info-py.csv
   ```

---

## 1. Install CodeQL

```sh
tar -xzf codeql-bundle-linux64.tar.gz
export PATH="$PWD/codeql:$PATH"
```
Add the `export` line to your shell profile to persist it.

## 2. Install codeql-lsp-mcp

```sh
git clone https://github.com/neuralprogram/codeql-lsp-mcp
cd codeql-lsp-mcp
npm install
npm run build
cd -
```

## 3. Set up a plain Python virtualenv

`TUTORIAL.md`'s native path uses conda (`environment.yml`). If you don't have
conda available — e.g. a bare Linux coder/dev-container environment — a
plain venv works just as well; QLCoder has no conda-specific dependency:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` mirrors `environment.yml`'s pip section, so either path
installs the same package versions.

## 4. Configure `.env`

```sh
cp .env.example .env
```

Fill in:
```sh
ANTHROPIC_API_KEY=sk-ant-...          # only if using --agent claude
CLAUDE_CODE_OAUTH_TOKEN=              # only if using --agent claude_cli, see TUTORIAL.md Section 5
CODEQL_HOME=~/codeql
CODEQL_LSP_MCP_HOME=~/codeql-lsp-mcp
QLCODER_LANGUAGE=python
QLPACK_PATH=~/codeql/qlpacks/codeql
```

`SECURITY_QLPACK_PATH`/`LIBRARY_QLPACK_PATH` stay blank — QLCoder derives
them from `QLCODER_LANGUAGE` + `QLPACK_PATH`, auto-detecting whichever
`<version>` is installed under `QLPACK_PATH/python-queries/` and
`QLPACK_PATH/python-all/`. Only fill those two in yourself if your CodeQL
install doesn't follow that layout.

`QLCODER_LANGUAGE=python` is the only thing that makes this a Python run
instead of a Java run — see "How QLCoder picks Python instead of Java" above.

## 5. One-time `qlcoder` setup

```sh
chmod +x bin/qlcoder
ln -s "$(pwd)/bin/qlcoder" ~/.local/bin/qlcoder   # ~/.local/bin must be on PATH
```
`qlcoder --help` should now work from anywhere; every command below assumes
this is set up (drop into `python3 src/cli.py <command>` instead if you'd
rather not symlink it).

## 6. Retrieve the CVE repo and generate the fix diff

```sh
qlcoder get-cve-repos --cve CVE-2026-27825
```

This clones `sooperset/mcp-atlassian` at the buggy commit into
`cves/CVE-2026-27825/` and generates
`cves/CVE-2026-27825/CVE-2026-27825.diff`.

## 7. Build the CodeQL databases

```sh
qlcoder build-dbs --cve-id CVE-2026-27825
```

Uses `--build-mode=none` (no build toolchain required — CodeQL extracts
Python source without executing it). Creates
`cves/CVE-2026-27825/CVE-2026-27825-vul` and
`cves/CVE-2026-27825/CVE-2026-27825-fix`.

## 8. Start ChromaDB

In a **separate terminal**, and keep it running for the rest of this
tutorial:
```sh
chroma run --path data/chroma_db
```
Same as `TUTORIAL.md` B7 — leave `CHROMA_HOST` unset for native runs.

## 9. Populate the RAG database

```sh
qlcoder fetch-docs   # one-time; pulls Python stdlib + language-guide docs this time, not Java's
qlcoder fetch-cwe     # one-time
qlcoder fetch-cves    # re-run after adding CVEs
```

`fetch-docs` populates a `codeql_python_stdlib` collection instead of
`codeql_java_stdlib` (see `scripts/codeql_docs_fetcher.py`'s
`_LANGUAGE_GUIDE_URLS`), matching the language detected in Section 4.

## 10. Run the pipeline

Start with the small one, to validate everything end-to-end quickly:
```sh
qlcoder run --cve-id CVE-2026-27825 --agent claude_cli --model claude-sonnet-5 --max-iteration 10
```

`mcp-atlassian` is a small, modern, single-purpose Python package — a fix
that hardens a path-traversal check (`CWE-22`) against symlink-based
bypasses in `AttachmentsMixin.download_attachment`. Good for iterating
quickly on prompt/query changes without waiting on a large codebase.

Once that's working, stress-test against the larger, more complex codebase:
```sh
qlcoder run --cve-id CVE-2020-11651 --agent claude_cli --model claude-sonnet-5 --max-iteration 10
```

`saltstack/salt` is a large, real-world Python codebase (CVE-2020-11651: an
authentication-bypass RCE in `salt-master`'s `ClearFuncs`/`MWorker` classes)
— useful for checking the pipeline still converges in reasonable time on
something bigger than a toy example, the same way `TUTORIAL.md`'s Kafka
example stress-tests the Java path.

If `--vuln-db`/`--fixed-db`/`--diff` are omitted (as above),
`QLAgentIterativeCLI.discover_cve_paths` auto-discovers them from
`cves/<CVE-ID>/` by convention.

## 11. Inspect results

Same as `TUTORIAL.md` Section A8 —
`output/ql_agent_CVE-2026-27825_<timestamp>_<N>-iterations_<model>_<ablation-mode>/`:
- `results/` — per-iteration logs, the compiled `.ql` query, and evaluation
  output
- a metadata file with pass/fail, recall/precision per iteration, and the
  final query path
- a cost/usage summary

## Everything else is unchanged

Sections 5–9 of `TUTORIAL.md` (subscription billing via `--agent claude_cli`,
the model/agent table, ablation modes, cleaning up `cve_analysis_*`
collections, troubleshooting) apply identically here — none of that is
Java-specific. The one troubleshooting addition specific to this doc:

- **Wrong CSV/language picked up** — if `qlcoder run` can't find your CVE,
  double check `.env` has `QLCODER_LANGUAGE=python` — `src/config.LANGUAGE`
  decides whether `data/project_info.csv` or `data/project_info-py.csv` gets
  read, and a mismatch here is the most likely reason a CVE that's clearly
  in the CSV still isn't found.
- **`SECURITY_QLPACK_PATH`/`LIBRARY_QLPACK_PATH` derivation failing** — if
  those come back pointing at the java fallback despite `QLCODER_LANGUAGE=python`,
  check `QLPACK_PATH` actually points at your CodeQL bundle's `qlpacks/codeql`
  directory and that `python-queries`/`python-all` exist under it
  (`ls $QLPACK_PATH/python-queries/`); `_find_qlpack_subpath` in
  `src/config.py` silently falls back to the hardcoded java default path if
  it can't find an installed version there.

## 12. (Experimental) Direct agentic triage: `cve_coder.py`

Separate from the CodeQL query-synthesis pipeline above (Sections 6–11) is
a much lighter-weight prototype: instead of synthesizing a reusable CodeQL
query and grading it against pre-/post-fix databases, a coding agent reads
the checked-out repo directly and produces a finding, a fix, and a
regression test that proves the fix — no CodeQL database, no CodeQL LSP
server, no ChromaDB at all. See
[`../DEV/readme-approach.md`](../DEV/readme-approach.md) section 6 for why
this exists and how it compares to the pipeline above; this section is
just the "how do I run it" walkthrough.

Because there's no CodeQL DB/LSP/Chroma involved, you can skip Sections
2/7/8/9 above entirely for this path — all you need is Sections 0/1(skip
CodeQL itself, just the venv)/3/4/5 (the venv + `.env` with
`QLCODER_LANGUAGE=python` + an agent CLI/API key) and a CVE already in
`data/project_info-py.csv`.

Try the smallest, fastest CVE first — the same `CVE-2026-27825`
(`mcp-atlassian`) used in Section 10 above, since it's already verified as
a small, single-purpose repo with a real method-body-level fix:

```sh
# sanity-check the wiring first, without spending any agent calls:
python3 scripts/cve_coder.py pipeline --cve-id CVE-2026-27825 --dry-run

# the real run:
python3 scripts/cve_coder.py pipeline --cve-id CVE-2026-27825 \
    --agent claude_cli --model sonnet-5
```

This runs all four stages in order — `spec` (fetch NVD metadata, clone/
checkout the repo, no agent call), `detect` (agent reads the code, judges
whether the vulnerability is really there), `patch` (agent fixes it on an
isolated clone), `verify` (agent writes a regression test and runs it
against both the original and patched checkouts) — then writes a summary.
Results land at:

```
output/triage/CVE-2026-27825/
├── cve-1-metadata.yaml   # NVD description/CWE + repo/commit info
├── cve-2-findings.yaml   # what the agent found: file(s), line(s), reasoning
├── cve-3-fixes.yaml      # what it changed: fix description + the actual on-disk code
├── cve-4-tests.yaml      # the regression test it wrote + PASS/FAILED on both checkouts
└── cve-5-pipeline.yaml   # one-line-per-stage summary + overall_status
```

Open `cve-5-pipeline.yaml` first — its `overall_status` tells you at a
glance whether the whole chain worked (`EFFECTIVE`), the fix didn't hold up
(`FIX_FAILED`), the test never actually demonstrated the bug
(`INCONCLUSIVE`), or the CVE wasn't confirmed vulnerable in the first place
(`SKIPPED_NOT_VULNERABLE`) — then drill into the individual
`cve-N-*.yaml` files for the full trace behind that verdict.

If `overall_status` isn't `EFFECTIVE`, try letting it retry automatically:
```sh
python3 scripts/cve_coder.py pipeline --cve-id CVE-2026-27825 \
    --agent claude_cli --model sonnet-5 --max-iters 3
```
This re-runs `patch`→`verify` as up to 3 rounds, feeding each round's
verify failure back into the next round's patch attempt, stopping early
the first round that comes back `EFFECTIVE`. Round outputs are kept as
`cve-3-fixes-iter-<N>.yaml`/`cve-4-tests-iter-<N>.yaml` so you can see what
changed between attempts.

To run one stage at a time instead of the full pipeline (useful for
inspecting each report before letting the agent proceed, or re-running
just one stage):
```sh
python3 scripts/cve_coder.py spec   --cve-id CVE-2026-27825
python3 scripts/cve_coder.py detect --in output/triage/CVE-2026-27825/cve-1-metadata.yaml
python3 scripts/cve_coder.py patch  --in output/triage/CVE-2026-27825/cve-2-findings.yaml
python3 scripts/cve_coder.py verify --in output/triage/CVE-2026-27825/cve-3-fixes.yaml
```

`python3 scripts/cve_coder.py --help` (and `... <command> --help`) lists
every option — `--max-turns`/`--timeout` (agent-CLI limits),
`--force` (patch/verify anyway even if not confirmed vulnerable), `--iter`
(label a manual re-run without overwriting the previous attempt's report).

**This path is newer and less exercised than the CodeQL pipeline above —
it has only been smoke-tested with `--dry-run` so far, never against a
live agent.** If something breaks on a real run, that's useful signal in
itself; check `docs/DEV/readme-approach.md` section 6 for the known,
already-flagged limitations (e.g. the generated regression test isn't
independently checked for actually exercising the vulnerability) before
assuming it's something new.

## Adding more Python CVEs

`data/project_info-py.csv` currently has 10 verified CVEs (small, single-file
fixes through large, multi-file real-world codebases) spanning path
traversal, SSRF, pickle/deserialization RCE, missing authorization, and
sandbox-escape bugs — a broader stress-test set than just the two walked
through above. Try any of them the same way:
```sh
grep CVE data/project_info-py.csv | cut -d, -f3
```
To add your own, append a row to `data/project_info-py.csv` (repo/commit
info) and `data/fix_info-py.csv` (the ground-truth vulnerable
class/method(s) the fix touches — used to score recall/precision each
iteration), following the existing rows' format.
