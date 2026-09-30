# Tests

Automated tests for the direct-agentic-triage prototype
(`scripts/cve_spec.py`/`cve_detect.py`/`cve_patch.py`/`cve_verify.py`/
`cve_coder.py` -- see [`../docs/DEV/readme-approach.md`](../docs/DEV/readme-approach.md)
section 6 for the design). The CodeQL query-synthesis pipeline
(`src/ql_agent.py`) still has no automated test suite -- validation there
remains end-to-end runs, per `CLAUDE.md`.

Order of focus: **Python first, then JavaScript** (Java deliberately
deferred for now).

## Layout

```
tests/
  common/           # language-agnostic: shared helpers + fixtures
    test_triage_common.py   # unit tests for scripts/triage_common.py
    repo_fixtures.py         # make_synthetic_repo() used by the per-language tests
  python/
    test_cve_lookup.py       # CVE-2026-27825 resolves from data/project_info-py.csv
    test_pipeline_dry_run.py # cve_coder.py pipeline wiring, offline, --dry-run
  javascript/
    test_cve_lookup.py       # CVE-2017-16042 resolves from data/project_info-js.csv
    test_pipeline_dry_run.py # cve_coder.py pipeline wiring, offline, --dry-run
```

All of the above are **offline** (no network, no agent calls, no
ChromaDB/CodeQL) and fast -- safe to run anytime. Standard library
`unittest` only; no new dependency was added since none of the existing
`requirements.txt` includes a test framework yet.

## Running

```sh
source .venv/bin/activate

# everything:
python3 -m unittest discover -s tests -v

# just one language:
python3 -m unittest discover -s tests/python -v
python3 -m unittest discover -s tests/javascript -v

# a single file:
python3 -m unittest tests.common.test_triage_common -v
```

## What `test_pipeline_dry_run.py` does and doesn't prove

Each one creates a tiny one-commit synthetic local repo (a single toy
source file with an obviously path-traversal-shaped function) and runs
`cve_coder.py pipeline --repo-path <that repo> --dry-run`, asserting all
five reports (`cve-1-metadata.yaml` through `cve-5-pipeline.yaml`) get
written and chain together correctly. This proves the **mechanical
wiring** works (CLI parsing, report-to-report chaining, file naming) for
that language -- it does NOT prove a real CVE in that language gets
correctly detected/patched/verified, since `--dry-run` never calls the
agent.

## Live smoke test (not automated -- costs real agent calls)

To validate the *real* detect/patch/verify behavior against an actual
agent, run the full pipeline without `--dry-run` against one of the
pre-vetted small seed CVEs:

```sh
# Python:
python3 scripts/cve_coder.py pipeline --cve-id CVE-2026-27825 --agent claude_cli --model sonnet-5

# JavaScript:
python3 scripts/cve_coder.py pipeline --cve-id CVE-2017-16042 --agent claude_cli --model sonnet-5
```

Inspect `output/triage/<CVE-ID>/cve-5-pipeline.yaml`'s `overall_status`
first, then drill into the individual `cve-N-*.yaml` reports. See
`docs/GUIDE/TUTORIAL-py.md` section 12 for the walkthrough (JS tutorial
doesn't have the equivalent section yet).

Not run in CI / not part of `unittest discover` -- this is deliberately a
manual, human-reviewed step, not an automated pass/fail check: whether the
agent's verdict is *correct* for a given commit needs a human (or a
comparison against `data/fix_info-*.csv` ground truth) to judge, the same
open question flagged in `docs/DEV/readme-approach.md` section 6's
"suggested improvements".
