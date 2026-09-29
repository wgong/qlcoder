# Rethinking QLCoder's approach

Brainstorming doc, prompted by two questions raised 2026-09-29 while
reviewing `docs/GUIDE/TUTORIAL.md` §7 (ablation modes):

1. Does any current mode let Claude (a) verify a vulnerability exists,
   (b) report the finding, (c) write a fix, (d) verify the fix — directly
   against the target repo, using its own coding ability, instead of via a
   synthesized CodeQL query?
2. Is the current architecture (LSP server + CodeQL DB server + vector DB,
   then iterative query synthesis against pre-/post-fix DBs) more
   infrastructure than the problem needs?

Not a decision doc — no plan has been approved. Captures the current state,
why it's shaped this way, and directions worth considering.

## 1. What today's pipeline actually does (and doesn't)

`--ablation-mode` (`full`/`no_tools`/`no_lsp`/`no_docs`/`no_ast`,
`src/agent_backends/__init__.py:15`) only gates *how the agent is helped to
write a CodeQL query* — LSP tool access, AST-diff hints, docs RAG. Every
mode's job, at every ablation level, is: synthesize a `.ql` file, compile
it, run it against the vulnerable DB and the fixed DB, score
recall/precision against ground truth, refine, repeat
(`ql_agent.py`'s `_run_iterative_phase3`). There is no mode where the agent
reads the target repo's source directly, proposes a patch, or verifies a
patch — the agent's entire interaction with the vulnerability is *mediated
through a CodeQL query it writes*, never a direct read/patch/verify loop
against the code.

So today: **(a)/(b)/(c)/(d) are all out of scope of the current pipeline.**
The pipeline answers a narrower question — "can a synthesized static-analysis
query distinguish the vulnerable version from the fixed version" — not "can
the agent find and fix this bug." That's a deliberate, if narrow, framing:
QLCoder's stated goal (`CLAUDE.md`) is producing a reusable *CodeQL query*
as the artifact, e.g. for scanning an entire fleet of repos for the same bug
class later, not one-off patching one CVE in one repo.

## 2. Why the current architecture looks the way it does

Each piece exists to serve that narrow "produce a durable detection query"
goal:

- **CodeQL DB (pre-fix + post-fix)** — the ground truth the synthesized
  query is graded against every iteration. Not optional if the deliverable
  is a query, since "does this query flag the vuln and not the fix" *is*
  the success criterion.
- **CodeQL LSP MCP server** — lets the agent interactively check "does this
  predicate/class exist, what's its signature" instead of guessing CodeQL
  library API from training data (which is often stale — CodeQL's Java/
  Python/JS libraries change across versions). Directly reduces
  compile-fail iterations.
- **Vector DB (Chroma)** — two independent uses bundled together: (i) RAG
  over CodeQL/CWE docs so the agent's query-writing is grounded in current
  API rather than memorized API, (ii) a cache (`cve_ast_cache`,
  `nist_cve_cache`) to avoid re-doing expensive AST extraction / NVD lookups
  across repeated runs of the *same* CVE.
- **Iterative refinement loop** — CodeQL queries are notoriously easy to
  write "successfully" (compiles, runs) but semantically wrong (wrong
  recall/precision), so a single-shot generation is unlikely to produce a
  usable query; the loop exists to let the agent see its own query's
  actual behavior against real data and correct it.

None of these are wrong per se — they're the right tools *for the stated
goal of synthesizing a reusable static query*. The complaint is really: is
that the right goal, given what a modern coding agent can do directly?

## 3. The case that this is overbuilt for a large class of real use

Claude Sonnet (and comparable frontier coding agents) can already, with a
CVE ID/advisory and repo access:
- read the pre-fix commit and reason about whether the described
  vulnerability class (e.g. "path traversal in `download_attachment`") is
  actually reachable/exploitable in that code — a direct code-reading
  exercise, not requiring a static-analysis query as an intermediary,
- write up the finding in natural language with source citations,
  because the model just read the source,
  the moment it's shown the pre-fix code — no synthesized detection
  artifact is needed *for that one instance*,
- diff its own patch against the real upstream fix commit and self-assess.

For "is repo X, at commit Y, vulnerable to CVE Z, and what's the fix" —
a single-CVE, single-repo question — routing through query synthesis,
compilation, and DB evaluation is arguably solving a harder, more
general problem (a *reusable detector*) than the question actually asked
(a *yes/no + patch* for one instance). The overhead the user is reacting to
(LSP server, DB server, two DBs, vector DB, iterate-compile-run loop) is
overhead in service of reusability and academic rigor (a query is a
falsifiable, inspectable, re-runnable artifact; a one-off LLM judgment is
none of those) — but if the actual need most of the time is "triage this
one CVE against this one repo," that rigor is bought at a real latency/
complexity cost (the very 8-min/iteration, 5-iterations-no-convergence
problem that motivated the Kafka timeout fix earlier this session).

## 4. Directions worth considering (not decided, not scoped)

These aren't mutually exclusive — QLCoder could grow a second, lighter mode
alongside the existing query-synthesis one, rather than replacing it.

**A. Direct agentic triage mode (new, much simpler pipeline)**
Given a CVE + repo + commit, let the agent directly: read the pre-fix
source around the described location, reason/verify exploitability, write
a finding report, propose a patch, then (optionally) re-run against the
post-fix commit or a test to verify the patch resolves it — no CodeQL DB,
no LSP server, no vector DB, no query synthesis at all. This is close to
"just ask Claude Code to do a security review of this diff/commit," which
is a capability that already exists generically — QLCoder's value-add here
would be structuring the CVE metadata input and the finding/patch output
format consistently, and cross-checking against the real fix commit for
scoring. Much lower latency, no infra dependencies, but produces a
non-reusable, per-instance judgment rather than a durable query.

**B. Keep query synthesis, but make it a downstream/optional step**
Run direct agentic triage (A) first, fast; only invoke the full CodeQL
query-synthesis loop when the goal is specifically "I want a detector I can
re-run against other repos/future commits" (e.g. building a rule for CI, or
scanning a fleet) — not as the default path for "is this one CVE real."
This preserves the current pipeline's value for its actual differentiator
(reusable detection) while not forcing every single-CVE check through it.

**C. Cut cold-start cost, keep the architecture**
Short of a redesign: several of the "convoluted" pieces are mostly
*one-time* costs already amortized across runs — `fetch-docs`/`fetch-cwe`
are one-time, `cve_ast_cache`/`nist_cve_cache` persist across runs of the
same CVE, and the Kafka fix this session already addressed the worst
per-iteration cost (unbounded subprocess timeouts + per-iteration cache
clearing). What's left as genuinely per-run overhead: building two CodeQL
DBs (`build-dbs`, itself a `codeql database create` cost, not a QLCoder
design choice) and the LSP/Chroma *processes* needing to be up. A batch/
prewarm mode (start LSP+Chroma once, run many CVEs against them) would cut
the fixed setup cost without touching the core loop.

**D. Skip LSP, lean harder on RAG + the agent's own knowledge**
The LSP server's value (live "does this API exist" checks) could partly be
replaced by a richer static extraction from the installed qlpack's `.qll`
files into the vector DB once, at setup — trading interactivity for a
simpler runtime dependency graph (no long-lived LSP process during the
run). Lower fidelity than a live LSP round-trip, but removes one moving
part.

## 5. Open questions for whoever picks this up

- Is a "reusable CodeQL query" actually a deliverable the user's team
  wants (e.g. for CI/fleet scanning), or was that framing inherited from
  this project's CWE-Bench-Java research lineage and not actually the
  user's real goal?
- If (A) direct agentic triage is built, what's the evaluation story? The
  current pipeline's recall/precision-against-ground-truth scoring is
  fairly rigorous (`evaluation.py`); an LLM's free-text "yes this is
  vulnerable" claim needs its own verification method (e.g. diffing its
  patch against the real fix commit, or re-running the repo's own tests)
  to avoid just trusting the model's self-report.
- Would (B)'s two-tier design fragment the codebase (two pipelines to
  maintain) more than it's worth, versus just optimizing the existing one
  further per (C)/(D)?

## 6. Prototype: option A, direct agentic triage (2026-09-29)

### Requirement, as given

Build option A as three separate, atomic scripts in `scripts/`, chained via
YAML reports on disk (no shared process, no CodeQL DB/LSP/vector DB),
reusing QLCoder's existing CVE-metadata plumbing where it fits:

- **(a) `cve_detect.py`** — given a `--cve-id`, fetch its metadata from the
  national CVE registry (NVD) plus any known fix info, and generate an
  analysis report in `.yaml` format.
- **(b) `cve_patch.py`** — consume (a)'s YAML report and generate a fix,
  either a repo/dependency upgrade or an actual code change, producing a
  report of the fix made per the original finding.
- **(c) `cve_verify.py`** — consume (b)'s report, generate a test suite,
  run it, and report whether the fix is effective or not.

### What was built

`scripts/cve_detect.py`, `scripts/cve_patch.py`, `scripts/cve_verify.py`,
plus a shared `scripts/triage_common.py` (CVE/CSV lookup, repo clone/
checkout reuse via `get_cve_repos.process_cve`, the headless `claude` CLI
invocation, YAML fenced-block extraction/report read-write — factored out
because all three scripts need it, the same way the three prompt modules
share `prompt_helpers.py`). No CodeQL, no LSP server, no Chroma — each
script is a single headless `claude --print` call plus plain
subprocess/git/filesystem work.

- **`cve_detect.py`**: resolves the CVE's repo/commit from
  `data/project_info*.csv` (scans all three language variants, since the
  CVE's language isn't known up front) or `--github-url`/`--commit` for
  CVEs not yet in QLCoder's seed data; reuses `cves_fetcher.py`'s
  `fetch_cve_from_nvd`/`create_cve_metadata` for the NVD description/CWE/
  CVSS; reuses `get_cve_repos.process_cve` to clone+checkout the vulnerable
  commit under the same `cves/<CVE-ID>/<repo>` convention the rest of
  QLCoder uses. The prompt hands the agent only the CVE's *public*
  description/CWE — deliberately not the known fix location from
  `fix_info*.csv`, even when QLCoder already has it, so the agent's
  verdict is a genuine independent read of the code, not a lookup; the
  known location is still recorded in the report (under a
  `_known_fix_hints_not_shown_to_agent` key) for later scoring. Agent gets
  read-only tools (`Read,Grep,Glob,Bash(git:*)`). Output:
  `output/triage/<CVE-ID>/detect_report.yaml` (verdict, confidence,
  reasoning, cited evidence, suggested fix locations).
- **`cve_patch.py`**: refuses to run if the detect report says
  `vulnerable: false` (override with `--force`); clones the vulnerable
  checkout locally into a separate `<repo>-patched` working copy so the
  original checkout `cve_detect.py` reasoned about is left untouched;
  hands the agent the finding (not the real upstream fix diff — same
  reasoning as above) and asks it to fix it directly, dependency bump or
  source edit, uncommitted; captures `git diff` itself afterward rather
  than trusting the agent's self-report. Output: `patch_report.yaml`
  (strategy, files touched, full diff, agent's rationale).
- **`cve_verify.py`**: asks the agent to write exactly one new regression
  test file into the patched copy, designed to fail pre-patch and pass
  post-patch; copies that *same* test file into the original vulnerable
  checkout so both sides run an identical test; runs it against both,
  captures exit codes/output; `fix_effective` is only true if the test
  actually failed on the vulnerable checkout AND passed on the patched
  one — a checkout where the test doesn't fail either way is reported as
  `inconclusive`, not silently treated as a pass. Output:
  `verify_report.yaml`.

All three support `--dry-run` (build the prompt, skip the agent call,
write a stub report) — used in this session to smoke-test the full
detect → patch → verify wiring against the real `CVE-2026-27825` seed data
end-to-end (CSV lookup, NVD fetch, repo checkout reuse, local-clone
isolation, YAML round-tripping, and the `--force`/`skipped` gating between
stages) without spending a real agent call. **Not verified**: an actual
live `claude` CLI run through all three stages — that needs real API/
subscription credentials and was out of scope for this pass; the prompts
and YAML schemas are new and unproven against a live model's actual output
shape.

### My take / suggested improvements

The three-script, YAML-chained shape is right for a prototype — cheap to
inspect and re-run any single stage by hand. A few things worth deciding
before relying on this:

1. **Evaluation rigor is currently weaker than the CodeQL pipeline's.**
   `evaluation.py`'s recall/precision scoring is method-level and
   deterministic; here, "vulnerable: true/false" and "fix_effective" are
   both ultimately the same model grading its own homework (the detecting
   agent decides if it's vulnerable, a possibly-different agent call
   writes the proof-test that then judges the fix). Worth cross-checking
   `cve_detect.py`'s verdict against `fix_info*.csv`'s ground truth
   automatically (when present) as a numeric accuracy metric across the
   existing 12+216 CVE seed set, the same way the CodeQL pipeline reports
   recall/precision — currently that comparison isn't wired up, only
   recorded as an unused hint in the report.
2. **`cve_verify.py`'s test can lie in one specific way**: nothing stops
   the agent from writing a test that's trivially true/false regardless of
   the actual vulnerability (e.g. `assert True`), which would still
   satisfy "fails pre-patch, passes post-patch" if the test additionally
   does something environment-dependent. Consider asking a *second*,
   independent agent call to critique the generated test for whether it
   actually exercises the claimed vulnerability, before trusting its
   pass/fail as "fix_effective" — cheap insurance against a self-fulfilling
   test.
3. **No fallback if repo has no runnable test tooling** (e.g. a repo with
   no test framework at all, or one needing a build step this prototype
   doesn't run) — `cve_verify.py`'s generated `test_command` could easily
   fail for infrastructure reasons unrelated to the fix, and today that's
   indistinguishable in the report from "the fix didn't work" (both are
   just a non-zero exit code). Worth having the agent report a
   `setup_required` flag distinctly from a genuine test failure.
4. **Cost/safety**: `cve_patch.py` gives the agent `Edit,Write` plus
   `Bash(git:*)` directly against a real cloned repo (still just a local
   working copy, not pushed anywhere) — fine for a prototype run by hand,
   but if this gets wired into any automation, the local-clone isolation
   should be paired with a resource/time budget (a stray `git clean -fdx`
   or dependency-install command in the agent's `Bash` scope could still
   do real damage to that working copy, low blast radius but worth a
   sandboxed cwd or container in a non-prototype version).
5. **Not wired into `qlcoder`'s click CLI or `bin/qlcoder`** — these are
   standalone scripts today, callable only via
   `python3 scripts/cve_detect.py ...`, consistent with how the option A
   vs. option B question in section 4/5 above hasn't been decided (adding
   them as `qlcoder detect`/`patch`/`verify` subcommands is cheap once the
   design is validated against a couple of real live-agent runs, but
   premature before that).
6. **Language handling is best-effort, not enforced** — `cve_detect.py`'s
   CSV scan infers language from which CSV matched, but doesn't feed that
   into the prompt or pick language-specific test tooling hints for
   `cve_verify.py`; the agent has to infer the language/test framework
   itself from the checked-out repo each time. Fine given frontier models
   handle that well, but worth noting as a difference from the CodeQL
   pipeline's explicit `LANGUAGE` threading.

None of the above blocks trying this against a real CVE — recommend
running the full (non-dry-run) chain against `CVE-2026-27825` (small,
already seeded, already verified as a real method-body fix) as the first
live test, since it's the cheapest real end-to-end validation available.

### 6.1 Report redesign: auditable, per-item lists (2026-09-29)

Follow-up requirement: the three reports should read as a single, complete,
auditable trace of the work on one CVE, not three single-verdict blobs.
Renamed and restructured all three (schemas/prompts updated in
`cve_detect.py`/`cve_patch.py`/`cve_verify.py`, helpers added to
`triage_common.py`):

- `detect_report.yaml` -> **`cve_findings.yaml`**: `findings:` is now a
  list, one entry per distinct vulnerable location (`file`, `lines`,
  `vulnerable`, `description`, `confidence`) rather than one bundled
  evidence list — the agent is explicitly told to record each location
  separately if the vulnerability spans more than one file/function.
- `patch_report.yaml` -> **`cve_patch.yaml`**: `fixes:` is a list, one
  entry per finding acted on (`fix_name`, `fix_description`, `file`,
  `lines`, `fixed_code`). Deliberately, `fixed_code` is **read straight off
  disk** from the patched working copy (new `triage_common.read_file_lines`
  helper) after the agent's edit, rather than trusted from whatever the
  agent claims it wrote — the report's code snippets can't drift from what
  the file actually contains. The full unified diff is kept alongside it
  for completeness/cross-check.
- `verify_report.yaml` -> **`cve_verified.yaml`**: `tests:` is a list, one
  per regression test the agent writes (ideally one per fix), each with
  `pre_patch_result`/`post_patch_result` as `PASS`/`FAILED` and a per-test
  `verdict` (`EFFECTIVE` / `INCONCLUSIVE` / `FIX_FAILED`), rolled up into
  one `overall_verdict` — the worst verdict across all tests wins, so one
  broken fix can't be hidden behind others passing.

Smoke-tested (dry-run) end-to-end against `CVE-2026-27825` again after the
redesign to confirm the new filenames and list schemas chain correctly.

### 6.2 Orchestrator: `cve_secure.py` (2026-09-29)

Added `scripts/cve_secure.py`, a click CLI in front of the three scripts —
same translation-layer pattern `src/cli.py` uses for the CodeQL pipeline's
scripts (click options mirror each script's argparse options 1:1, build an
argv list, call that script's own unmodified `main(argv)`; not a
reimplementation, so `python3 scripts/cve_detect.py ...` and
`python3 scripts/cve_secure.py detect ...` run identical logic).

```sh
python3 scripts/cve_secure.py --help
python3 scripts/cve_secure.py detect --cve-id CVE-2026-27825
python3 scripts/cve_secure.py patch --report output/triage/CVE-2026-27825/cve_findings.yaml
python3 scripts/cve_secure.py verify --report output/triage/CVE-2026-27825/cve_patch.yaml
python3 scripts/cve_secure.py pipeline --cve-id CVE-2026-27825          # all three, chained
python3 scripts/cve_secure.py pipeline --cve-id CVE-2026-27825 --dry-run
```

- `detect`/`patch`/`verify` — run one unit standalone, identical options to
  the underlying script.
- `pipeline` — runs detect → patch → verify back-to-back for one CVE,
  using each stage's own default report path
  (`output/triage/<CVE-ID>/cve_findings.yaml` → `cve_patch.yaml` →
  `cve_verified.yaml`) so the three reports are produced together, in
  order, as one auditable trace. Each stage's own gating still applies —
  `patch`/`verify` decline to run (writing a `skipped: true` report
  instead) if the previous stage didn't confirm a vulnerability, unless
  `--force`. `--stop-after {detect,patch,verify}` runs a prefix of the
  pipeline (e.g. `--stop-after detect` to only triage, without patching
  yet). A `SystemExit` from any stage (e.g. a hard error) aborts the
  pipeline with a clear "stage X exited with code Y" message instead of a
  raw traceback.

Smoke-tested: `--help` on the group and `pipeline`; a full `--dry-run`
pipeline run against `CVE-2026-27825` producing all three reports at their
conventional paths; `--stop-after detect` correctly halting after the
first stage. Not yet run live (needs real agent credentials, same caveat
as the underlying three scripts).

Still not wired into `bin/qlcoder`/`src/cli.py` (per suggestion 5 in
section 6 above) — `cve_secure.py` is its own standalone entry point for
now, consistent with this whole prototype not yet being merged into the
main `qlcoder` CLI pending validation against a live run.