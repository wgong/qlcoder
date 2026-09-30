# Skills research: reusable SKILL.md for CVE detect / patch / verify

Date: 2026-09-30. Scope: **Python first, then JavaScript. Java is dropped for now.**
Primary agent: Claude Code.

Goal: reduce prompt code by moving methodology into `SKILL.md` files, while keeping the
pipeline's deterministic parts in code. Prompt code lives in two places today:
- the CodeQL pipeline: `src/agent_backends/*_prompts.py`, `prompt_helpers.py`;
- the direct-agentic-triage prototype (`docs/DEV/readme-approach.md` section 6):
  `PROMPT_TEMPLATE` in `scripts/cve_detect.py`, `cve_patch.py`, `cve_verify.py`, run through
  `run_agent_cli` in `scripts/triage_common.py`. This maps one-to-one onto detect/patch/verify,
  so **it is the first target**, not the CodeQL prompts.

## 1. License policy

Company rule: **MIT and Apache-2.0 only.** Everything else is treated as problematic.

| Source | License (verified from LICENSE file / GitHub) | Verdict |
|---|---|---|
| [jpoindexter/security-skills](https://github.com/jpoindexter/security-skills) | MIT | OK to copy/adapt (keep copyright notice) |
| [anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official) | Apache-2.0 (repo level). The `claude-security` plugin folder was **not confirmed**; the README says each plugin carries its own LICENSE. | Repo OK. Check the plugin's own LICENSE before copying anything. |
| [VoltAgent/awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills) | MIT (it is an index; linked skills keep their own licenses) | Use only as a discovery list |
| [trailofbits/skills](https://github.com/trailofbits/skills) | **CC-BY-SA-4.0** | **Avoid.** Share-alike would force the same license on derived files. Do not copy text, templates or queries. |
| [semgrep/skills](https://github.com/semgrep/skills) | **Semgrep Rules License v1.0** (LICENSE file header) | **Avoid.** Not MIT/Apache. Do not copy skills or rules. |
| Claude docs page (code.claude.com "claude-security") | Documentation, no code license | Read for ideas only; write our own text |

Rules for this repo:
- Never paste or paraphrase closely from CC-BY-SA or Semgrep-licensed files. Ideas and general
  methodology (for example "extract root cause from the patch, then generalize") are not
  copyrightable, but write our own wording and our own CodeQL templates.
- If MIT/Apache text is copied, keep the notice: add a `NOTICE`/`THIRD_PARTY.md` entry with source URL, license and commit.
- Record the source and license of any adapted skill in its `SKILL.md` frontmatter comment.
- CodeQL itself (queries in `github/codeql`) is MIT. The CodeQL CLI has its own terms;
  that is unchanged by this work.

## 2. What exists publicly

No public skill goes from *CVE + fix diff* to *verified detector and patch*. That is QLCoder's niche.

| Area | Best public reference | Usable under policy? |
|---|---|---|
| Detect from a patch (variant analysis, CodeQL/Semgrep templates for Python, JS, Java) | trailofbits `variant-analysis` | No (CC-BY-SA). Use as inspiration only. |
| Patch validation (baseline vs patched, isolated worktrees, evidence artifacts) | trailofbits `post-patch-validation` | No (CC-BY-SA). The idea matches our evaluator anyway. |
| Dependency CVE audit (`npm audit`, `pip-audit`, `osv-scanner`, reachability triage) | jpoindexter `dependency-audit` | **Yes (MIT)**. Java only via `osv-scanner`. |
| SAST scan skill (Semgrep + CodeQL) | jpoindexter `sast-scan` | **Yes (MIT)** |
| Multi-agent scan, independent patch review that runs tests | Anthropic Claude Security plugin | Design idea only until its license is confirmed |
| Skill layout conventions (`SKILL.md`, `references/`, `scripts/`) | semgrep/skills, trailofbits | Layout is a convention, not protected. Do not copy content. |
| arXiv 2609.05335 "The History Is the Detector" | Paper | Not verified. The fetched summary was vague. Read it before relying on it. |

Not evaluated: mcpmarket "CVE Research" and "Vulnerability Scanner" listings (listing pages only, licenses unknown).

Conclusion: with the license policy, almost everything usable must be **written by us**. Only
jpoindexter's dependency and SAST skills can be adapted directly, and they help mainly with
Python and JS dependency work.

## 3. Balance: skills vs code

Claude is the primary backend. Gemini and Codex may not load skills the same way (unverified), so
skills reduce code for the Claude backends first.

**Move to skills (methodology, per language and step):**
- Detect: how to judge whether the described vuln is present and reachable (source, sink, sanitizer), what evidence to cite, Python/JS idioms for the CWE classes.
- Patch: minimal-fix rules per language, dependency bump vs source change, independent review checklist.
- Verify: how to write a regression test that fails before the patch and passes after (pytest for Python; jest/mocha/node:test for JS), and how to report INCONCLUSIVE honestly.
- For the CodeQL pipeline (later): CodeQL Python/JS library guidance and refinement guidance from `claude_prompts.py`.

**Keep in code (deterministic, must not be agent-graded):**
- `scripts/triage_common.py`: repo checkout, cloning, agent invocation, YAML extraction, report writing.
- Running each test against both the vulnerable and patched trees and deciding EFFECTIVE / INCONCLUSIVE (`cve_verify.py`).
- CodeQL pipeline: `evaluation.py`, `query_subagents_evaluation.py`, AST extraction and caching, cost accounting.
- The output schema (`cve-N-*.yaml`). The skill describes it; code validates it.

Rule of thumb: skills say *how to think*; code decides *whether it worked*.

## 4. Where skills live

Source of truth inside `src/`, organized by step, then language:

```
src/skills/
  THIRD_PARTY.md              # source, license, commit for anything adapted
  detect/
    common/SKILL.md           # language-independent method
    python/SKILL.md           # phase 1
    javascript/SKILL.md       # phase 2
  patch/
    common/SKILL.md
    python/SKILL.md
    javascript/SKILL.md
  verify/
    common/SKILL.md
    python/SKILL.md
    javascript/SKILL.md
```

Java is intentionally absent; adding it later is one more directory per step. Each skill may
add `references/` and `scripts/` (thin helpers only).

**Discovery caveat.** Claude Code finds skills at `.claude/skills/<skill-name>/SKILL.md`, one
directory level, so `src/skills/detect/python/SKILL.md` is not discovered on its own. Plan:
- A small installer in `scripts/triage_common.py` (called by `run_agent_cli`) copies `common` plus the CVE's language for the step being run into `<cwd>/.claude/skills/`, flattened to `cve-detect-common`, `cve-detect-python`, and so on. Language comes from the CVE row (`_SUFFIX_TO_LANGUAGE`), so only the relevant skills load and context stays small.
- The flattened name and a precise `description` in each frontmatter are what make Claude pick the skill. Names must be unique after flattening.
- **Risk: `cwd` is the target repo checkout** (the vulnerable checkout for detect, a fresh clone for patch and verify). Writing `.claude/` there would show up in `git status` and in the patch diff. Mitigation: add `.claude/` to that checkout's `.git/info/exclude` (local, not committed), and remove the copied skills after the run.
- Alternative to check: load skills as a Claude Code plugin from `src/skills` via `--plugin-dir`, which would avoid touching the checkout. I have not verified that flag or the plugin manifest requirements in this environment.
- CodeQL pipeline (later): the equivalent hook is `ClaudeBackend.setup_workspace` (`src/agent_backends/claude_backend.py:101`), which already writes per-run config into `output_dir`. Ablation modes could gate which skills install.
- Gemini/Codex: leave their prompts as they are. Revisit after checking their skill support.

## 5. Proposed next steps

1. Python detect: write `detect/common` and `detect/python`. Move the guidance out of `PROMPT_TEMPLATE` in `scripts/cve_detect.py`, leaving the prompt with only the CVE facts, output schema and a pointer to the skill.
2. Add the skill installer to `triage_common.py`, behind a `--skills/--no-skills` flag so old and new prompts can be compared on the same CVEs.
3. Python patch and verify skills, same treatment for `cve_patch.py` and `cve_verify.py`.
4. Run 3 to 5 known Python CVEs with and without skills. Compare finding accuracy, rounds to EFFECTIVE, and cost. The `tests/python` dry-run test should keep passing.
5. Only after step 4 shows a gain, repeat for JavaScript.
6. Confirm the `claude-security` plugin license before borrowing anything from it.

## 6. Status (2026-09-30)

Done, Python detect only:
- `src/skills/detect/common/SKILL.md` and `src/skills/detect/python/SKILL.md`, written from
  scratch (nothing copied from CC-BY-SA or Semgrep-licensed sources, so no `THIRD_PARTY.md` entry needed yet).
- `triage_common.skills_installed()` and `available_skill_names()`: copy the skills into
  `<checkout>/.claude/skills/` for one agent call, add `.claude/` to the checkout's local
  `.git/info/exclude`, and remove the copies afterward. A pre-existing `.claude/` is preserved.
- `--skills` flag on `cve_detect.py`, `cve_coder.py detect` and `cve_coder.py pipeline`. Off by
  default until compared against the inline prompt. With it, the prompt keeps the CVE facts, the
  output schema and a pointer to the skills; the `Skill` tool is added to the allowed tools.
  `--dry-run` only names the skills and never writes into the checkout.
- Verified live: headless `claude --print` in a checkout with the skills installed loaded
  `cve-detect-python` through the `Skill` tool. Unit tests in `tests/common/test_triage_common.py`
  cover install, git-hiding, cleanup and frontmatter/dir name agreement.

Not done: a with/without-skills comparison on real Python CVEs, patch and verify skills,
JavaScript.

Open questions:
- Does `data/` hold any Python CVEs with known fixes we can use for step 4? (`data/fix_info*.csv`, suffix `-py`.)
- Prefer skills inside the checkout with `.git/info/exclude`, or the `--plugin-dir` route (needs verification first)?
