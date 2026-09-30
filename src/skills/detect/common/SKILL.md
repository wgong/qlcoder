---
name: cve-detect-common
description: Method for judging, by reading source code directly, whether a described CVE/CWE vulnerability is really present and reachable in a checked-out repository, and for recording each affected location precisely. Use for the detect step of CVE triage, in any language. Detection only, never fix.
---

# CVE detect: language-independent method

You are given a CVE description, its CWE class and a repository checked out at the commit
believed to be vulnerable. Decide from the code alone whether the vulnerability is there.
Follow the output schema given in the task prompt exactly; this skill covers how to reach the
answer, not the format.

## Ground rules

- **Independent judgment.** Do not try to find the upstream fix. Use only git history reachable
  from `HEAD` (`git log HEAD`, `git blame`). Never run `git log --all`, `git branch -a`, look at
  other refs, tags newer than `HEAD`, or the remote's default branch. Finding the fix by lookup
  defeats the purpose of the step.
- **Detection only.** Do not edit, create or delete files in the repository.
- **Read the real code.** Every reported location must come from a file you opened and read at
  those exact lines. Never report a path or line range from memory or from grep output alone.

## Method

1. **Translate the CVE into questions.** From the description and CWE, write down (for yourself):
   what is the attacker-controlled *source*, what is the dangerous *sink*, and what *check or
   sanitizer* would make it safe. A description often names the component, parameter, API
   endpoint or feature; treat those words as search terms.
2. **Find candidates.** Search for the sink and for the named feature. Search both sides: the
   dangerous call and the entry points that feed it. Skip vendored and generated code
   (`vendor/`, `third_party/`, `node_modules/`, `venv/`, `site-packages/`, `build/`, `dist/`)
   and, unless the CVE is about them, tests and examples.
3. **Trace source to sink.** Follow the value through helpers, wrappers, subclasses and
   callbacks. Open each function on the path. If the path crosses a dynamic dispatch, decorator or
   framework registration, find how it is wired instead of assuming.
4. **Check the guard.** Find every check between source and sink. Ask whether it is applied on
   *all* paths, whether it can be bypassed (encoding, case, separators, redirects, absolute
   paths, type confusion, ordering of validate-then-transform), and whether it checks the same
   value that reaches the sink.
5. **Check reachability.** Is the code called from a public entry point (network handler, CLI
   argument, message consumer, public API, file the user supplies)? Code that is unreachable,
   test-only or behind a trusted-only boundary is not the vulnerability, though you may mention
   it in the notes.
6. **Decide.** Superficially similar but safe code is `vulnerable: false`. Say why it is safe.
7. **Enumerate locations.** One finding per distinct location. If the flaw spans several
   functions or files (missing check here, unsafe sink there), list each separately. Include the
   place where the check is *missing* when that is the real defect.
8. **Dependency case.** If the CVE is about a third-party library, the repository's own defect
   is the dependency declaration (manifest or lockfile line that pins a vulnerable version) plus
   any call site that uses the affected API. Report the manifest line as a finding, and say
   whether the affected API is actually used.

## Line ranges

Use the smallest range that contains the defect: the function or block that holds the unsafe
logic, not the whole file. Re-read the file with line numbers and confirm the range before
reporting it.

## Confidence

- 80-100: you traced source to sink and saw the missing or bypassable guard.
- 50-79: the pattern matches and nothing guards it, but you could not confirm reachability or
  a detail of the description.
- Below 50: similar code, weak evidence. Say so plainly rather than rounding up.
- `overall_vulnerable: unknown` only when the evidence is genuinely too weak either way.

## Pitfalls

- Reporting the first grep hit. Verify each candidate.
- Reporting a sanitizer as the defect when it is correct, or missing the case where it only
  covers one of several code paths.
- Folding two files into one finding, which hides one of them from the patch step.
- Treating a test fixture that contains the payload as the vulnerable code.
- Inflating confidence to look decisive.
