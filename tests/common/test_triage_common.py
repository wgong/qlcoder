"""Unit tests for scripts/triage_common.py -- the helpers shared by the
cve_spec/cve_detect/cve_patch/cve_verify/cve_coder direct-agentic-triage
prototype (see docs/DEV/readme-approach.md section 6). Language-agnostic,
so these live outside the per-language test directories.

No network, no agent calls -- pure functions only. Run with:
    python3 -m unittest tests.common.test_triage_common -v
or the whole suite with:
    python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scripts import triage_common as tc


class ExtractAssistantTextTests(unittest.TestCase):
    """Regression coverage for a real bug found 2026-09-30: `claude --print
    --output-format json` returns a single JSON *object* with the reply in
    its `result` field, not a list of turn events. The old implementation
    assumed the list shape, silently fell through on the real (dict) shape,
    and returned the raw JSON blob -- which yaml.safe_load then happily
    parsed as valid YAML (JSON is a YAML subset), producing a dict with
    none of the expected keys and no visible error anywhere. Every case
    below pins the fix.
    """

    def test_dict_shape_returns_result_field(self):
        stdout = json.dumps({"result": "the actual reply\n```yaml\nfoo: 1\n```", "is_error": False})
        self.assertEqual(tc.extract_assistant_text(stdout), "the actual reply\n```yaml\nfoo: 1\n```")

    def test_dict_shape_missing_result_falls_back_to_raw(self):
        stdout = json.dumps({"is_error": True, "no_result_field": True})
        self.assertEqual(tc.extract_assistant_text(stdout), stdout)

    def test_list_shape_concatenates_assistant_turns(self):
        # Defensive fallback only -- this codebase never actually requests
        # --output-format stream-json, but extract_assistant_text handles
        # it anyway rather than silently mis-parsing it as dict-shaped.
        stdout = json.dumps([
            {"type": "assistant", "message": {"content": [{"type": "text", "text": "working...\n```yaml\nfoo: 1\n```"}]}},
            {"type": "assistant", "message": {"content": [{"type": "text", "text": "done."}]}},
        ])
        text = tc.extract_assistant_text(stdout)
        self.assertIn("```yaml\nfoo: 1\n```", text)
        self.assertIn("done.", text)

    def test_malformed_json_falls_back_to_raw_stdout(self):
        stdout = "not json at all"
        self.assertEqual(tc.extract_assistant_text(stdout), stdout)


class ExtractYamlBlockTests(unittest.TestCase):

    def test_finds_fenced_block(self):
        text = "some reasoning\n```yaml\nvulnerable: true\nconfidence: 90\n```"
        self.assertEqual(tc.extract_yaml_block(text), {"vulnerable": True, "confidence": 90})

    def test_takes_last_of_multiple_blocks(self):
        text = (
            "Here's the schema you asked about:\n```yaml\nvulnerable: true | false\n```\n"
            "My actual answer:\n```yaml\nvulnerable: false\nconfidence: 80\n```"
        )
        self.assertEqual(tc.extract_yaml_block(text), {"vulnerable": False, "confidence": 80})

    def test_no_fenced_block_and_unparseable_text_is_a_parse_error(self):
        result = tc.extract_yaml_block("just: a: sentence: with: too: many: colons: not valid")
        self.assertTrue(result.get("_parse_error"))
        self.assertIn("_raw_text", result)

    def test_no_fenced_block_but_whole_text_happens_to_be_valid_yaml(self):
        # A bare scalar/mapping with no code fence still parses -- this is
        # intentional fallback behavior, not something to "fix": it's what
        # lets a very terse agent reply still work.
        result = tc.extract_yaml_block("vulnerable: true")
        self.assertEqual(result, {"vulnerable": True})


class ReadFileLinesTests(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        with open(os.path.join(self.tmpdir, "sample.py"), "w") as f:
            f.write("line1\nline2\nline3\nline4\nline5\n")

    def test_reads_inclusive_range(self):
        self.assertEqual(tc.read_file_lines(self.tmpdir, "sample.py", "2-4"), "line2\nline3\nline4\n")

    def test_no_range_reads_whole_file(self):
        self.assertEqual(tc.read_file_lines(self.tmpdir, "sample.py", None), "line1\nline2\nline3\nline4\nline5\n")

    def test_missing_file_reports_clearly(self):
        self.assertIn("not found", tc.read_file_lines(self.tmpdir, "does-not-exist.py", "1-1"))

    def test_out_of_range_lines_are_clamped(self):
        self.assertEqual(tc.read_file_lines(self.tmpdir, "sample.py", "3-999"), "line3\nline4\nline5\n")


class DefaultReportPathTests(unittest.TestCase):

    def test_no_iter_suffix(self):
        path = tc.default_report_path("CVE-2026-27825", "cve-3-fixes.yaml")
        self.assertTrue(path.endswith("CVE-2026-27825/cve-3-fixes.yaml"))

    def test_iter_suffix_inserted_before_extension(self):
        path = tc.default_report_path("CVE-2026-27825", "cve-3-fixes.yaml", iter_num=2)
        self.assertTrue(path.endswith("CVE-2026-27825/cve-3-fixes-iter-2.yaml"))


class FindCveRowLanguageRoutingTests(unittest.TestCase):
    """The 'per-language' concern for the triage prototype: given only a
    CVE ID, find_cve_row must resolve it from the right project_info*.csv
    and report the right language -- this is the one place cve_coder.py's
    pipeline is actually language-sensitive (everything else is generic
    natural-language security review, unlike the CodeQL pipeline's
    per-language query templates/prompts)."""

    def test_python_seed_cve_resolves_as_python(self):
        row, language = tc.find_cve_row("CVE-2026-27825")
        self.assertEqual(language, "python")
        self.assertEqual(row["github_repository_name"], "mcp-atlassian")

    def test_javascript_seed_cve_resolves_as_javascript(self):
        row, language = tc.find_cve_row("CVE-2017-16042")
        self.assertEqual(language, "javascript")
        self.assertEqual(row["github_repository_name"], "node-growl")

    # Java coverage deliberately deferred -- focusing on Python then
    # JavaScript first (see docs/DEV/readme-approach.md section 6).

    def test_unknown_cve_resolves_to_none(self):
        row, language = tc.find_cve_row("CVE-0000-00000")
        self.assertIsNone(row)
        self.assertIsNone(language)


class SkillsInstalledTests(unittest.TestCase):
    """src/skills/<step>/{common,<language>} are copied into the checkout's
    .claude/skills/ for one agent call, hidden from git, then removed."""

    def setUp(self):
        from tests.common.repo_fixtures import make_synthetic_repo
        self.repo = make_synthetic_repo("a.py", "x = 1\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.repo, ignore_errors=True)

    def _git_status(self):
        import subprocess
        return subprocess.run(["git", "status", "--porcelain"], cwd=self.repo,
                              capture_output=True, text=True).stdout

    def test_available_names_skip_missing_language(self):
        self.assertEqual(tc.available_skill_names("detect", "python"),
                         ["cve-detect-common", "cve-detect-python"])
        self.assertEqual(tc.available_skill_names("detect", "nonexistent-lang"), ["cve-detect-common"])
        self.assertEqual(tc.available_skill_names("detect", None), ["cve-detect-common"])

    def test_installs_flattened_names_hidden_from_git_and_cleans_up(self):
        with tc.skills_installed("detect", "python", self.repo) as names:
            self.assertEqual(names, ["cve-detect-common", "cve-detect-python"])
            for name in names:
                self.assertTrue(os.path.isfile(os.path.join(self.repo, ".claude", "skills", name, "SKILL.md")))
            self.assertEqual(self._git_status(), "")
        self.assertFalse(os.path.exists(os.path.join(self.repo, ".claude")))

    def test_preserves_preexisting_claude_dir(self):
        os.makedirs(os.path.join(self.repo, ".claude"))
        with tc.skills_installed("detect", "python", self.repo):
            pass
        self.assertTrue(os.path.isdir(os.path.join(self.repo, ".claude")))
        self.assertFalse(os.path.exists(os.path.join(self.repo, ".claude", "skills", "cve-detect-python")))

    def test_skill_frontmatter_name_matches_installed_dir(self):
        for name in tc.available_skill_names("detect", "python"):
            sub = name[len("cve-detect-"):]
            with open(os.path.join(tc.SKILLS_SRC_DIR, "detect", sub, "SKILL.md"), encoding="utf-8") as f:
                self.assertIn(f"name: {name}\n", f.read())


if __name__ == "__main__":
    unittest.main()
