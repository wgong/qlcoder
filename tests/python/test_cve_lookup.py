"""Sanity check that the Python CVE seed data resolves correctly, without
digging through tests/common/. Offline, no network, no agent calls.

Run with:
    python3 -m unittest tests.python.test_cve_lookup -v
"""
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scripts import triage_common as tc


class PythonCveLookupTest(unittest.TestCase):

    def test_seed_cve_resolves_from_python_csv(self):
        row, language = tc.find_cve_row("CVE-2026-27825")
        self.assertEqual(language, "python")
        self.assertEqual(row["github_repository_name"], "mcp-atlassian")
        self.assertEqual(row["github_url"], "https://github.com/sooperset/mcp-atlassian")

    def test_seed_cve_has_matching_fix_info_row(self):
        _, language = tc.find_cve_row("CVE-2026-27825")
        fix_rows = tc.find_fix_info_rows("CVE-2026-27825", language)
        self.assertGreater(len(fix_rows), 0)


if __name__ == "__main__":
    unittest.main()
