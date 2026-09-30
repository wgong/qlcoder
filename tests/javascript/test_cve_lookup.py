"""Sanity check that the JavaScript CVE seed data resolves correctly,
without digging through tests/common/. Offline, no network, no agent calls.

Run with:
    python3 -m unittest tests.javascript.test_cve_lookup -v
"""
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scripts import triage_common as tc


class JavaScriptCveLookupTest(unittest.TestCase):

    def test_seed_cve_resolves_from_javascript_csv(self):
        row, language = tc.find_cve_row("CVE-2017-16042")
        self.assertEqual(language, "javascript")
        self.assertEqual(row["github_repository_name"], "node-growl")
        self.assertEqual(row["github_url"], "https://github.com/tj/node-growl")

    def test_seed_cve_has_matching_fix_info_row(self):
        _, language = tc.find_cve_row("CVE-2017-16042")
        fix_rows = tc.find_fix_info_rows("CVE-2017-16042", language)
        self.assertGreater(len(fix_rows), 0)


if __name__ == "__main__":
    unittest.main()
