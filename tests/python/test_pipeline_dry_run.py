"""cve_coder.py pipeline wiring, exercised against a Python source file.

Offline and fast: --repo-path points at a synthetic one-commit local repo
(see tests/common/repo_fixtures.py), and --dry-run skips every actual
agent call, so this only proves the mechanical wiring (CLI parsing, report
chaining, file naming) works for a Python target -- not that a real Python
CVE gets detected/fixed/verified correctly. For that, see the live-run
instructions in tests/README.md (uses the real, pre-vetted CVE-2026-27825
from data/project_info-py.csv).

Run with:
    python3 -m unittest tests.python.test_pipeline_dry_run -v
"""
import os
import shutil
import subprocess
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scripts import triage_common as tc
from tests.common.repo_fixtures import make_synthetic_repo

_CVE_ID = "CVE-9999-00001"

_SAMPLE_SOURCE = '''\
import os


def download_attachment(download_path, content):
    """Toy stand-in for a path-traversal-prone download handler."""
    target = os.path.abspath(download_path)
    with open(target, "wb") as f:
        f.write(content)
'''


class PythonPipelineDryRunTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.repo_dir = make_synthetic_repo("vulnerable.py", _SAMPLE_SOURCE)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.repo_dir, ignore_errors=True)
        # cve_patch.py clones an isolated "-patched" sibling of the source repo.
        shutil.rmtree(cls.repo_dir + "-patched", ignore_errors=True)

    def tearDown(self):
        shutil.rmtree(os.path.join(tc.TRIAGE_OUTPUT_DIR, _CVE_ID), ignore_errors=True)

    def test_dry_run_pipeline_produces_all_five_reports(self):
        result = subprocess.run(
            [sys.executable, "scripts/cve_coder.py", "pipeline",
             "--cve-id", _CVE_ID, "--repo-path", self.repo_dir, "--dry-run"],
            cwd=_ROOT, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        for filename in ("cve-1-metadata.yaml", "cve-2-findings.yaml", "cve-3-fixes.yaml",
                          "cve-4-tests.yaml", "cve-5-pipeline.yaml"):
            path = tc.default_report_path(_CVE_ID, filename)
            self.assertTrue(os.path.isfile(path), f"missing {filename}")

        spec = tc.load_report(tc.default_report_path(_CVE_ID, "cve-1-metadata.yaml"))
        self.assertEqual(spec["repo_dir"], self.repo_dir)

        summary = tc.load_report(tc.default_report_path(_CVE_ID, "cve-5-pipeline.yaml"))
        self.assertEqual(summary["stages_run"], ["spec", "detect", "patch", "verify"])


if __name__ == "__main__":
    unittest.main()
