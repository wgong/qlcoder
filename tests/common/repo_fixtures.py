"""Shared test fixture: a tiny synthetic local git repo, used by the
per-language cve_coder.py pipeline smoke tests (tests/<language>/
test_pipeline_dry_run.py).

Deliberately synthetic rather than a real cloned CVE repo: cve_coder.py's
pipeline is almost entirely language-agnostic (unlike the CodeQL
query-synthesis pipeline, its prompts are generic natural-language security
review, not per-language templates) -- the one place it's actually
language-sensitive is CVE-ID -> project_info*.csv routing, which is
already covered offline in tests/common/test_triage_common.py's
FindCveRowLanguageRoutingTests. What the per-language pipeline tests need
is just "does the mechanical --repo-path wiring work end to end for this
language's file extension", which a one-commit local repo answers just as
well as a real clone -- without the size/network/flakiness cost of picking
and cloning a real small-enough CVE repo for each language.
"""
import subprocess
import tempfile


def make_synthetic_repo(filename: str, content: str) -> str:
    """Create a one-file, one-commit git repo in a fresh temp dir. Returns
    the repo directory (the caller is responsible for cleaning it up)."""
    repo_dir = tempfile.mkdtemp(prefix="cve_coder_test_repo_")
    subprocess.run(["git", "init", "--quiet"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)
    with open(f"{repo_dir}/{filename}", "w") as f:
        f.write(content)
    subprocess.run(["git", "add", filename], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "initial"], cwd=repo_dir, check=True)
    return repo_dir
