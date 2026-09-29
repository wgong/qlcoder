import os
import re
import chromadb
from dotenv import load_dotenv

load_dotenv()

QL_CODER_ROOT_DIR = os.path.join(os.path.dirname(__file__), "..")
# path to vulnerable and fixed CodeQL databases for CVEs
CVES_PATH = f"{QL_CODER_ROOT_DIR}/cves"
LOGS_DIR = f"{QL_CODER_ROOT_DIR}/logs"
CVE_DESCRIPTIONS_FILE = f"{QL_CODER_ROOT_DIR}/data/cve_descriptions.json"
QUERIES_PATH = f"{QL_CODER_ROOT_DIR}/src/queries"
BUILD_INFO = f"{QL_CODER_ROOT_DIR}/data/build_info.csv"
# chroma db collection for retrieving CVE descriptions
NVD_CACHE="nist_cve_cache"
# chroma db collection for retrieving ASTs of CVE diffs.
AST_CACHE = "cve_ast_cache"
_CODEQL_HOME = os.environ.get("CODEQL_HOME", "/path/to/codeql")

# Base directory holding your CodeQL bundle's per-language qlpacks, e.g.
# ~/codeql/qlpacks/codeql — each language ships as
# <QLPACK_PATH>/<language>-queries/<version>/... and
# <QLPACK_PATH>/<language>-all/<version>/....
QLPACK_PATH = os.environ.get("QLPACK_PATH", f"{_CODEQL_HOME}/qlpacks/codeql")

# Explicit overrides, only honored if the user actually set them (for CodeQL
# installs that don't follow the <language>-queries/<language>-all layout).
_explicit_security_qlpack_path = os.environ.get("SECURITY_QLPACK_PATH")
_explicit_library_qlpack_path = os.environ.get("LIBRARY_QLPACK_PATH")


def _detect_language() -> str:
    """Infer the target language for this run.

    QLCoder operates on one language per run (one .env, one qlpack).
    QLCODER_LANGUAGE is the primary source of truth; if it's unset, fall back
    to parsing an explicitly-set SECURITY_QLPACK_PATH/LIBRARY_QLPACK_PATH
    (CodeQL's own qlpack layout always names the language, e.g.
    .../qlpacks/codeql/python-queries/<version>/...), for back-compat with
    setups that configured those directly. Defaults to "java".
    """
    explicit = os.environ.get("QLCODER_LANGUAGE")
    if explicit:
        return explicit.strip().lower()
    for path in (_explicit_security_qlpack_path, _explicit_library_qlpack_path):
        if not path:
            continue
        match = re.search(r"codeql[/\\]([a-zA-Z]+)-(?:queries|all)", path)
        if match:
            return match.group(1).lower()
    return "java"


# Target language for this run (see _detect_language). Selects the qlpack
# dependency, AST-extraction query variants, CVE metadata CSVs, and the
# derived SECURITY_QLPACK_PATH/LIBRARY_QLPACK_PATH below.
LANGUAGE = _detect_language()


def _find_qlpack_subpath(pack_name: str, tail: str):
    """Auto-detect the installed <version> under QLPACK_PATH/pack_name and
    return QLPACK_PATH/pack_name/<version>/tail, or None if pack_name isn't
    installed under QLPACK_PATH (e.g. QLPACK_PATH itself is unset/wrong)."""
    pack_dir = os.path.join(os.path.expanduser(QLPACK_PATH), pack_name)
    if not os.path.isdir(pack_dir):
        return None

    def _version_key(v):
        return [int(p) if p.isdigit() else p for p in re.split(r"[.\-]", v)]

    versions = sorted(
        (d for d in os.listdir(pack_dir) if os.path.isdir(os.path.join(pack_dir, d))),
        key=_version_key,
    )
    return os.path.join(pack_dir, versions[-1], tail) if versions else None


# path to CodeQL security qlpack: <QLPACK_PATH>/<LANGUAGE>-queries/<version>/Security/CWE,
# version auto-detected from what's installed under QLPACK_PATH. Set
# SECURITY_QLPACK_PATH directly to override (non-standard installs).
SECURITY_QLPACK_PATH = (
    _explicit_security_qlpack_path
    or _find_qlpack_subpath(f"{LANGUAGE}-queries", "Security/CWE")
    or f"{_CODEQL_HOME}/qlpacks/codeql/java-queries/1.6.1/Security/CWE"
)
# path to CodeQL library qlpack: <QLPACK_PATH>/<LANGUAGE>-all/<version>/semmle/code/<LANGUAGE>,
# version auto-detected the same way. Set LIBRARY_QLPACK_PATH directly to override.
LIBRARY_QLPACK_PATH = (
    _explicit_library_qlpack_path
    or _find_qlpack_subpath(f"{LANGUAGE}-all", f"semmle/code/{LANGUAGE}")
    or f"{_CODEQL_HOME}/qlpacks/codeql/java-all/7.4.0/semmle/code/java"
)
CODEQL_LSP_MCP_PATH = os.environ.get("CODEQL_LSP_MCP_PATH", "/path/to/codeql-lsp-mcp")

# CVE metadata CSVs, one pair per language: data/project_info.csv +
# data/fix_info.csv for java (the original, un-suffixed pair, kept for
# backwards compatibility), data/project_info-py.csv + data/fix_info-py.csv
# for python, data/project_info-js.csv + data/fix_info-js.csv for javascript.
_LANGUAGE_CSV_SUFFIX = {"java": "", "python": "-py", "javascript": "-js"}
_csv_suffix = _LANGUAGE_CSV_SUFFIX.get(LANGUAGE, "")
# contains CVE project fix metadata. Java pair adapted from CWE-Bench-Java
FIX_INFO = f"{QL_CODER_ROOT_DIR}/data/fix_info{_csv_suffix}.csv"
# contains CVE project metadata. Java pair adapted from CWE-Bench-Java
PROJECT_INFO = f"{QL_CODER_ROOT_DIR}/data/project_info{_csv_suffix}.csv"
CODEQL_PATH = os.environ.get("CODEQL_PATH", f"{_CODEQL_HOME}/codeql")
# ChromaDB connection settings
# Set CHROMA_HOST to use HTTP client (Docker/remote), unset for local PersistentClient
CHROMA_HOST = os.environ.get("CHROMA_HOST", None)
CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8000"))
CHROMA_AUTH_TOKEN = os.environ.get("CHROMA_AUTH_TOKEN", "test")
CHROMA_DB_PATH = os.environ.get(
    "CHROMA_DB_PATH",
    os.path.join(QL_CODER_ROOT_DIR, "data", "chroma_db")
)

def get_chroma_client() -> chromadb.ClientAPI:
    """Return a ChromaDB client based on environment configuration.

    - If CHROMA_HOST is set: returns HttpClient (for Docker / remote ChromaDB server)
    - Otherwise: returns PersistentClient (for local development)
    """
    if CHROMA_HOST:
        return chromadb.HttpClient(
            host=CHROMA_HOST,
            port=CHROMA_PORT,
            headers={"Authorization": f"Bearer {CHROMA_AUTH_TOKEN}"} if CHROMA_AUTH_TOKEN else None,
        )
    else:
        os.makedirs(CHROMA_DB_PATH, exist_ok=True)
        return chromadb.PersistentClient(path=CHROMA_DB_PATH)