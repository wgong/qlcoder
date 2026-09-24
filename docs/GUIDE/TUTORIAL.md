# QLCoder Tutorial

This walks through trying out QLCoder end-to-end, both with Docker and natively
on Linux, using `CVE-2025-27818` (Apache Kafka, CWE-502 deserialization) as the
worked example — it's already listed in `data/project_info.csv`.

QLCoder drives a coding-agent CLI (Claude Code by default) through a pipeline
that: clones the CVE's repo, builds "vulnerable" and "fixed" CodeQL databases,
extracts the AST of the fix diff, then iteratively writes and tests a CodeQL
query until it flags the vulnerable code and not the fixed code.

## 0. Prerequisites (both paths)

You need, regardless of Docker vs. native:

1. **A CodeQL bundle.** Download from the
   [CodeQL Action releases page](https://github.com/github/codeql-action/releases)
   (`codeql-bundle-linux64.tar.gz`). The paper used 2.22.2, but any version/language
   works.
2. **The [codeql-lsp-mcp](https://github.com/neuralprogram/codeql-lsp-mcp) server**,
   cloned and built (`npm install && npm run build`).
3. **An agent CLI or API key.** By default QLCoder drives Claude Code
   (`--agent claude`), so either:
   - an `ANTHROPIC_API_KEY` (paid API billing), or
   - the `claude` CLI installed and logged in (`claude login`), used with
     `--agent claude_cli` (equivalently `--adapter claude_cli`) for **subscription
     billing** instead of per-token API billing — see [Section 5](#5-using-claude-code-subscription-billing-no-api-key-needed).
4. **The CVE you want must be in `data/project_info.csv`.** `CVE-2025-27818` is
   already there; to try a different one, check with:
   ```sh
   grep "CVE-XXXX-YYYYY" data/project_info.csv
   ```

---

## Path A: Docker (recommended)

Docker is the easiest path — it bundles CodeQL, the LSP MCP server, and Python
deps into one image, and starts a ChromaDB sidecar for you.

### A-1. Make sure the Docker *daemon* is actually running

New to Docker? The `docker` command you type is just a client — it talks to a
background service (the **daemon**, `dockerd`) over a Unix socket. `docker
compose up -d` fails with:

```
Cannot connect to the Docker daemon at unix:///home/gongai/.docker/desktop/docker.sock.
Is the docker daemon running?
```

when that daemon isn't up yet, or the CLI is pointed at a socket nobody's
listening on. The socket path in the error tells you which daemon it tried:
`.../.docker/desktop/docker.sock` means the CLI is currently pointed at
**Docker Desktop's** daemon specifically, not necessarily the only Docker
install on the machine.

**Step 1 — see what Docker "contexts" (daemon targets) exist and which is active:**
```sh
docker context ls
```
The one marked `*` is active. On a machine with Docker Desktop installed you'll
typically see both `default` (a plain system `dockerd`, if installed) and
`desktop-linux` (Docker Desktop's own daemon) — they are two independent
daemons; only one needs to be running.

**Step 2 — check whether either daemon is actually up:**
```sh
systemctl status docker            # the plain system dockerd (Linux package)
systemctl --user status docker-desktop   # Docker Desktop's daemon
```
`Active: active (running)` means that one's alive; `inactive (dead)` means it
isn't.

**Step 3 — fix it, whichever way is true for you:**

- **If the system `docker` service is active** (the `systemctl status docker`
  check above showed `active (running)`), just point the CLI at it instead of
  Docker Desktop:
  ```sh
  docker context use default
  docker info    # should now succeed, no more "Cannot connect" error
  ```
  This is usually the fastest fix if you don't specifically need Docker
  Desktop's GUI/extensions — a plain `dockerd` is enough to run
  `docker compose`.

- **If neither is running and you want to use Docker Desktop,** start it like
  any other GUI app (Applications menu, or `systemctl --user start
  docker-desktop`), then wait for its whale icon / `docker info` to report
  `Server:` details instead of erroring. Docker Desktop needs a graphical
  session to run its UI, even though the daemon itself is headless — if you're
  on a headless/remote box, prefer installing plain `docker.io`/`docker-ce`
  (a systemd service, no GUI needed) over Docker Desktop.

- **If neither is installed at all,** follow Docker's own install guide for
  your distro: https://docs.docker.com/engine/install/ (Docker Engine, no GUI)
  or https://docs.docker.com/desktop/setup/install/linux/ (Docker Desktop).

Once `docker info` succeeds without error, continue below.

### A0. sym-links
```bash
ln -s ~/projects/AI-Tools/CodeQL/codeql ~/codeql
ln -s ~/projects/AI-Tools/CodeQL/codeql-lsp-mcp ~/codeql-lsp-mcp
ln -s ~/projects/AI-Tools/qlcoder ~/qlcoder
```

### A1. Install CodeQL and codeql-lsp-mcp on the host

These are volume-mounted into the container, so they still need to exist on
the host filesystem:

```sh
tar -xzf codeql-bundle-linux64.tar.gz -C ~/
# now ~/codeql/codeql exists

git clone https://github.com/neuralprogram/codeql-lsp-mcp ~/codeql-lsp-mcp
cd ~/codeql-lsp-mcp
npm install
npm run build
cd -
```

### A2. Configure `.env`

```sh
cp .env.example .env
echo "APP_UID=$(id -u)" >> .env
echo "APP_GID=$(id -g)" >> .env
```

Edit `.env` and fill in:

```sh
# only needed if using --agent claude (paid API billing)
ANTHROPIC_API_KEY=sk-ant-...

# only needed if using --agent claude_cli (subscription billing, see Section 5)
CLAUDE_CODE_OAUTH_TOKEN=

# find these version numbers with:
#   ls ~/codeql/qlpacks/codeql/java-queries/   -> SECURITY_QLPACK_PATH
#   ls ~/codeql/qlpacks/codeql/java-all/        -> LIBRARY_QLPACK_PATH
SECURITY_QLPACK_PATH=~/codeql/qlpacks/codeql/java-queries/<version>/Security/CWE
LIBRARY_QLPACK_PATH=~/codeql/qlpacks/codeql/java-all/<version>/semmle/code/java
```

`CODEQL_HOME` and `CODEQL_LSP_MCP_HOME` default to `~/codeql` and
`~/codeql-lsp-mcp` respectively (see `.env.example`) — only override them if you
extracted/cloned elsewhere.

### A3. Start services

```sh
docker compose up -d
docker compose ps      # confirm both "chroma" and "app" are running
```

This builds the `app` image (Claude Code, Gemini CLI, Codex, Python deps) and
starts a `chroma` container listening on `localhost:8000`.

### A4. Retrieve the CVE repo and generate the fix diff

```sh
docker compose run --rm app python3 scripts/get_cve_repos.py --cve CVE-2025-27818
```

This clones `apache/kafka` at the buggy commit into `cves/CVE-2025-27818/` and
generates `cves/CVE-2025-27818/CVE-2025-27818.diff`.

### A5. Build the CodeQL databases

```sh
docker compose run --rm app python3 scripts/build_codeql_dbs.py --cve-id CVE-2025-27818
```

Uses `--build-mode=none` (no build toolchain required). Creates
`cves/CVE-2025-27818/CVE-2025-27818-vul` and `cves/CVE-2025-27818/CVE-2025-27818-fix`.
This step can take a while for larger repos like Kafka.

### A6. Populate the RAG database

```sh
docker compose run --rm app python3 scripts/codeql_docs_fetcher.py   # one-time
docker compose run --rm app python3 scripts/cwe_fetcher.py           # one-time
docker compose run --rm app python3 scripts/cves_fetcher.py          # re-run after adding CVEs
```

These populate the `nist_cve_cache` and CodeQL-docs Chroma collections that the
agent queries via RAG during synthesis.

### A7. Run the pipeline

```sh
./run_cve.sh CVE-2025-27818
```

Or with options (see [Section 5](#5-using-claude-code-subscription-billing-no-api-key-needed)
and [Section 6](#6-picking-a-modelagent)):

```sh
./run_cve.sh CVE-2025-27818 --adapter claude_cli --model claude-sonnet-5 --max-iteration 10
```

`run_cve.sh` is a thin wrapper:
```sh
docker compose run --rm app python3 src/ql_agent.py \
  --cve-id CVE-2025-27818 \
  --vuln-db cves/CVE-2025-27818/CVE-2025-27818-vul \
  --fixed-db cves/CVE-2025-27818/CVE-2025-27818-fix \
  --diff cves/CVE-2025-27818/CVE-2025-27818.diff \
  "$@"
```
so any flag you pass after the CVE ID goes straight to `src/ql_agent.py`.

### A8. Inspect results

Output lands in `output/ql_agent_CVE-2025-27818_<timestamp>_<N>-iterations_<model>_<ablation-mode>/`:
- `results/` — per-iteration logs, the compiled `.ql` query, and evaluation output
- a metadata file with pass/fail, recall/precision per iteration, and the final
  query path
- a cost/usage summary (token counts, `$` cost — `$0` when using `claude_cli`
  subscription billing)

### A9. Tear down / clean up

```sh
docker compose down                                    # stop services
docker compose run --rm app python3 scripts/delete_cve_analysis_collections.py   # clean up per-run Chroma collections
```

---

## Path B: Native (Linux)

Use this if you don't want Docker, or need to debug the pipeline directly.

### B1. Install CodeQL

```sh
tar -xzf codeql-bundle-linux64.tar.gz
export PATH="$PWD/codeql:$PATH"
```
Add the `export` line to your shell profile to persist it.

### B2. Install codeql-lsp-mcp

```sh
git clone https://github.com/neuralprogram/codeql-lsp-mcp
cd codeql-lsp-mcp
npm install
npm run build
cd -
```

### B3. Set up the Conda environment

```sh
conda env create -f environment.yml
conda activate qlcoder
```

### B4. Configure `.env`

```sh
cp .env.example .env
```

Fill in:
```sh
ANTHROPIC_API_KEY=sk-ant-...          # only if using --agent claude
CLAUDE_CODE_OAUTH_TOKEN=              # only if using --agent claude_cli, see Section 5
CODEQL_HOME=~/codeql
CODEQL_LSP_MCP_HOME=~/codeql-lsp-mcp
SECURITY_QLPACK_PATH=~/codeql/qlpacks/codeql/java-queries/<version>/Security/CWE
LIBRARY_QLPACK_PATH=~/codeql/qlpacks/codeql/java-all/<version>/semmle/code/java
```

Find the `<version>` numbers with:
```sh
ls ~/codeql/qlpacks/codeql/java-queries/
ls ~/codeql/qlpacks/codeql/java-all/
```

### B5. Retrieve the CVE repo and generate the fix diff

```sh
python3 scripts/get_cve_repos.py --cve CVE-2025-27818
```

### B6. Build the CodeQL databases

```sh
python3 scripts/build_codeql_dbs.py --cve-id CVE-2025-27818
```

### B7. Start ChromaDB

In a **separate terminal**, and keep it running for the rest of this tutorial:

```sh
chroma run --path data/chroma_db
```

Unlike Docker (which sets `CHROMA_HOST` so `src/config.py` uses an `HttpClient`),
native runs leave `CHROMA_HOST` unset, so `get_chroma_client()` uses a
`PersistentClient` pointed at `data/chroma_db` — the `chroma run` server and the
pipeline's own Python process both need to agree on that path, which they do by
default.

### B8. Populate the RAG database

```sh
python3 scripts/codeql_docs_fetcher.py   # one-time
python3 scripts/cwe_fetcher.py           # one-time
python3 scripts/cves_fetcher.py          # re-run after adding CVEs
```

### B9. Run the pipeline

```sh
python3 src/ql_agent.py \
  --cve-id CVE-2025-27818 \
  --vuln-db cves/CVE-2025-27818/CVE-2025-27818-vul \
  --fixed-db cves/CVE-2025-27818/CVE-2025-27818-fix \
  --diff cves/CVE-2025-27818/CVE-2025-27818.diff \
  --adapter claude_cli --model claude-sonnet-5 --max-iteration 10
```

If `--vuln-db`/`--fixed-db`/`--diff` are omitted, `QLAgentIterativeCLI.discover_cve_paths`
auto-discovers them from `cves/<CVE-ID>/` by convention, so the above can be
shortened to:
```sh
python3 src/ql_agent.py --cve-id CVE-2025-27818 --adapter claude_cli --model claude-sonnet-5
```

### B10. Inspect results

Same as [A8](#a8-inspect-results) — `output/ql_agent_CVE-2025-27818_.../`.

---

## 5. Using Claude Code subscription billing (no API key needed)

If you already pay for a Claude Code subscription and don't want per-token API
charges, use `--agent claude_cli` (alias `--adapter claude_cli`):

```sh
./run_cve.sh CVE-2025-27818 --adapter claude_cli --model claude-sonnet-5
# or natively:
python3 src/ql_agent.py --cve-id CVE-2025-27818 --adapter claude_cli --model claude-sonnet-5
```

How it works: `ClaudeCLIBackend` (`src/agent_backends/claude_cli_backend.py`)
wraps the same logic as the default `claude` backend, but strips
`ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL`, and Claude Code's nested-session
guard vars from the subprocess environment before invoking the `claude` CLI.
With no API key visible, the CLI falls back to its locally stored OAuth
session — the same one used by interactive `claude` sessions — so usage is
billed against your subscription, not the API. The cost/usage summary written
to `output/.../` will show `$0` for these runs.

Setup:
- **Native:** run `claude login` once on the host before running the pipeline.
- **Docker:** either bake in `CLAUDE_CODE_OAUTH_TOKEN` in `.env` (passed through
  by `docker-compose.yml`), or `docker compose run --rm app claude login`
  interactively once, then reuse the container.

`--model claude-sonnet-5` is passed straight through to the `claude` CLI's own
`--model` flag — QLCoder doesn't restrict `--model` to a fixed list. A few
short aliases are recognized for convenience (see `MODELS` in
`src/agent_backends/claude_backend.py`): `sonnet-4`, `sonnet-4.5`, `sonnet-5`.
Anything else, including full model ids like `claude-sonnet-5` or
`claude-opus-4-6`, is used as-is.

## 6. Picking a model/agent

| `--agent`/`--adapter` | Backend | Billing | Notes |
|---|---|---|---|
| `claude` (default) | Claude Code | Anthropic API (`ANTHROPIC_API_KEY`) | full MCP tool access |
| `claude_cli` | Claude Code | Claude Code subscription | see Section 5 |
| `gemini` | Gemini CLI | `GEMINI_API_KEY` | |
| `codex` | Codex CLI | `OPENAI_API_KEY` | GPT and open-source models |

`--model` aliases per agent: `sonnet-4`, `sonnet-4.5`, `sonnet-5` (Claude);
`gemini-2.5-pro`, `gemini-2.5-flash` (Gemini); `gpt-5` (Codex, medium reasoning
effort by default — override in
[`codex_backend.py`](../../src/agent_backends/codex_backend.py#L365)).

## 7. Ablation modes

`--ablation-mode` controls which tools/context the agent gets, useful for
comparing how much QLCoder's scaffolding matters:

| Mode | Description | Supported agents |
|---|---|---|
| `full` (default) | All tools + AST extraction | claude, codex, gemini |
| `no_tools` | No tools, no AST extraction | claude, codex, gemini |
| `no_lsp` | No CodeQL LSP tools | claude only |
| `no_docs` | No CodeQL documentation retrieval | claude only |
| `no_ast` | No AST extraction from diff | claude only |

```sh
./run_cve.sh CVE-2025-27818 --ablation-mode no_tools
```

`no_tools`/`no_docs` skip Chroma and instead read a pre-fetched CVE
description from `data/cve_descriptions.json` (populate it with
`python3 scripts/cves_fetcher.py --descriptions-file data/cve_descriptions.json`).

## 8. Cleaning up between runs

Each run creates a `cve_analysis_<cve>_<run_id>` Chroma collection for RAG
retrieval during that run. These accumulate over time:

```sh
python3 scripts/delete_cve_analysis_collections.py
# or, for full inspection/maintenance:
# pip install chromadb-ops, then:
chops db clean data/chroma_db
```

## 9. Troubleshooting

- **"Context window failed" / timeout errors** — each agent context window has
  a default shell timeout (300s). Increase it in the relevant backend's
  `execute_prompt` method (e.g. `asyncio.wait_for(..., timeout=3600)` in
  `claude_backend.py`).
- **`rtk gain` / wrong `rtk`** — unrelated to QLCoder; if you have the Rust
  Token Killer CLI hook installed, `git status` etc. get transparently rewritten
  to `rtk git status`. Ignore unless you're seeing hook-related errors.
- **Chroma connection errors (native)** — confirm `chroma run --path data/chroma_db`
  is still running in its own terminal; `CHROMA_HOST` must stay unset natively.
- **Chroma connection errors (Docker)** — confirm `docker compose ps` shows
  `chroma` as `Up`; `CHROMA_HOST=chroma` is set by `docker-compose.yml` for the
  `app` service.
- **`claude_cli` still billing the API** — make sure `ANTHROPIC_API_KEY` isn't
  exported in a way that reaches the container/shell in an unexpected place;
  `ClaudeCLIBackend` only strips it from the subprocess env it constructs, not
  from your shell's own `.bashrc`/`.env` exports elsewhere.
