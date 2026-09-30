---
name: cve-detect-python
description: Python-specific search patterns, sinks, sanitizer pitfalls and entry points for detecting a described CVE/CWE vulnerability by reading a Python repository. Use together with cve-detect-common during the detect step of CVE triage on Python code.
---

# CVE detect: Python

Apply after `cve-detect-common`. This file supplies Python-specific sinks, guards and entry
points. Search with `Grep`; the patterns below are starting points, not complete lists.

## Where untrusted input enters

- Web: Flask `@app.route` / `request.args|form|json|files`, Django `urls.py` + views +
  `request.GET|POST`, FastAPI path operations and their parameters, aiohttp/Starlette/Tornado handlers.
- CLI and config: `argparse`, `click`, `sys.argv`, environment variables, config files.
- Messaging and jobs: Celery tasks, queue consumers, webhooks.
- **MCP servers and LLM tool wrappers** (`@mcp.tool`, `@server.tool`, tool handlers): arguments
  come from a model or remote client and must be treated as untrusted.
- Files and archives the user supplies: uploads, `zipfile`, `tarfile`, pickles, YAML, XML.
- Dynamic wiring: `getattr(obj, name)`, plugin registries, decorators, `functools.partial`.
  Find the registration rather than assuming a function is unused.

## Sinks by CWE

| CWE | Look for | Notes |
|---|---|---|
| 22 path traversal | `open`, `Path(...).read_*`, `send_file`, `send_from_directory`, `os.path.join`, `shutil.*`, `zipfile.extractall`, `tarfile.extractall`, `shutil.unpack_archive` | Archive extraction is a traversal sink (zip slip). |
| 78 / 77 command injection | `subprocess.*(..., shell=True)`, `os.system`, `os.popen`, `asyncio.create_subprocess_shell` | List argv without a shell is safe from shell injection, but check argument injection (values starting with `-`). |
| 89 SQL injection | f-string, `%`, `.format()`, `+` inside `cursor.execute`; SQLAlchemy `text()`, Django `raw()`, `extra()`, `RawSQL` | Parameterized `execute(sql, params)` is safe. |
| 79 XSS / 1336 SSTI | `Markup(...)`, `|safe`, `mark_safe`, `render_template_string`, `Template(user).render`, Jinja2 `Environment` without `autoescape` | Jinja2 `Environment()` does not autoescape by default. |
| 94 / 95 code injection | `eval`, `exec`, `compile`, `__import__`, `importlib.import_module` on user input | |
| 502 deserialization | `pickle.load(s)`, `marshal`, `shelve`, `jsonpickle`, `yaml.load` without `SafeLoader`, `torch.load` without `weights_only=True` | `yaml.safe_load` is fine. |
| 918 SSRF | `requests.*`, `httpx.*`, `urllib.request.urlopen`, `aiohttp` with a user-influenced URL | Check allowlist, redirects, scheme, and IP checks that resolve DNS separately from the request. |
| 611 XXE | `lxml.etree` with `resolve_entities=True`, `xml.sax`, `xml.dom`, `XMLParser` | `defusedxml` is the safe alternative. |
| 601 open redirect | `redirect(request.args[...])`, `HttpResponseRedirect(user)` | Check for a scheme/host allowlist. |
| 287 / 862 / 863 authn/authz | missing `@login_required` or permission check on one route among many, tokens compared with `==` (use `hmac.compare_digest`), JWT `decode(..., verify_signature=False)`, `algorithms` including `none` | The defect is often a *missing* check on a sibling handler. |
| 295 / 327 / 330 crypto | `verify=False`, `ssl._create_unverified_context`, `md5`/`sha1` for secrets, `random` used for tokens (should be `secrets`), hardcoded keys | |
| 1333 ReDoS | nested quantifiers in `re.compile` applied to user input | |
| 400 / 770 resource exhaustion | unbounded reads (`request.data`, `.read()`), no size limits on uploads or decompression | |
| 200 / 532 info exposure | secrets or tokens in logs, exceptions or responses | |

## Sanitizer pitfalls

- `os.path.abspath` and `os.path.normpath` do not confine a path to a directory.
- `os.path.join(base, user)` discards `base` when `user` is absolute.
- `path.startswith(base)` without a trailing separator lets `/data/uploads-evil` pass for
  `/data/uploads`. Sound checks: `os.path.commonpath`, `Path.resolve()` then
  `is_relative_to(base.resolve())`, or `werkzeug.utils.secure_filename` for a filename.
  Confirm symlinks and `..` are resolved before the check, not after.
- Validation applied to the raw string but a different decoded value used afterward
  (URL-decoding, Unicode normalization, `~` expansion).
- Checks in one handler but not its async, batch, or v2 sibling.
- `assert` used as a security check disappears under `python -O`.

## Dependency vulnerabilities

If the CVE is in a third-party package, read `requirements*.txt`, `pyproject.toml`,
`poetry.lock`, `Pipfile(.lock)`, `setup.py`/`setup.cfg`. Report the line that allows or pins a
vulnerable version, then grep for imports of the affected module and calls to the affected API
to judge reachability. Unpinned ranges (`>=`) that admit a vulnerable release still count, with
lower confidence if a lockfile pins a fixed one.

## Search tips

- `Grep` for the sink name, then for each caller. Include `*.py` only; also check `*.pyi` and
  templates (`*.html`, `*.jinja*`) for XSS and SSTI.
- Search for the parameter or feature named in the CVE description (for example an endpoint,
  option or tool name), including its snake_case and camelCase forms.
- Skip `venv/`, `.venv/`, `site-packages/`, `build/`, `dist/`, `__pycache__/`, and `tests/`
  unless the description points there.
