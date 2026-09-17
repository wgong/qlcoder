"""Claude Code CLI backend: forces Claude Code subscription/session auth.

`ClaudeBackend` invokes the `claude` CLI but passes the parent environment
through unchanged, so if `ANTHROPIC_API_KEY` is set the CLI bills against
the paid Anthropic API instead of using the local Claude Code session
(subscription billing, zero marginal cost). This backend strips the
API-key/session-marker env vars before every invocation so `claude` always
falls back to its locally-stored OAuth/session credentials.
"""

from typing import Dict

from .claude_backend import ClaudeBackend

# Vars that would route requests to the paid API (or confuse a nested
# Claude Code session) instead of the local subscription session.
_STRIP_VARS = {
    "ANTHROPIC_API_KEY",       # paid API — must NOT be used here
    "ANTHROPIC_BASE_URL",      # API base URL — not needed for CLI auth
    "CLAUDECODE",              # nested-session guard
    "CLAUDE_CODE_ENTRYPOINT",  # nested-session guard
}


class ClaudeCLIBackend(ClaudeBackend):
    """ClaudeBackend variant that always uses Claude Code session auth.

    Identical to `ClaudeBackend` (same MCP setup, prompts, and output
    parsing) except that it strips `ANTHROPIC_API_KEY` and related vars
    from the subprocess environment, guaranteeing subscription billing
    even when an API key happens to be present in the caller's environment.
    """

    async def execute_prompt(
        self,
        prompt: str,
        env: dict,
        cwd: str,
        phase_name: str,
    ) -> Dict:
        stripped_env = {k: v for k, v in env.items() if k not in _STRIP_VARS}
        return await super().execute_prompt(prompt, stripped_env, cwd, phase_name)
