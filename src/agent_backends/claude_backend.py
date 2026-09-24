import asyncio
import json
import os
import re
import shutil
import subprocess
from typing import Dict, Optional

from . import AgentBackend
from src.config import CHROMA_DB_PATH, CHROMA_AUTH_TOKEN, CHROMA_HOST, CHROMA_PORT, CODEQL_LSP_MCP_PATH
from . import claude_prompts as prompts

# Ablation modes that skip Chroma MCP setup
_NO_CHROMA_MODES = ("no_tools",)
# Ablation modes that skip CodeQL LSP MCP setup
_NO_LSP_MODES = ("no_tools", "no_lsp")

MODELS = {
    "sonnet-4": "claude-sonnet-4-20250514",
    "sonnet-4.5": "claude-sonnet-4-5-20250929",
    "sonnet-5": "claude-sonnet-5",
}


class ClaudeBackend(AgentBackend):

    def __init__(self, model: str, logger, ablation_mode: str = "full"):
        super().__init__(model, logger, ablation_mode=ablation_mode)
        self.cli_path = os.environ.get(
            "CLAUDE_CODE_PATH", shutil.which("claude") or "claude"
        )

    def get_tool_prefix(self) -> str:
        return "mcp__chroma__"

    def get_codeql_tool_prefix(self) -> str:
        return "mcp__codeql__"

    @staticmethod
    def extract_text_output(stdout: str) -> str:
        """Extract the final assistant text from claude --output-format json output."""
        try:
            objs = json.loads(stdout)
            if not isinstance(objs, list):
                return stdout
            for obj in reversed(objs):
                if obj.get("type") == "assistant":
                    blocks = obj.get("message", {}).get("content", [])
                    text_parts = [b["text"] for b in blocks if b.get("type") == "text"]
                    if text_parts:
                        return "\n".join(text_parts).strip()
        except Exception:
            pass
        return stdout

    def parse_usage(self, stdout: str) -> Dict:
        usage = {
            "total_cost_usd": 0.0,
            "total_input_tokens": 0,
            "total_cache_creation_tokens": 0,
            "total_cache_read_tokens": 0,
            "total_output_tokens": 0,
            "sessions_count": 0,
            "parsing_errors": [],
        }

        try:
            pattern = (
                r'"total_cost_usd":([0-9.]+),"usage":\{'
                r'"input_tokens":([0-9]+),'
                r'"cache_creation_input_tokens":([0-9]+),'
                r'"cache_read_input_tokens":([0-9]+),'
                r'"output_tokens":([0-9]+)[^}]*\}'
            )
            matches = re.findall(pattern, stdout)
            if matches:
                for m in matches:
                    try:
                        usage["total_cost_usd"] += float(m[0])
                        usage["total_input_tokens"] += int(m[1])
                        usage["total_cache_creation_tokens"] += int(m[2])
                        usage["total_cache_read_tokens"] += int(m[3])
                        usage["total_output_tokens"] += int(m[4])
                        usage["sessions_count"] += 1
                    except (ValueError, IndexError) as e:
                        usage["parsing_errors"].append(f"Error parsing match {m}: {e}")

                self.logger.info(
                    f"Parsed {usage['sessions_count']} API usage entries, "
                    f"total cost: ${usage['total_cost_usd']:.6f}"
                )
            else:
                self.logger.warning("No Claude API usage data found in output")
                usage["parsing_errors"].append("No usage pattern matches found")
        except Exception as e:
            self.logger.error(f"Error parsing Claude API usage: {e}")
            usage["parsing_errors"].append(f"General parsing error: {e}")

        return usage

    def setup_workspace(self, output_dir: str, task) -> Optional[str]:
        """Generate MCP desktop config + register project-scoped MCP servers."""
        if self.ablation_mode in _NO_CHROMA_MODES:
            # Remove any existing .mcp.json so no MCP tools are available
            mcp_json = os.path.join(output_dir, ".mcp.json")
            if os.path.exists(mcp_json):
                os.remove(mcp_json)
            self.logger.info(f"Ablation mode '{self.ablation_mode}': skipping all MCP setup")
            return None

        config_path = self._generate_mcp_config(output_dir)
        if self.ablation_mode not in _NO_LSP_MODES:
            self._setup_project_scoped_codeql(output_dir)
        else:
            self.logger.info(f"Ablation mode '{self.ablation_mode}': skipping CodeQL LSP MCP setup")
        self._setup_project_scoped_chroma(output_dir)
        return config_path

    async def execute_prompt(
        self,
        prompt: str,
        env: dict,
        cwd: str,
        phase_name: str,
    ) -> Dict:
        """Execute a single Claude Code context window."""
        model_id = MODELS.get(self.model, self.model)

        allowed_tools, disallowed_tools = self._get_tool_flags()
        cmd = [
            self.cli_path,
            "--print",
            "--output-format", "json",
            "--model", model_id,
            "--max-turns", "50",
            "--verbose",
            "--allowedTools", allowed_tools,
        ]
        if disallowed_tools:
            cmd += ["--disallowedTools", disallowed_tools]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                env=env,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )

            process.stdin.write(prompt.encode())
            process.stdin.close()

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), timeout=3600
            )

            stdout_str = stdout_bytes.decode("utf-8")
            stderr_str = stderr_bytes.decode("utf-8")
            api_usage = self.parse_usage(stdout_str)

            return {
                "stdout": stdout_str,
                "stderr": stderr_str,
                "returncode": process.returncode,
                "api_usage": api_usage,
            }

        except Exception as e:
            self.logger.error(f"Claude execution failed: {e}")
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": 1,
                "api_usage": self.parse_usage(""),
            }

    def _get_tool_flags(self) -> tuple:
        """Return (allowed_tools_str, disallowed_tools_str) for the current ablation mode."""
        chroma_disallow = (
            "mcp__chroma__chroma_list_collections,"
            "mcp__chroma__chroma_modify_collection,"
            "mcp__chroma__chroma_delete_collection,"
            "mcp__chroma__chroma_add_documents,"
            "mcp__chroma__chroma_update_documents,"
            "mcp__chroma__chroma_delete_documents"
        )
        base_disallow = f"WebSearch,Bash(codeql:*),Bash(python:*),{chroma_disallow}"

        if self.ablation_mode == "no_tools":
            return "TodoWrite,Read,Write,Glob,Grep,Edit", "WebSearch,Bash(codeql:*),Bash(python:*)"
        elif self.ablation_mode == "no_lsp":
            return "mcp__chroma,TodoWrite,Read,Write,Glob,Grep,Edit", base_disallow
        else:
            # full, no_docs, no_ast — full MCP access; prompt controls behaviour
            return "mcp__chroma,mcp__codeql,TodoWrite,Read,Write,Glob,Grep,Edit", base_disallow

    # Prompt generation

    def create_phase1_prompt(self, task) -> str:
        if self.ablation_mode in ("no_tools", "no_docs"):
            return prompts.phase1_no_docs(task)
        return prompts.phase1_full(task)

    def create_phase3_initial_prompt(self, task, use_cache: bool, collection_name: str,
                                     phase1_output: str = "") -> str:
        if self.ablation_mode == "no_tools":
            return prompts.phase3_no_tools(task, phase1_output=phase1_output)
        elif self.ablation_mode == "no_lsp":
            return prompts.phase3_no_lsp(task, use_cache, collection_name)
        elif self.ablation_mode == "no_docs":
            return prompts.phase3_no_docs(task, use_cache, collection_name)
        elif self.ablation_mode == "no_ast":
            return prompts.phase3_no_ast(task, use_cache, collection_name)
        else:
            return prompts.phase3_full(task, use_cache=use_cache, collection_name=collection_name)

    def create_refinement_prompt(self, task, previous_feedback: str,
                                 iteration: int, collection_name: str) -> str:
        if self.ablation_mode == "no_tools":
            return prompts.refinement_no_tools(task, previous_feedback, iteration)
        elif self.ablation_mode == "no_lsp":
            return prompts.refinement_no_lsp(task, previous_feedback, iteration, collection_name)
        elif self.ablation_mode == "no_docs":
            return prompts.refinement_no_docs(task, previous_feedback, iteration, collection_name)
        elif self.ablation_mode == "no_ast":
            return prompts.refinement_no_ast(task, previous_feedback, iteration, collection_name)
        else:
            return prompts.refinement_full(task, previous_feedback, iteration, collection_name)

    # Claude-specific helpers

    def _generate_mcp_config(self, working_dir: str) -> str:
        """Generate MCP desktop config JSON from environment variables."""
        codeql_mcp = os.environ.get(
            "CODEQL_MCP_PATH", f"{CODEQL_LSP_MCP_PATH}/dist/index.js"
        )

        config = {
            "mcpServers": {
                "chroma-http": {
                    "command": "uvx",
                    "args": [
                        "chroma",
                        "--client-type", "http",
                        "--host", f"http://{CHROMA_HOST}",
                        "--port", str(CHROMA_PORT),
                        "--custom-auth-credentials", CHROMA_AUTH_TOKEN,
                        "--ssl", "false",
                    ],
                },
                "codeql": {
                    "command": "node",
                    "args": [codeql_mcp],
                },
            }
        }

        config_dir = os.path.join(working_dir, "mcp_configs")
        os.makedirs(config_dir, exist_ok=True)
        config_path = os.path.join(config_dir, "claude_desktop_config.json")
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        self.logger.info(f"Generated MCP config at {config_path}")
        return config_path

    def _setup_project_scoped_codeql(self, workspace_dir: str):
        """Register project-scoped CodeQL MCP server."""
        original_cwd = os.getcwd()
        os.chdir(workspace_dir)
        try:
            self.logger.info("Setting up project-scoped CodeQL MCP server...")
            result = subprocess.run(
                [
                    "claude", "mcp", "add", "codeql",
                    "--scope", "project",
                    "node",
                    f"{CODEQL_LSP_MCP_PATH}/dist/index.js"
                ],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                self.logger.warning(f"CodeQL MCP setup: {result.stderr}")
            else:
                self.logger.info("CodeQL MCP configured")

            if os.path.exists(".mcp.json"):
                self.logger.info("Project-scoped CodeQL MCP configured successfully")
                with open(".mcp.json") as f:
                    self.logger.debug(f"MCP config: {json.load(f)}")
            else:
                self.logger.warning(".mcp.json file not created")
        except Exception as e:
            self.logger.error(f"Failed to setup project-scoped CodeQL MCP: {e}")
        finally:
            os.chdir(original_cwd)

    def _setup_project_scoped_chroma(self, workspace_dir: str):
        """Register project-scoped Chroma MCP server (HTTP client)."""
        original_cwd = os.getcwd()
        os.chdir(workspace_dir)
        try:
            self.logger.info("Setting up project-scoped Chroma MCP server...")
            result = subprocess.run(
                [
                    "claude", "mcp", "add", "chroma",
                    "--scope", "project", "--",
                    "uvx", "chroma-mcp",
                    "--client-type", "http",
                    "--host", CHROMA_HOST,
                    "--port", str(CHROMA_PORT),
                    "--custom-auth-credentials", CHROMA_AUTH_TOKEN,
                    "--ssl", "false",
                ],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                self.logger.warning(f"Chroma MCP setup: {result.stderr}")
            else:
                self.logger.info("Chroma MCP configured with HTTP client")

            if os.path.exists(".mcp.json"):
                self.logger.info("Project-scoped Chroma MCP configured successfully")
                with open(".mcp.json") as f:
                    self.logger.debug(f"MCP config: {json.load(f)}")
            else:
                self.logger.warning(".mcp.json file not created")
        except Exception as e:
            self.logger.error(f"Failed to setup project-scoped Chroma MCP: {e}")
        finally:
            os.chdir(original_cwd)
