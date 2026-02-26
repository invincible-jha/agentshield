"""ToolCallValidatorScanner — validate tool invocations before dispatch.

Provides structural validation of tool call arguments to catch common
abuse patterns before they reach backing services:

* Path traversal sequences in file-path arguments.
* Shell metacharacters in arguments that will be passed to a shell.
* Suspicious URL schemes in arguments intended for HTTP clients.
* Argument type mismatches against a declared schema.

Runs exclusively during the TOOL_CALL phase.
"""
from __future__ import annotations

import json
import re

from agentshield.core.context import ScanContext
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase, Scanner

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Path traversal: sequences that walk up directory trees.
_PATH_TRAVERSAL_PATTERN: re.Pattern[str] = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e[%/\\]|%252e%252e)",
    re.IGNORECASE,
)

# Shell metacharacters that should never appear in non-shell arguments.
_SHELL_META_PATTERN: re.Pattern[str] = re.compile(
    r"[;&|`$<>\\!]|\$\(|\$\{|\|\|?|&&"
)

# URL schemes that suggest Server-Side Request Forgery (SSRF) risk.
_SUSPICIOUS_URL_SCHEME_PATTERN: re.Pattern[str] = re.compile(
    r"^(?:file|gopher|dict|ldap|ftp|sftp|tftp|jar|netdoc|data)://",
    re.IGNORECASE,
)

# Private / loopback IP ranges in URLs (SSRF to internal services).
_PRIVATE_IP_IN_URL_PATTERN: re.Pattern[str] = re.compile(
    r"https?://(?:"
    r"127\.\d+\.\d+\.\d+"
    r"|10\.\d+\.\d+\.\d+"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|192\.168\.\d+\.\d+"
    r"|0\.0\.0\.0"
    r"|localhost"
    r"|::1"
    r")",
    re.IGNORECASE,
)

# Absolute Windows paths (flagged when the tool is not expected to accept them).
_WINDOWS_ABS_PATH_PATTERN: re.Pattern[str] = re.compile(
    r"^[A-Za-z]:\\|^\\\\[A-Za-z0-9]"
)

# Argument names that commonly receive file paths.
_FILE_PATH_ARG_NAMES: frozenset[str] = frozenset(
    {
        "path", "file", "filepath", "file_path", "filename", "file_name",
        "src", "dest", "destination", "source", "target", "dir", "directory",
        "output", "input", "log", "log_path", "config",
    }
)

# Argument names that commonly receive shell commands.
_COMMAND_ARG_NAMES: frozenset[str] = frozenset(
    {
        "command", "cmd", "shell", "exec", "execute", "run", "script",
        "args", "arguments", "argv",
    }
)

# Argument names that commonly receive URLs.
_URL_ARG_NAMES: frozenset[str] = frozenset(
    {
        "url", "uri", "endpoint", "href", "link", "webhook",
        "callback", "redirect", "base_url", "api_url",
    }
)


class ToolCallValidatorScanner(Scanner):
    """Validate tool call arguments for structural security issues.

    Runs exclusively during the TOOL_CALL phase.  The scanner operates on the
    JSON-serialised argument dictionary that the pipeline passes as *content*.

    Attributes
    ----------
    allow_private_urls:
        When ``True``, suppress SSRF findings for private/loopback URLs.
        Useful in development environments where agents legitimately call
        local services.  Defaults to ``False``.

    Example
    -------
    ::

        scanner = ToolCallValidatorScanner()
        report = await pipeline.scan_tool_call("read_file", {"path": "../../etc/passwd"})
    """

    name: str = "tool_call_validator"
    phases: list[ScanPhase] = [ScanPhase.TOOL_CALL]

    def __init__(self, allow_private_urls: bool = False) -> None:
        self.allow_private_urls = allow_private_urls

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        """Validate the JSON-encoded tool argument dictionary.

        Parameters
        ----------
        content:
            JSON string of the tool's argument dictionary.
        context:
            Current scan context.  :attr:`~ScanContext.tool_name` is
            available when set by the pipeline.

        Returns
        -------
        list[Finding]
            Structural security findings.
        """
        findings: list[Finding] = []

        # Deserialise the arguments.
        try:
            args: dict[str, object] = json.loads(content)
        except json.JSONDecodeError:
            findings.append(
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.MEDIUM,
                    category="tool_arg_parse_error",
                    message="Tool arguments could not be parsed as JSON.",
                    details={"raw_content_length": len(content)},
                )
            )
            return findings

        if not isinstance(args, dict):
            findings.append(
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.LOW,
                    category="tool_arg_format",
                    message="Tool arguments JSON root is not an object.",
                    details={"actual_type": type(args).__name__},
                )
            )
            return findings

        tool_name = context.tool_name or "unknown"
        findings.extend(self._validate_args(args, tool_name))
        return findings

    # ------------------------------------------------------------------
    # Internal validation helpers
    # ------------------------------------------------------------------

    def _validate_args(
        self, args: dict[str, object], tool_name: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for arg_name, arg_value in args.items():
            if not isinstance(arg_value, str):
                continue
            name_lower = arg_name.lower()

            if name_lower in _FILE_PATH_ARG_NAMES:
                findings.extend(
                    self._check_path_argument(tool_name, arg_name, arg_value)
                )

            if name_lower in _COMMAND_ARG_NAMES:
                findings.extend(
                    self._check_command_argument(tool_name, arg_name, arg_value)
                )

            if name_lower in _URL_ARG_NAMES:
                findings.extend(
                    self._check_url_argument(tool_name, arg_name, arg_value)
                )

            # Also scan all string values for path traversal regardless of
            # argument name — it may appear in unexpected fields.
            if name_lower not in _FILE_PATH_ARG_NAMES:
                traversal_findings = self._check_path_traversal_generic(
                    tool_name, arg_name, arg_value
                )
                findings.extend(traversal_findings)

        return findings

    def _check_path_argument(
        self, tool_name: str, arg_name: str, value: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        if _PATH_TRAVERSAL_PATTERN.search(value):
            findings.append(
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.CRITICAL,
                    category="path_traversal",
                    message=(
                        f"Tool '{tool_name}' argument '{arg_name}' contains a "
                        "path traversal sequence (e.g. '../') that may escape the "
                        "intended directory boundary."
                    ),
                    details={
                        "tool_name": tool_name,
                        "argument_name": arg_name,
                        "arg_length": len(value),
                    },
                )
            )

        if _WINDOWS_ABS_PATH_PATTERN.search(value):
            findings.append(
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.MEDIUM,
                    category="absolute_path",
                    message=(
                        f"Tool '{tool_name}' argument '{arg_name}' contains an "
                        "absolute Windows file path which may access arbitrary "
                        "filesystem locations."
                    ),
                    details={
                        "tool_name": tool_name,
                        "argument_name": arg_name,
                        "arg_length": len(value),
                    },
                )
            )

        if value.startswith("/") and len(value) > 1 and value[1] != "/":
            # UNIX absolute path — flag as informational.
            findings.append(
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.LOW,
                    category="absolute_path",
                    message=(
                        f"Tool '{tool_name}' argument '{arg_name}' is an absolute "
                        "UNIX path. Ensure the backing service enforces a chroot "
                        "or equivalent boundary."
                    ),
                    details={
                        "tool_name": tool_name,
                        "argument_name": arg_name,
                    },
                )
            )

        return findings

    def _check_command_argument(
        self, tool_name: str, arg_name: str, value: str
    ) -> list[Finding]:
        if not _SHELL_META_PATTERN.search(value):
            return []
        return [
            Finding(
                scanner_name=self.name,
                severity=FindingSeverity.CRITICAL,
                category="shell_injection",
                message=(
                    f"Tool '{tool_name}' argument '{arg_name}' contains shell "
                    "metacharacters (e.g. ';', '|', '`', '$'). This may enable "
                    "shell injection if the value is passed to a shell."
                ),
                details={
                    "tool_name": tool_name,
                    "argument_name": arg_name,
                },
            )
        ]

    def _check_url_argument(
        self, tool_name: str, arg_name: str, value: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        if _SUSPICIOUS_URL_SCHEME_PATTERN.search(value):
            findings.append(
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.HIGH,
                    category="ssrf_risk",
                    message=(
                        f"Tool '{tool_name}' argument '{arg_name}' uses a "
                        "potentially dangerous URL scheme that may enable SSRF "
                        "or local resource access."
                    ),
                    details={
                        "tool_name": tool_name,
                        "argument_name": arg_name,
                    },
                )
            )

        if not self.allow_private_urls and _PRIVATE_IP_IN_URL_PATTERN.search(value):
            findings.append(
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.HIGH,
                    category="ssrf_risk",
                    message=(
                        f"Tool '{tool_name}' argument '{arg_name}' targets a "
                        "private or loopback address, which may expose internal "
                        "services (SSRF)."
                    ),
                    details={
                        "tool_name": tool_name,
                        "argument_name": arg_name,
                    },
                )
            )

        return findings

    def _check_path_traversal_generic(
        self, tool_name: str, arg_name: str, value: str
    ) -> list[Finding]:
        """Check non-path arguments for traversal sequences (catch-all)."""
        if not _PATH_TRAVERSAL_PATTERN.search(value):
            return []
        return [
            Finding(
                scanner_name=self.name,
                severity=FindingSeverity.HIGH,
                category="path_traversal",
                message=(
                    f"Tool '{tool_name}' argument '{arg_name}' contains a path "
                    "traversal sequence outside of an expected file-path argument."
                ),
                details={
                    "tool_name": tool_name,
                    "argument_name": arg_name,
                },
            )
        ]
