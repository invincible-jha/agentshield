"""ToolCallChecker — validates tool/function calls before dispatch.

Enforces an allowlist of permitted tool names, validates argument shapes,
applies per-minute rate limiting using a sliding window, and enforces
chain depth limits to prevent runaway tool chains.

Runs exclusively during the TOOL_CALL phase.
"""
from __future__ import annotations

import collections
import json
import time

from agentshield.core.context import ScanContext
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase, Scanner

# Sentinel: no limit applied.
_UNLIMITED: int = 0


class ToolCallChecker(Scanner):
    """Validate tool invocations for allowlist compliance and rate limits.

    Attributes
    ----------
    allowed_tools:
        Set of permitted tool name strings.  An empty set means all tools
        are permitted (no allowlist enforcement).
    max_calls_per_minute:
        Maximum number of calls to any single tool per 60-second window.
        Set to 0 (default) to disable rate limiting.
    max_chain_depth:
        Maximum number of accumulated tool calls permitted within a single
        session context before a HIGH finding is raised.  Set to 0
        (default) to disable chain depth limiting.

    Example
    -------
    ::

        checker = ToolCallChecker(
            allowed_tools={"search_web", "read_file", "write_file"},
            max_calls_per_minute=10,
            max_chain_depth=5,
        )
        report = await pipeline.scan_tool_call("read_file", {"path": "data.csv"})
    """

    name: str = "tool_call_checker"
    phases: list[ScanPhase] = [ScanPhase.TOOL_CALL]

    def __init__(
        self,
        allowed_tools: set[str] | None = None,
        max_calls_per_minute: int = _UNLIMITED,
        max_chain_depth: int = _UNLIMITED,
    ) -> None:
        self.allowed_tools: set[str] = allowed_tools if allowed_tools is not None else set()
        self.max_calls_per_minute: int = max_calls_per_minute
        self.max_chain_depth: int = max_chain_depth

        # Sliding-window rate tracking: tool_name -> deque of UTC timestamps (float).
        self._call_timestamps: dict[str, collections.deque[float]] = (
            collections.defaultdict(collections.deque)
        )
        # Per-session chain depth counters: session_id -> total tool call count.
        self._session_chain_depth: dict[str, int] = collections.defaultdict(int)

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        """Validate the tool call represented by *context* and *content*.

        Parameters
        ----------
        content:
            JSON-serialised argument dictionary (provided by the pipeline).
        context:
            Current scan context.  :attr:`~ScanContext.tool_name` is the
            tool being invoked.

        Returns
        -------
        list[Finding]
            Findings for any policy violation detected.
        """
        findings: list[Finding] = []
        tool_name = context.tool_name or "unknown"
        session_id = context.session_id

        # 1. Allowlist check.
        if self.allowed_tools:
            findings.extend(self._check_allowlist(tool_name))

        # 2. Argument structure check (must be valid JSON object).
        arg_findings, args = self._check_args_structure(content, tool_name)
        findings.extend(arg_findings)
        if args is None:
            return findings

        # 3. Rate limit check.
        if self.max_calls_per_minute > _UNLIMITED:
            findings.extend(self._check_rate_limit(tool_name))

        # 4. Chain depth check.
        if self.max_chain_depth > _UNLIMITED:
            findings.extend(self._check_chain_depth(tool_name, session_id))

        return findings

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_allowlist(self, tool_name: str) -> list[Finding]:
        if tool_name in self.allowed_tools:
            return []
        return [
            Finding(
                scanner_name=self.name,
                severity=FindingSeverity.HIGH,
                category="tool_not_allowed",
                message=(
                    f"Tool '{tool_name}' is not in the configured allowlist. "
                    "Only explicitly permitted tools may be invoked."
                ),
                details={
                    "tool_name": tool_name,
                    "allowed_tools": sorted(self.allowed_tools),
                },
            )
        ]

    def _check_args_structure(
        self, content: str, tool_name: str
    ) -> tuple[list[Finding], dict[str, object] | None]:
        """Parse and structurally validate the JSON argument string.

        Returns
        -------
        tuple[list[Finding], dict[str, object] | None]
            Findings (may be empty) and the parsed argument dict if parsing
            succeeded, or ``None`` on failure.
        """
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            finding = Finding(
                scanner_name=self.name,
                severity=FindingSeverity.MEDIUM,
                category="tool_arg_parse_error",
                message=(
                    f"Arguments for tool '{tool_name}' could not be parsed as JSON. "
                    "Malformed arguments may indicate a pipeline error or injection attempt."
                ),
                details={"tool_name": tool_name, "content_length": len(content)},
            )
            return [finding], None

        if not isinstance(parsed, dict):
            finding = Finding(
                scanner_name=self.name,
                severity=FindingSeverity.LOW,
                category="tool_arg_format",
                message=(
                    f"Arguments for tool '{tool_name}' must be a JSON object, "
                    f"got {type(parsed).__name__!r}."
                ),
                details={"tool_name": tool_name, "actual_type": type(parsed).__name__},
            )
            return [finding], None

        return [], parsed

    def _check_rate_limit(self, tool_name: str) -> list[Finding]:
        now = time.monotonic()
        window_start = now - 60.0
        timestamps = self._call_timestamps[tool_name]

        # Evict timestamps outside the 60-second window.
        while timestamps and timestamps[0] < window_start:
            timestamps.popleft()

        # Record this call.
        timestamps.append(now)
        call_count = len(timestamps)

        if call_count > self.max_calls_per_minute:
            return [
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.HIGH,
                    category="rate_limit_exceeded",
                    message=(
                        f"Tool '{tool_name}' has been called {call_count} time(s) "
                        f"in the last 60 seconds, exceeding the limit of "
                        f"{self.max_calls_per_minute}."
                    ),
                    details={
                        "tool_name": tool_name,
                        "call_count_in_window": call_count,
                        "max_calls_per_minute": self.max_calls_per_minute,
                    },
                )
            ]
        return []

    def _check_chain_depth(self, tool_name: str, session_id: str) -> list[Finding]:
        self._session_chain_depth[session_id] += 1
        depth = self._session_chain_depth[session_id]

        if depth > self.max_chain_depth:
            return [
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.HIGH,
                    category="chain_depth_exceeded",
                    message=(
                        f"Tool chain depth {depth} exceeds the configured maximum of "
                        f"{self.max_chain_depth} for session '{session_id}'. "
                        "This may indicate a runaway agent loop."
                    ),
                    details={
                        "tool_name": tool_name,
                        "chain_depth": depth,
                        "max_chain_depth": self.max_chain_depth,
                        "session_id": session_id,
                    },
                )
            ]
        return []

    def reset_session(self, session_id: str) -> None:
        """Reset the chain depth counter for a session.

        Call this when a conversation or task completes so that depth
        counters do not accumulate across logically separate sessions.

        Parameters
        ----------
        session_id:
            The session identifier to reset.
        """
        self._session_chain_depth.pop(session_id, None)

    def reset_rate_counters(self) -> None:
        """Flush all rate-limit sliding windows.

        Useful in testing or when reusing the scanner across independent
        test runs.
        """
        self._call_timestamps.clear()
