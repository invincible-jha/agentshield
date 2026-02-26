"""Unit tests for agentshield.core.context.ScanContext."""
from __future__ import annotations

import uuid

import pytest

from agentshield.core.context import ScanContext
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase


def _make_finding(severity: FindingSeverity = FindingSeverity.MEDIUM) -> Finding:
    return Finding(
        scanner_name="test",
        severity=severity,
        category="test_category",
        message="Test finding",
    )


class TestScanContextDefaults:
    def test_phase_required(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        assert context.phase == ScanPhase.INPUT

    def test_agent_id_defaults_to_default(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        assert context.agent_id == "default"

    def test_session_id_generated_as_uuid(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        parsed = uuid.UUID(context.session_id)
        assert str(parsed) == context.session_id

    def test_session_ids_unique_across_instances(self) -> None:
        ctx_a = ScanContext(phase=ScanPhase.INPUT)
        ctx_b = ScanContext(phase=ScanPhase.INPUT)
        assert ctx_a.session_id != ctx_b.session_id

    def test_tool_name_defaults_to_none(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        assert context.tool_name is None

    def test_metadata_defaults_to_empty_dict(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        assert context.metadata == {}

    def test_accumulated_findings_defaults_to_empty_list(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        assert context.accumulated_findings == []


class TestScanContextCustomValues:
    def test_agent_id_custom(self) -> None:
        context = ScanContext(phase=ScanPhase.OUTPUT, agent_id="order-agent-v2")
        assert context.agent_id == "order-agent-v2"

    def test_session_id_custom(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT, session_id="user-abc123")
        assert context.session_id == "user-abc123"

    def test_tool_name_set(self) -> None:
        context = ScanContext(phase=ScanPhase.TOOL_CALL, tool_name="read_file")
        assert context.tool_name == "read_file"

    def test_metadata_custom(self) -> None:
        meta: dict[str, object] = {"environment": "production", "user_role": "admin"}
        context = ScanContext(phase=ScanPhase.INPUT, metadata=meta)
        assert context.metadata["environment"] == "production"


class TestAddFindings:
    def test_add_single_finding(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        finding = _make_finding()
        context.add_findings([finding])
        assert len(context.accumulated_findings) == 1
        assert context.accumulated_findings[0] is finding

    def test_add_multiple_findings_in_one_call(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        findings = [_make_finding(), _make_finding(FindingSeverity.HIGH)]
        context.add_findings(findings)
        assert len(context.accumulated_findings) == 2

    def test_add_findings_accumulates_across_calls(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        context.add_findings([_make_finding()])
        context.add_findings([_make_finding(FindingSeverity.CRITICAL)])
        assert len(context.accumulated_findings) == 2

    def test_add_empty_list_does_not_change_count(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        context.add_findings([])
        assert len(context.accumulated_findings) == 0


class TestForPhase:
    def test_returns_new_context_object(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        new_context = context.for_phase(ScanPhase.OUTPUT)
        assert new_context is not context

    def test_new_context_has_updated_phase(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        new_context = context.for_phase(ScanPhase.OUTPUT)
        assert new_context.phase == ScanPhase.OUTPUT

    def test_agent_id_copied(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT, agent_id="my-agent")
        new_context = context.for_phase(ScanPhase.OUTPUT)
        assert new_context.agent_id == "my-agent"

    def test_session_id_copied(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT, session_id="session-xyz")
        new_context = context.for_phase(ScanPhase.OUTPUT)
        assert new_context.session_id == "session-xyz"

    def test_accumulated_findings_shared(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        new_context = context.for_phase(ScanPhase.OUTPUT)
        # They share the same list object.
        new_context.add_findings([_make_finding()])
        assert len(context.accumulated_findings) == 1

    def test_metadata_shallow_copy(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT, metadata={"key": "value"})
        new_context = context.for_phase(ScanPhase.OUTPUT)
        # Modifying the copy should not affect the original.
        new_context.metadata["key2"] = "new"
        assert "key2" not in context.metadata


class TestCloneForTool:
    def test_returns_new_context(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        tool_context = context.clone_for_tool("read_file")
        assert tool_context is not context

    def test_phase_set_to_tool_call(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        tool_context = context.clone_for_tool("read_file")
        assert tool_context.phase == ScanPhase.TOOL_CALL

    def test_tool_name_set(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        tool_context = context.clone_for_tool("write_file")
        assert tool_context.tool_name == "write_file"

    def test_agent_id_copied(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT, agent_id="agent-007")
        tool_context = context.clone_for_tool("search_web")
        assert tool_context.agent_id == "agent-007"

    def test_accumulated_findings_shared(self) -> None:
        context = ScanContext(phase=ScanPhase.INPUT)
        tool_context = context.clone_for_tool("search_web")
        tool_context.add_findings([_make_finding()])
        assert len(context.accumulated_findings) == 1
