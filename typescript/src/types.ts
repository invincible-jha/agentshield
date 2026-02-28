/**
 * TypeScript interfaces for the AgentShield defense layer.
 *
 * Mirrors the Pydantic models defined in:
 *   agentshield.schemas.threats
 *   agentshield.schemas.scan
 *   agentshield.schemas.defense
 *
 * All interfaces use readonly fields to match Python's frozen Pydantic models.
 */

// ---------------------------------------------------------------------------
// Threat level classification
// ---------------------------------------------------------------------------

/**
 * Severity level of a detected threat.
 * Maps to ThreatLevel enum in Python.
 */
export type ThreatLevel = "critical" | "high" | "medium" | "low" | "info";

// ---------------------------------------------------------------------------
// Defense layers
// ---------------------------------------------------------------------------

/**
 * The layer of the defense pipeline that produced a finding.
 * Maps to DefenseLayer enum in Python.
 */
export type DefenseLayer =
  | "input_validation"
  | "output_validation"
  | "tool_call_validation"
  | "pii_detection"
  | "prompt_injection"
  | "malicious_payload";

// ---------------------------------------------------------------------------
// Individual threat finding
// ---------------------------------------------------------------------------

/** A single threat or anomaly detected by one defense rule. */
export interface ThreatFinding {
  /** Unique identifier for this finding. */
  readonly finding_id: string;
  /** Defense layer that produced this finding. */
  readonly layer: DefenseLayer;
  /** Threat severity. */
  readonly level: ThreatLevel;
  /** Short rule identifier (e.g. "PI-001", "PII-EMAIL"). */
  readonly rule_id: string;
  /** Human-readable description of the finding. */
  readonly description: string;
  /** Character offset in the scanned content where the issue begins (-1 if not applicable). */
  readonly offset: number;
  /** Redacted excerpt of the offending content (never the raw payload). */
  readonly excerpt: string;
  /** Arbitrary metadata from the rule implementation. */
  readonly metadata: Readonly<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// Scan result
// ---------------------------------------------------------------------------

/** Result of scanning a single piece of content through the defense pipeline. */
export interface ScanResult {
  /** Unique identifier for this scan operation. */
  readonly scan_id: string;
  /** ISO-8601 UTC timestamp of when the scan completed. */
  readonly scanned_at: string;
  /** Agent that triggered the scan. */
  readonly agent_id: string;
  /** Whether any finding at level "high" or "critical" was detected. */
  readonly blocked: boolean;
  /** All findings produced by the scan, ordered by severity descending. */
  readonly findings: readonly ThreatFinding[];
  /** Highest threat level across all findings ("info" when no threats found). */
  readonly max_level: ThreatLevel;
  /** Total scan duration in milliseconds. */
  readonly duration_ms: number;
}

// ---------------------------------------------------------------------------
// Threat detection result (aggregate over a time window)
// ---------------------------------------------------------------------------

/** Aggregated threat statistics for a single agent over a time window. */
export interface ThreatDetectionResult {
  /** Agent being reported on. */
  readonly agent_id: string;
  /** ISO-8601 UTC start of the reporting window. */
  readonly window_start: string;
  /** ISO-8601 UTC end of the reporting window. */
  readonly window_end: string;
  /** Total number of scans in this window. */
  readonly total_scans: number;
  /** Number of scans that triggered a block action. */
  readonly blocked_count: number;
  /** Breakdown of finding counts by threat level. */
  readonly findings_by_level: Readonly<Record<ThreatLevel, number>>;
  /** Breakdown of finding counts by defense layer. */
  readonly findings_by_layer: Readonly<Record<DefenseLayer, number>>;
  /** Most frequently triggered rule_ids in this window. */
  readonly top_rules: readonly string[];
}

// ---------------------------------------------------------------------------
// Tool-call validation
// ---------------------------------------------------------------------------

/** Request to validate a proposed tool call before execution. */
export interface ToolCallValidationRequest {
  /** Agent submitting the tool call. */
  readonly agent_id: string;
  /** Name of the tool being called. */
  readonly tool_name: string;
  /** Arguments that will be passed to the tool. */
  readonly tool_arguments: Readonly<Record<string, unknown>>;
  /** Optional session context for policy decisions. */
  readonly session_id?: string;
}

/** Outcome of a tool-call validation check. */
export interface ToolCallValidationResult {
  /** Whether the tool call is permitted to proceed. */
  readonly allowed: boolean;
  /** Reason the call was blocked, or null if allowed. */
  readonly block_reason: string | null;
  /** Findings raised during validation. */
  readonly findings: readonly ThreatFinding[];
  /** Validation duration in milliseconds. */
  readonly duration_ms: number;
}

// ---------------------------------------------------------------------------
// API result wrapper (shared pattern)
// ---------------------------------------------------------------------------

/** Standard error payload returned by the AgentShield API. */
export interface ApiError {
  readonly error: string;
  readonly detail: string;
}

/** Result type for all client operations. */
export type ApiResult<T> =
  | { readonly ok: true; readonly data: T }
  | { readonly ok: false; readonly error: ApiError; readonly status: number };
