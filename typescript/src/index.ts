/**
 * @aumos/agentshield
 *
 * TypeScript client for the AumOS AgentShield defense layer.
 * Provides HTTP client, synchronous input scanner, and threat-detection type definitions.
 */

// Client and configuration
export type { AgentShieldClient, AgentShieldClientConfig, ContentScanRequest } from "./client.js";
export { createAgentShieldClient } from "./client.js";

// Core types
export type {
  ThreatLevel,
  DefenseLayer,
  ThreatFinding,
  ScanResult,
  ThreatDetectionResult,
  ToolCallValidationRequest,
  ToolCallValidationResult,
  ApiError,
  ApiResult,
} from "./types.js";

// Input scanner
export type { InputScanner, ScanOptions } from "./scanner.js";
export { createInputScanner } from "./scanner.js";
