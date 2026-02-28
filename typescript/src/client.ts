/**
 * HTTP client for the AgentShield defense API.
 *
 * Uses the Fetch API (available natively in Node 18+, browsers, and Deno).
 * No external dependencies required.
 *
 * @example
 * ```ts
 * import { createAgentShieldClient } from "@aumos/agentshield";
 *
 * const client = createAgentShieldClient({ baseUrl: "http://localhost:8091" });
 *
 * const result = await client.scanInput({
 *   agent_id: "my-agent",
 *   content: userMessage,
 *   session_id: "session-abc",
 * });
 *
 * if (result.ok && result.data.blocked) {
 *   console.warn("Input blocked:", result.data.findings);
 * }
 * ```
 */

import type {
  ApiError,
  ApiResult,
  ScanResult,
  ThreatDetectionResult,
  ToolCallValidationRequest,
  ToolCallValidationResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// Client configuration
// ---------------------------------------------------------------------------

/** Configuration options for the AgentShieldClient. */
export interface AgentShieldClientConfig {
  /** Base URL of the AgentShield server (e.g. "http://localhost:8091"). */
  readonly baseUrl: string;
  /** Optional request timeout in milliseconds (default: 10000). */
  readonly timeoutMs?: number;
  /** Optional extra HTTP headers sent with every request. */
  readonly headers?: Readonly<Record<string, string>>;
}

// ---------------------------------------------------------------------------
// Scan request types
// ---------------------------------------------------------------------------

/** Request body for input or output scanning. */
export interface ContentScanRequest {
  /** Agent that produced or received the content. */
  readonly agent_id: string;
  /** Raw content string to scan. */
  readonly content: string;
  /** Optional session context. */
  readonly session_id?: string;
  /** Arbitrary metadata forwarded to rule implementations. */
  readonly metadata?: Readonly<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function fetchJson<T>(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<ApiResult<T>> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    clearTimeout(timeoutId);

    const body = await response.json() as unknown;

    if (!response.ok) {
      const errorBody = body as Partial<ApiError>;
      return {
        ok: false,
        error: {
          error: errorBody.error ?? "Unknown error",
          detail: errorBody.detail ?? "",
        },
        status: response.status,
      };
    }

    return { ok: true, data: body as T };
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      error: { error: "Network error", detail: message },
      status: 0,
    };
  }
}

function buildHeaders(
  extraHeaders: Readonly<Record<string, string>> | undefined,
): Record<string, string> {
  return {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...extraHeaders,
  };
}

// ---------------------------------------------------------------------------
// Client interface
// ---------------------------------------------------------------------------

/** Typed HTTP client for the AgentShield defense server. */
export interface AgentShieldClient {
  /**
   * Scan content arriving as agent input (e.g. user messages, tool results).
   *
   * @param request - Content and context to scan.
   * @returns ScanResult with findings and a blocked flag.
   */
  scanInput(request: ContentScanRequest): Promise<ApiResult<ScanResult>>;

  /**
   * Scan content produced as agent output (e.g. LLM responses, tool invocations).
   *
   * @param request - Content and context to scan.
   * @returns ScanResult with findings and a blocked flag.
   */
  scanOutput(request: ContentScanRequest): Promise<ApiResult<ScanResult>>;

  /**
   * Retrieve aggregated threat detection statistics for an agent.
   *
   * @param options - Agent and optional time-window filters.
   * @returns ThreatDetectionResult summarising threat activity.
   */
  getThreatReport(options: {
    agentId: string;
    windowStart?: string;
    windowEnd?: string;
  }): Promise<ApiResult<ThreatDetectionResult>>;

  /**
   * Validate a proposed tool call before it is executed.
   *
   * @param request - Tool name, arguments, and calling-agent context.
   * @returns ToolCallValidationResult indicating whether execution is permitted.
   */
  validateToolCall(
    request: ToolCallValidationRequest,
  ): Promise<ApiResult<ToolCallValidationResult>>;
}

// ---------------------------------------------------------------------------
// Client factory
// ---------------------------------------------------------------------------

/**
 * Create a typed HTTP client for the AgentShield server.
 *
 * @param config - Client configuration including base URL.
 * @returns An AgentShieldClient instance.
 */
export function createAgentShieldClient(
  config: AgentShieldClientConfig,
): AgentShieldClient {
  const { baseUrl, timeoutMs = 10_000, headers: extraHeaders } = config;
  const baseHeaders = buildHeaders(extraHeaders);

  return {
    async scanInput(
      request: ContentScanRequest,
    ): Promise<ApiResult<ScanResult>> {
      return fetchJson<ScanResult>(
        `${baseUrl}/scan/input`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify(request),
        },
        timeoutMs,
      );
    },

    async scanOutput(
      request: ContentScanRequest,
    ): Promise<ApiResult<ScanResult>> {
      return fetchJson<ScanResult>(
        `${baseUrl}/scan/output`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify(request),
        },
        timeoutMs,
      );
    },

    async getThreatReport(options: {
      agentId: string;
      windowStart?: string;
      windowEnd?: string;
    }): Promise<ApiResult<ThreatDetectionResult>> {
      const params = new URLSearchParams({ agent_id: options.agentId });
      if (options.windowStart !== undefined) {
        params.set("window_start", options.windowStart);
      }
      if (options.windowEnd !== undefined) {
        params.set("window_end", options.windowEnd);
      }
      return fetchJson<ThreatDetectionResult>(
        `${baseUrl}/threats/report?${params.toString()}`,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async validateToolCall(
      request: ToolCallValidationRequest,
    ): Promise<ApiResult<ToolCallValidationResult>> {
      return fetchJson<ToolCallValidationResult>(
        `${baseUrl}/validate/tool-call`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify(request),
        },
        timeoutMs,
      );
    },
  };
}

/** Re-export request/response types for convenience. */
export type {
  ContentScanRequest,
  ScanResult,
  ThreatDetectionResult,
  ToolCallValidationRequest,
  ToolCallValidationResult,
};
