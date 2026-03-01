/**
 * HTTP client for the AgentShield defense API.
 *
 * Delegates all HTTP transport to `@aumos/sdk-core` which provides
 * automatic retry with exponential back-off, timeout management via
 * `AbortSignal.timeout`, interceptor support, and a typed error hierarchy.
 *
 * The public-facing `ApiResult<T>` envelope is preserved for full
 * backward compatibility with existing callers.
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

import {
  createHttpClient,
  HttpError,
  NetworkError,
  TimeoutError,
  AumosError,
  type HttpClient,
} from "@aumos/sdk-core";

import type {
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
// Internal adapter — maps sdk-core ResponseData / errors to ApiResult
// ---------------------------------------------------------------------------

async function callApi<T>(
  operation: () => Promise<{ readonly data: T; readonly status: number }>,
): Promise<ApiResult<T>> {
  try {
    const response = await operation();
    return { ok: true, data: response.data };
  } catch (error: unknown) {
    if (error instanceof HttpError) {
      return {
        ok: false,
        error: { error: error.message, detail: String(error.body ?? "") },
        status: error.statusCode,
      };
    }
    if (error instanceof TimeoutError) {
      return {
        ok: false,
        error: { error: "Request timed out", detail: error.message },
        status: 0,
      };
    }
    if (error instanceof NetworkError) {
      return {
        ok: false,
        error: { error: "Network error", detail: error.message },
        status: 0,
      };
    }
    if (error instanceof AumosError) {
      return {
        ok: false,
        error: { error: error.code, detail: error.message },
        status: error.statusCode ?? 0,
      };
    }
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      error: { error: "Unexpected error", detail: message },
      status: 0,
    };
  }
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
  const http: HttpClient = createHttpClient({
    baseUrl: config.baseUrl,
    timeout: config.timeoutMs ?? 10_000,
    defaultHeaders: config.headers,
  });

  return {
    scanInput(request: ContentScanRequest): Promise<ApiResult<ScanResult>> {
      return callApi(() => http.post<ScanResult>("/scan/input", request));
    },

    scanOutput(request: ContentScanRequest): Promise<ApiResult<ScanResult>> {
      return callApi(() => http.post<ScanResult>("/scan/output", request));
    },

    getThreatReport(options: {
      agentId: string;
      windowStart?: string;
      windowEnd?: string;
    }): Promise<ApiResult<ThreatDetectionResult>> {
      const queryParams: Record<string, string> = { agent_id: options.agentId };
      if (options.windowStart !== undefined) queryParams["window_start"] = options.windowStart;
      if (options.windowEnd !== undefined) queryParams["window_end"] = options.windowEnd;
      return callApi(() =>
        http.get<ThreatDetectionResult>("/threats/report", { queryParams }),
      );
    },

    validateToolCall(
      request: ToolCallValidationRequest,
    ): Promise<ApiResult<ToolCallValidationResult>> {
      return callApi(() =>
        http.post<ToolCallValidationResult>("/validate/tool-call", request),
      );
    },
  };
}
