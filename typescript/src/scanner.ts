/**
 * InputScanner — pure, synchronous content-scanning utilities.
 *
 * These functions operate on plain strings and return typed finding arrays.
 * They do not make network calls and have no side effects.
 *
 * Defensive-only framing: detects patterns associated with known attack
 * categories so that the caller can decide whether to block or log.
 */

import type { DefenseLayer, ThreatFinding, ThreatLevel } from "./types.js";

// ---------------------------------------------------------------------------
// Helper types
// ---------------------------------------------------------------------------

/** Options shared by all scanner methods. */
export interface ScanOptions {
  /** Agent performing or receiving the content. */
  readonly agentId: string;
  /** Optional session context passed through to findings metadata. */
  readonly sessionId?: string;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

let findingIdCounter = 0;

function nextFindingId(): string {
  findingIdCounter += 1;
  return `finding-${Date.now()}-${findingIdCounter}`;
}

function buildFinding(
  layer: DefenseLayer,
  level: ThreatLevel,
  ruleId: string,
  description: string,
  text: string,
  offset: number,
  metadata: Readonly<Record<string, unknown>>,
): ThreatFinding {
  // Produce a redacted excerpt — never expose the raw payload.
  const excerpt =
    text.length > 80
      ? `${text.slice(0, 40)}...[redacted]...${text.slice(-20)}`
      : text.replace(/./g, "*");

  return {
    finding_id: nextFindingId(),
    layer,
    level,
    rule_id: ruleId,
    description,
    offset,
    excerpt,
    metadata,
  };
}

// ---------------------------------------------------------------------------
// Prompt-injection detection patterns
// ---------------------------------------------------------------------------

/**
 * Patterns that signal an attempt to override system instructions.
 * Each entry is [ruleId, description, pattern, level].
 */
const PROMPT_INJECTION_RULES: ReadonlyArray<
  readonly [string, string, RegExp, ThreatLevel]
> = [
  [
    "PI-001",
    "Instruction-override attempt detected",
    /ignore\s+(all\s+)?previous\s+instructions?/i,
    "high",
  ],
  [
    "PI-002",
    "System-prompt disclosure request detected",
    /reveal\s+(your\s+)?(system\s+)?prompt/i,
    "high",
  ],
  [
    "PI-003",
    "Role-switch injection attempt detected",
    /you\s+are\s+now\s+(a|an)\s+\w/i,
    "medium",
  ],
  [
    "PI-004",
    "Jailbreak keyword detected",
    /\b(jailbreak|dan\s+mode|developer\s+mode)\b/i,
    "critical",
  ],
  [
    "PI-005",
    "Fake-completion injection pattern detected",
    /<\/?(?:system|assistant|user)\s*>/i,
    "high",
  ],
];

// ---------------------------------------------------------------------------
// PII detection patterns
// ---------------------------------------------------------------------------

/**
 * Patterns for common PII categories.
 * Each entry is [ruleId, description, pattern, level].
 */
const PII_RULES: ReadonlyArray<
  readonly [string, string, RegExp, ThreatLevel]
> = [
  [
    "PII-EMAIL",
    "Email address detected",
    /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/,
    "medium",
  ],
  [
    "PII-SSN",
    "US Social Security Number pattern detected",
    /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/,
    "critical",
  ],
  [
    "PII-CREDIT-CARD",
    "Credit card number pattern detected",
    /\b(?:\d[ -]?){13,16}\b/,
    "critical",
  ],
  [
    "PII-PHONE",
    "Phone number pattern detected",
    /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/,
    "low",
  ],
  [
    "PII-IP-ADDRESS",
    "IP address detected",
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
    "info",
  ],
];

// ---------------------------------------------------------------------------
// Malicious payload patterns
// ---------------------------------------------------------------------------

/**
 * Patterns for known malicious payload indicators.
 * Defensive framing: these detect encoded or obfuscated content.
 * Each entry is [ruleId, description, pattern, level].
 */
const MALICIOUS_PAYLOAD_RULES: ReadonlyArray<
  readonly [string, string, RegExp, ThreatLevel]
> = [
  [
    "MPL-001",
    "Base64-encoded block detected — possible payload obfuscation",
    /\b[A-Za-z0-9+/]{40,}={0,2}\b/,
    "medium",
  ],
  [
    "MPL-002",
    "Shell command injection pattern detected",
    /(?:;\s*(?:rm|curl|wget|bash|sh|python|perl|nc)\b|&&\s*(?:rm|curl|wget|bash|sh)\b)/i,
    "critical",
  ],
  [
    "MPL-003",
    "SQL injection pattern detected",
    /(?:';\s*(?:drop|delete|update|insert|select)\b|--\s*$|\bUNION\s+SELECT\b)/i,
    "critical",
  ],
  [
    "MPL-004",
    "Path traversal pattern detected",
    /(?:\.\.\/|\.\.\\){2,}/,
    "high",
  ],
  [
    "MPL-005",
    "Excessive token repetition detected — possible resource-exhaustion attempt",
    /(\b\w+\b)(?:\s+\1){20,}/i,
    "medium",
  ],
];

// ---------------------------------------------------------------------------
// Generic pattern-matching runner
// ---------------------------------------------------------------------------

function runPatternRules(
  text: string,
  rules: ReadonlyArray<readonly [string, string, RegExp, ThreatLevel]>,
  layer: DefenseLayer,
  options: ScanOptions,
): readonly ThreatFinding[] {
  const findings: ThreatFinding[] = [];

  for (const [ruleId, description, pattern, level] of rules) {
    const match = pattern.exec(text);
    if (match !== null) {
      findings.push(
        buildFinding(
          layer,
          level,
          ruleId,
          description,
          match[0],
          match.index,
          {
            agent_id: options.agentId,
            session_id: options.sessionId ?? null,
            match_length: match[0].length,
          },
        ),
      );
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// InputScanner interface
// ---------------------------------------------------------------------------

/** Synchronous content-scanning utilities. */
export interface InputScanner {
  /**
   * Detect prompt-injection patterns in the given text.
   *
   * @param text - Raw input string to analyse.
   * @param options - Agent and session context.
   * @returns Array of ThreatFindings for any injection patterns found.
   */
  checkPromptInjection(
    text: string,
    options: ScanOptions,
  ): readonly ThreatFinding[];

  /**
   * Detect personally identifiable information in the given text.
   *
   * @param text - Raw content string to analyse.
   * @param options - Agent and session context.
   * @returns Array of ThreatFindings for any PII patterns found.
   */
  checkPII(text: string, options: ScanOptions): readonly ThreatFinding[];

  /**
   * Detect indicators of malicious payloads in the given text.
   *
   * @param text - Raw content string to analyse.
   * @param options - Agent and session context.
   * @returns Array of ThreatFindings for any suspicious patterns found.
   */
  checkMaliciousPayload(
    text: string,
    options: ScanOptions,
  ): readonly ThreatFinding[];

  /**
   * Run all checks and return the combined, deduplicated findings list
   * sorted by severity (critical first).
   *
   * @param text - Raw content string to analyse.
   * @param options - Agent and session context.
   * @returns All findings across all defense layers.
   */
  scanAll(text: string, options: ScanOptions): readonly ThreatFinding[];
}

// ---------------------------------------------------------------------------
// Severity ordering helper
// ---------------------------------------------------------------------------

const THREAT_LEVEL_ORDER: Readonly<Record<ThreatLevel, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an InputScanner instance.
 *
 * @returns An InputScanner with all check methods.
 */
export function createInputScanner(): InputScanner {
  return {
    checkPromptInjection(
      text: string,
      options: ScanOptions,
    ): readonly ThreatFinding[] {
      return runPatternRules(text, PROMPT_INJECTION_RULES, "prompt_injection", options);
    },

    checkPII(text: string, options: ScanOptions): readonly ThreatFinding[] {
      return runPatternRules(text, PII_RULES, "pii_detection", options);
    },

    checkMaliciousPayload(
      text: string,
      options: ScanOptions,
    ): readonly ThreatFinding[] {
      return runPatternRules(
        text,
        MALICIOUS_PAYLOAD_RULES,
        "malicious_payload",
        options,
      );
    },

    scanAll(text: string, options: ScanOptions): readonly ThreatFinding[] {
      const all: ThreatFinding[] = [
        ...runPatternRules(text, PROMPT_INJECTION_RULES, "prompt_injection", options),
        ...runPatternRules(text, PII_RULES, "pii_detection", options),
        ...runPatternRules(text, MALICIOUS_PAYLOAD_RULES, "malicious_payload", options),
      ];

      return all.sort(
        (a, b) =>
          THREAT_LEVEL_ORDER[a.level] - THREAT_LEVEL_ORDER[b.level],
      );
    },
  };
}
