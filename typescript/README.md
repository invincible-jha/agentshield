# @aumos/agentshield

TypeScript client for the [AumOS AgentShield](https://github.com/invincible-jha/agentshield)
defense layer. Scan agent inputs and outputs for prompt-injection, PII, and malicious
payloads — and validate tool calls before execution.

## Requirements

- Node.js 18+ (uses native Fetch API)
- TypeScript 5.3+ (strict mode)

## Installation

```bash
npm install @aumos/agentshield
```

## Usage

### HTTP client

```ts
import { createAgentShieldClient } from "@aumos/agentshield";

const client = createAgentShieldClient({
  baseUrl: "http://localhost:8091",
  timeoutMs: 10_000,
});

// Scan an incoming user message
const inputScan = await client.scanInput({
  agent_id: "my-agent",
  content: userMessage,
  session_id: "session-abc123",
});

if (inputScan.ok && inputScan.data.blocked) {
  console.warn("Input blocked. Findings:", inputScan.data.findings);
  // Do not forward the message to the LLM.
}

// Scan an LLM response before returning it to the user
const outputScan = await client.scanOutput({
  agent_id: "my-agent",
  content: llmResponse,
  session_id: "session-abc123",
});

// Validate a tool call before execution
const toolCheck = await client.validateToolCall({
  agent_id: "my-agent",
  tool_name: "web_search",
  tool_arguments: { query: userQuery },
  session_id: "session-abc123",
});

if (toolCheck.ok && !toolCheck.data.allowed) {
  console.warn("Tool call blocked:", toolCheck.data.block_reason);
}

// Retrieve aggregated threat report
const report = await client.getThreatReport({
  agentId: "my-agent",
  windowStart: "2026-02-01T00:00:00Z",
  windowEnd: "2026-02-28T23:59:59Z",
});
if (report.ok) {
  console.log("Blocked scans:", report.data.blocked_count);
}
```

### Local input scanner (no network required)

```ts
import { createInputScanner } from "@aumos/agentshield";

const scanner = createInputScanner();
const options = { agentId: "my-agent", sessionId: "session-abc123" };

// Check for prompt injection
const injectionFindings = scanner.checkPromptInjection(userInput, options);
if (injectionFindings.length > 0) {
  console.warn("Injection attempt detected:", injectionFindings[0].rule_id);
}

// Check for PII
const piiFindings = scanner.checkPII(llmOutput, options);

// Check for malicious payloads
const payloadFindings = scanner.checkMaliciousPayload(toolResult, options);

// Run all checks at once (sorted by severity)
const allFindings = scanner.scanAll(content, options);
for (const finding of allFindings) {
  console.log(`[${finding.level}] ${finding.rule_id}: ${finding.description}`);
}
```

## API reference

### `createAgentShieldClient(config)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `baseUrl` | `string` | required | AgentShield server URL |
| `timeoutMs` | `number` | `10000` | Request timeout (ms) |
| `headers` | `Record<string, string>` | `{}` | Extra HTTP headers |

#### Methods

| Method | Description |
|--------|-------------|
| `scanInput(request)` | Scan content arriving as agent input |
| `scanOutput(request)` | Scan content produced as agent output |
| `getThreatReport(options)` | Aggregated threat statistics for an agent |
| `validateToolCall(request)` | Validate a tool call before execution |

### `createInputScanner()`

| Method | Description |
|--------|-------------|
| `checkPromptInjection(text, options)` | Detect instruction-override patterns |
| `checkPII(text, options)` | Detect email, SSN, credit-card, phone, IP |
| `checkMaliciousPayload(text, options)` | Detect shell injection, SQL injection, path traversal |
| `scanAll(text, options)` | Run all checks, results sorted by severity |

### Threat levels

| Level | Description |
|-------|-------------|
| `critical` | Immediate block recommended (jailbreak, SSN, shell injection) |
| `high` | Block recommended (instruction override, SQL injection) |
| `medium` | Review recommended (role-switch, base64 obfuscation) |
| `low` | Log and monitor (phone numbers) |
| `info` | Informational only (IP addresses) |

## License

Apache-2.0. See [LICENSE](../../LICENSE) for details.
