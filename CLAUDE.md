# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Clawsec is a comprehensive security plugin for OpenClaw.ai that prevents AI agents from taking dangerous actions. It provides:
- Purchase protection with spend limits
- Website access control (allowlist/blocklist)
- Destructive command detection (shell, cloud, code)
- Secrets/PII detection
- Data exfiltration prevention
- Prompt injection scanning

Key features:
- **Hybrid Detection**: Fast pattern matching (~5ms) with optional LLM analysis for ambiguous cases
- **Multi-Channel Approval**: Native CLI, agent-confirm parameter, and webhook approval flows
- **Dual Distribution**: OpenClaw plugin OR standalone proxy mode

## Development Commands

### Build & Compile
```bash
npm run build         # Compile TypeScript to dist/
npm run dev           # Watch mode compilation
npm run clean         # Remove dist/ directory
```

### Testing
```bash
npm test              # Run all tests with Vitest
npm run test:watch    # Run tests in watch mode
npm run test:coverage # Generate coverage report

# Run specific test file
npx vitest run src/detectors/purchase/domain-detector.test.ts

# Run tests matching a pattern
npx vitest run --grep "purchase detection"
```

### Code Quality
```bash
npm run lint          # Run ESLint on src/
npm run lint:fix      # Auto-fix ESLint issues
```

### OpenClaw Plugin Testing
```bash
# Install plugin locally for testing
openclaw plugins install -l ./

# List installed plugins
openclaw plugins list

# Show plugin info
openclaw plugins info clawsec

# Run diagnostics
openclaw plugins doctor
```

### Configuration Testing
```bash
# Test your clawsec.yaml configuration
npx clawsec test

# Check plugin status
npx clawsec status

# View audit log
npx clawsec audit --since "1 hour ago"
```

## Architecture

### Plugin Lifecycle & Hook System

Clawsec integrates with OpenClaw through **three core hooks** that execute at different points:

1. **before-tool-call** (Priority: 100) - `src/hooks/before-tool-call/`
   - Intercepts tool calls BEFORE execution
   - Runs hybrid detection (pattern matching + optional LLM)
   - Returns: `{ allow: boolean, blockMessage?, modifiedInput?, metadata? }`
   - Primary enforcement point for all security rules

2. **before-agent-start** (Priority: 50) - `src/hooks/before-agent-start/`
   - Fires when agent session initializes
   - Injects security context into system prompt
   - Returns: `{ systemPromptAddition?, modifiedConfig? }`

3. **tool-result-persist** (Priority: 100) - `src/hooks/tool-result-persist/`
   - Filters tool outputs before persisting to conversation history
   - Scans for prompt injection, secrets leakage
   - Returns: `{ allow: boolean, filteredOutput?, redactions? }`

### Hybrid Detection Flow

```
Tool Call Request
    │
    ▼
before-tool-call hook
    │
    ├─► Agent-Confirm Present? ──► YES ──► Validate ID ──► ALLOW (skip detection)
    │                                         │
    │                                      INVALID
    │                                         │
    │                                      BLOCK
    │
    ├─► Pattern Matchers (5ms, parallel)
    │   ├─ Purchase Detector
    │   ├─ Website Detector
    │   ├─ Destructive Detector
    │   ├─ Secrets Detector
    │   └─ Exfiltration Detector
    │        │
    │        ▼
    │   Sort by Severity + Confidence
    │        │
    │        ▼
    │   Determine Action:
    │   - Critical + confidence >0.8 → BLOCK (no LLM)
    │   - Critical + confidence 0.5-0.8 → CONFIRM + trigger LLM
    │   - High + confidence >0.7 → CONFIRM (no LLM)
    │   - High + confidence 0.5-0.7 → WARN + trigger LLM
    │   - Medium + confidence 0.5-0.8 → WARN + trigger LLM
    │   - Low/None → ALLOW
    │        │
    │        ▼
    │   LLM Analysis? (only if confidence 0.5-0.8)
    │        │
    │        ├─► YES ──► LLM (~500ms) ──► Override action?
    │        │
    │        └─► NO ──► Use pattern-based action
    │                   │
    │                   ▼
    │          Action Executor (block/confirm/warn/log)
    │                   │
    │     ┌─────────────┼─────────────┬──────────┐
    │     │             │             │          │
    │   BLOCK       CONFIRM         WARN       ALLOW
    │   Reject      Create          Log        Proceed
    │              Approval ID      Warning
    │              (3 methods)
```

### Detector Architecture

All detectors in `src/detectors/` follow a consistent pattern:

```typescript
interface Detector {
  detect(context: DetectionContext): DetectionResult;
  detectAll(context: DetectionContext): DetectionResult[];
}

interface DetectionResult {
  category: ThreatCategory;
  severity: Severity;
  confidence: number;     // 0.0 - 1.0 (1.0 = definitive)
  reason: string;
  evidence?: string;
}
```

**Key detectors:**
- `purchase/` - Domain matching, form detection, spend tracking
- `website/` - URL pattern matching with glob support
- `destructive/` - Shell, cloud, and code pattern detection
- `secrets/` - API keys, tokens, PII using regex patterns
- `exfiltration/` - HTTP uploads, cloud transfers, network activity

### Configuration System

YAML configuration (`clawsec.yaml`) uses Zod schemas for validation:

1. **Loading Flow**: `src/config/loader.ts`
   - Loads YAML file
   - Validates against Zod schema (`src/config/schema.ts`)
   - Merges with defaults (`src/config/defaults.ts`)
   - Supports template inheritance via `extends: ["builtin/aws-security"]`

2. **Rule Structure**:
   ```yaml
   rules:
     <category>:
       enabled: true
       severity: critical|high|medium|low
       action: block|confirm|warn|log
       # category-specific options
   ```

3. **Built-in Templates**: `rules/builtin/`
   - 33 pre-built YAML templates
   - Cover cloud providers, compliance, development workflows
   - Can be extended or combined

### Template Inheritance System

**Overview**: Clawsec supports composable security configs through template inheritance, allowing users to build on battle-tested rules without copy-paste.

**Basic Usage**:
```yaml
# clawsec.yaml
version: "1.0"

extends:
  - builtin/aws-security
  - builtin/pii-protection

# Override specific settings
rules:
  purchase:
    spendLimits:
      perTransaction: 200
```

**How It Works** (`src/config/template-loader.ts`):
1. **Template Resolution**: Resolves `builtin/name` to `rules/builtin/name.yaml`
2. **Loading**: Loads each template YAML, strips metadata fields (name, description)
3. **Deep Merge**: Merges templates in order, then user config on top
4. **Array Handling**: Concatenates and deduplicates pattern arrays
5. **Validation**: Final merged config validated against schema

**Custom Patterns**:
All detector types support custom regex patterns that extend built-in detection:

```yaml
rules:
  destructive:
    shell:
      patterns:
        - "my-dangerous-cmd"
        - "risky-operation.*--force"
    cloud:
      patterns:
        - "custom-cloud-delete"

  secrets:
    patterns:
      - "MY_API_KEY_[A-Z0-9]{32}"
      - "SECRET_TOKEN_\\w+"
```

**Pattern Matching Flow**:
1. Detector tries built-in patterns first (high confidence, fast)
2. If no match, tries custom patterns (confidence ~0.85)
3. Custom patterns use same confidence-based decision tree
4. Invalid regex patterns are safely skipped

**Available Templates** (33 total in `rules/builtin/`):
- Cloud: `aws-security`, `azure-security`, `gcp-security`, `kubernetes`
- Data: `pii-protection`, `database-nosql`, `database-sql`, `cloud-storage`
- Dev: `git-safety`, `cicd-security`, `container-registry`
- Secrets: `ai-services`, `api-keys`, `authentication`, `crypto-wallets`
- Compliance: `gdpr-basic`, `hipaa-basic`
- Environments: `development`, `staging`, `production`, `minimal`

**Example Templates**:

`builtin/minimal` - Lightweight for trusted environments:
```yaml
rules:
  destructive:
    shell:
      patterns:
        - "rm -rf /"
        - ":(){:|:&};:"  # Fork bomb
  secrets:
    patterns:
      - "-----BEGIN.*PRIVATE KEY-----"
      - "sk_live_"  # Production Stripe
```

`builtin/aws-security` - AWS-specific protections:
```yaml
rules:
  destructive:
    cloud:
      patterns:
        - "aws.*terminate-instances"
        - "aws.*delete-.*"
        - "aws s3 rb.*--force"
```

**Multiple Template Merging**:
```yaml
extends:
  - builtin/aws-security
  - builtin/pii-protection
  - builtin/production

# Result: All patterns from all 3 templates + your overrides
# Arrays are concatenated and deduplicated
# Later templates override earlier ones for non-array fields
```

### Action System (`src/actions/`)

Each action determines how threats are handled:

- **block**: Immediate rejection, no approval possible
- **confirm**: Requires approval through one of three channels:
  1. Native: `/approve <request-id>` CLI command
  2. Agent-confirm: Retry with `_clawsec_confirm: true` parameter
  3. Webhook: External approval system
- **warn**: Allow but log warning
- **log**: Silent audit logging

### State Management

Plugin state is managed in `src/index.ts`:

```typescript
interface PluginState {
  initialized: boolean;
  api: OpenClawPluginAPI;      // OpenClaw's API reference
  config: ClawsecConfig;        // Loaded YAML config
  logger: Logger;
  handlers: {                   // Registered hook handlers
    beforeToolCall: string;
    beforeAgentStart: string;
    toolResultPersist: string;
  };
}
```

State lifecycle:
1. `register()` - Called when plugin loads
2. `activate(api)` - Receives OpenClaw API, loads config, registers hooks
3. `deactivate()` - Cleanup on plugin unload

## Hook Flow Details

This section explains how each hook works internally, including when pattern matching vs LLM analysis is used.

### Hook 1: before-agent-start (Session Initialization)

**Purpose:** Inject security awareness into the agent's system prompt at session start.

**When it runs:** Once per agent session, before the agent receives any user instructions.

**Flow:**
1. Agent session initializes
2. Hook checks which security rules are enabled in config
3. Builds a natural language security context message:
   - Lists active protection categories (purchase, destructive, secrets, etc.)
   - Explains approval methods if agent-confirm is enabled
   - Adds helpful reminders about working within security boundaries
4. Returns this message as `systemPromptAddition`
5. OpenClaw injects it into the agent's system prompt

**Detection Method:** None - purely configuration-driven prompt generation

**LLM Involved:** No

**Example output:**
```
[CLAWSEC SECURITY CONTEXT]
This session has security protections enabled:
- Purchase Protection: Transactions require approval
- Destructive Commands: Commands like rm -rf, DROP TABLE are monitored
- Secrets Detection: API keys and credentials in outputs are filtered

If an action is blocked, retry with _clawsec_confirm="<approval-id>"
```

---

### Hook 2: before-tool-call (Pre-Execution Security Gate)

**Purpose:** Block or require approval for dangerous actions before they execute.

**When it runs:** Before every tool call, after the agent decides to use a tool but before execution.

**The Two-Path Flow:**

#### Fast Path: Agent-Confirm Validation (Bypass Security)
1. Check if tool input contains confirmation parameter (default: `_clawsec_confirm`)
2. If present:
   - Extract the approval ID from parameter value
   - Look up approval in pending approvals store
   - Validate status: must be PENDING (not expired/used/denied)
3. If valid:
   - Mark approval as used
   - Strip confirmation parameter from tool input
   - Return `allow: true` with modified input
   - **Skip all detection** - tool executes immediately
4. If invalid:
   - Return `allow: false` with error explaining why
   - Tool is blocked

This fast path enables the **approval feedback loop**: agent tries dangerous action → blocked with ID → agent retries with confirmation → allowed.

#### Slow Path: Hybrid Detection (Full Security Analysis)
When no valid confirmation is present:

**Phase 1: Pattern Matching (≤5ms)**
- Run 5 detectors in parallel:
  - **Purchase Detector**: Regex for payment domains (stripe.com, checkout.*, etc.), form fields (amount, card_number), transaction amounts
  - **Website Detector**: Glob pattern matching against allowlist/blocklist (*.malware.com, phishing-*.com)
  - **Destructive Detector**: Regex for shell commands (rm -rf, DROP TABLE), cloud operations (aws delete, kubectl delete), code patterns (shutil.rmtree)
  - **Secrets Detector**: Regex for API keys (sk-*, AKIA*), tokens (Bearer, eyJ*), credentials (password=), PII (SSN, credit cards)
  - **Exfiltration Detector**: Regex for data transfer patterns (curl -X POST, wget --post, cloud uploads)
- Each detector returns: detected (yes/no), category, severity, confidence (0.0-1.0), reason
- Filter out non-detections
- Sort remaining by: severity (critical > high > medium > low), then confidence (highest first)

**Phase 2: Action Determination (Confidence-Based Decision Tree)**

The highest severity detection determines the action based on confidence:

**Critical Severity:**
- Confidence > 0.8: Action = BLOCK (high confidence, no LLM needed)
- Confidence 0.5-0.8: Action = CONFIRM + requiresLLM = true (ambiguous zone)
- Confidence < 0.5: Action = CONFIRM (low confidence, no LLM)

**High Severity:**
- Confidence > 0.7: Action = CONFIRM (confident enough, no LLM)
- Confidence 0.5-0.7: Action = WARN + requiresLLM = true (ambiguous zone)
- Confidence < 0.5: Action = WARN

**Medium Severity:**
- Confidence 0.5-0.8: Action = WARN + requiresLLM = true (ambiguous zone)
- Otherwise: Action = WARN

**Low Severity or No Detections:**
- Action = ALLOW

**Phase 3: LLM Analysis (~500ms, conditional)**

LLM is invoked ONLY when:
- `requiresLLM === true` (confidence in 0.5-0.8 ambiguous zone)
- AND LLM is enabled in config
- AND LLM client is available

If invoked:
1. Send to LLM: detection details (category, severity, reason) + tool context (name, input, URL)
2. LLM analyzes: "Is this genuinely dangerous? Could this be a false positive? What's the context?"
3. LLM returns: determination (threat/safe/uncertain) + confidence + suggested action
4. Adjust action based on LLM response:
   - If LLM says "safe" with confidence ≥ 0.7: Override to ALLOW
   - If LLM says "threat": Keep BLOCK/CONFIRM
   - If LLM says "uncertain": Keep original action

**Phase 4: Action Execution**
- **BLOCK**: Return `allow: false` with block message, no approval possible
- **CONFIRM**: Create pending approval with unique ID, return `allow: false` with approval instructions (includes ID and methods: native CLI, agent-confirm, webhook)
- **WARN**: Return `allow: true` with warning message, log to audit
- **ALLOW**: Return `allow: true`, proceed with execution

**Detection Method:** Programmatic regex patterns FIRST, LLM only for ambiguous cases

**LLM Involved:** Only when confidence is 0.5-0.8 (the "ambiguous zone")

---

### Hook 3: tool-result-persist (Post-Execution Output Filter)

**Purpose:** Prevent secrets and prompt injections from leaking in tool outputs.

**When it runs:** After a tool executes successfully, before the result is persisted to conversation history.

**Flow:**
1. Tool execution completes with output
2. Convert output to string for scanning (handles strings, arrays, objects recursively)

3. **Prompt Injection Scan** (if sanitization rule enabled):
   - Pattern match for injection attempts:
     - Instruction override: "ignore previous instructions", "new instructions", "system:"
     - System leak: "reveal your system prompt", "show your instructions"
     - Jailbreak: "DAN mode", "developer mode", "pretend you are"
     - Encoded payload: Base64, hex, unicode escapes
   - If detected with action = BLOCK: Reject entire output
   - If detected with redactMatches = true: Sanitize the injection patterns
   - Otherwise: Log warning and continue

4. **Secrets Detection** (if secrets rule enabled):
   - Run regex patterns on output:
     - API keys: OpenAI (sk-*, sk-ant-*), AWS (AKIA*), GitHub (gho_*, ghp_*), Stripe (sk_live_*, sk_test_*)
     - Tokens: JWT (eyJ*), Bearer tokens, session tokens
     - Credentials: password=, api_key=, secret_key=
     - PII: SSN (xxx-xx-xxxx), credit cards (Luhn validation), phone numbers
     - Private keys: -----BEGIN RSA PRIVATE KEY-----
   - Also run secrets detector for more accurate type classification

5. **Output Filtering**:
   - Walk through output structure recursively:
     - Strings: Replace each detected secret with `[REDACTED:type]`
     - Arrays: Filter each element
     - Objects: Filter each property value
     - Primitives: Pass through unchanged
   - Track all redactions made

6. Return result:
   - `allow: true` (always - filtering doesn't block)
   - `filteredOutput`: Sanitized version with secrets redacted
   - `redactions`: Array of {type, description} for each secret found

**Detection Method:** Purely programmatic regex pattern matching (no detector objects, no confidence scores)

**LLM Involved:** No - must be fast and deterministic for output filtering

---

### Pattern Matching vs LLM: The Hybrid Strategy

**When Pattern Matching is Used:**
- **Always** as the first line of defense
- Fast (≤5ms) regex and string matching
- Deterministic - same input always produces same result
- Used in all three hooks:
  - before-tool-call: Detector patterns for threat identification
  - tool-result-persist: Secret patterns for output filtering
  - before-agent-start: No patterns (config-driven only)

**When LLM Analysis is Used:**
- **Only** in before-tool-call hook
- **Only** when pattern confidence is ambiguous (0.5-0.8)
- **Purpose**: Reduce false positives by understanding context
- Slower (~500ms) but more intelligent
- Non-deterministic - can vary slightly between calls

**The Ambiguous Confidence Zone (0.5-0.8):**

This is where pattern matching is uncertain:
- **Confidence < 0.5**: Pattern barely matched, probably safe → skip LLM
- **Confidence 0.5-0.8**: Pattern matched but context unclear → invoke LLM
- **Confidence > 0.8**: Pattern strongly matched, definitely dangerous → skip LLM

**Example Scenarios:**

| Scenario | Pattern Confidence | LLM Used? | Outcome |
|----------|-------------------|-----------|---------|
| `rm -rf /tmp/test-data` in test cleanup | 0.6 (ambiguous) | Yes | LLM sees test context → ALLOW |
| `rm -rf /var/lib/postgres` | 0.95 (definitive) | No | Pattern confidence high → BLOCK |
| `example_api_key = "sk-..."` in docs | 0.6 (ambiguous) | Yes | LLM sees example context → ALLOW |
| Actual API key in production config | 0.95 (definitive) | No | Pattern confidence high → BLOCK |
| Purchase on `checkout.stripe.com` | 0.85 (high) | No | Clear payment domain → CONFIRM |
| Request to `stripe.com/docs` | 0.55 (ambiguous) | Yes | LLM sees docs URL → ALLOW |

**Design Rationale:**
- **Speed**: Pattern matching handles 80% of cases instantly
- **Accuracy**: LLM handles the 20% where context matters
- **Cost**: Only pay LLM latency/cost for genuinely uncertain cases
- **Reliability**: System works even if LLM is unavailable (falls back to patterns)

## Code Patterns

### Adding a New Detector

1. Create detector directory: `src/detectors/<name>/`
2. Implement detector interface with `detect()` and `detectAll()` methods
3. Return `DetectionResult` with confidence score:
   - `1.0` = Definitive match (skip LLM)
   - `0.5-0.9` = Ambiguous (trigger LLM if enabled)
3. Add tests: `<name>.test.ts`
4. Export from `src/detectors/index.ts`
5. Integrate in `src/engine/analyzer.ts`

### Testing Patterns

Tests use Vitest with co-located test files (`*.test.ts`):

```typescript
import { describe, it, expect } from 'vitest';

describe('MyDetector', () => {
  it('should detect threat pattern', () => {
    const detector = createMyDetector(config);
    const result = detector.detect(context);
    expect(result.confidence).toBe(1.0);
    expect(result.category).toBe('my-category');
  });
});
```

Key testing principles:
- Test definitive matches (confidence = 1.0)
- Test ambiguous cases (0.5 < confidence < 1.0)
- Test false negatives (should NOT match)
- Mock LLM client for LLM-dependent tests

### Pattern Matching

Detectors use regex for pattern matching with escape utilities:

```typescript
// For glob patterns (website, purchase domains)
import { globToRegex } from '../utils/glob';

// For exact string matching with wildcards
const pattern = globToRegex('*.amazon.com');
const isMatch = pattern.test(url);
```

## Important Files

- `src/index.ts` - Plugin entry point, hook registration, state management
- `src/hooks/before-tool-call/handler.ts` - Primary detection & enforcement logic
- `src/engine/analyzer.ts` - Hybrid detection orchestration (pattern + LLM)
- `src/config/schema.ts` - Zod schemas defining valid configuration
- `openclaw.plugin.json` - Plugin metadata for OpenClaw registry
- `clawsec.yaml.example` - Example configuration with all options

## Configuration Notes

### Environment Variables

OpenClaw plugin configuration can use environment variables:
```bash
export OPENCLAW_PLUGIN_CLAWSEC_ENABLED=true
export OPENCLAW_PLUGIN_CLAWSEC_CONFIG_PATH="./clawsec.yaml"
```

Notification webhooks:
```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
export TELEGRAM_BOT_TOKEN="123:ABC..."
```

### Testing Locally

To test the plugin during development:

1. Build: `npm run build`
2. Install locally: `openclaw plugins install -l ./`
3. Create test config: Copy `clawsec.yaml.example` to `clawsec.yaml`
4. Run OpenClaw with plugin enabled
5. Check logs: Plugin logs to OpenClaw's log output

## Debugging

### Log Levels

Set `logLevel` in config or via environment:
```yaml
global:
  logLevel: debug  # debug, info, warn, error
```

### Audit Trail

View security events:
```bash
npx clawsec audit --since "1 hour ago"
npx clawsec audit --severity critical
npx clawsec audit --category destructive
```

### Testing Detection

Use `npx clawsec test` to validate configuration without running agent:
- Tests all enabled detectors
- Shows which patterns would trigger
- Validates YAML syntax and schema

## Distribution

Clawsec has **dual distribution**:

1. **OpenClaw Plugin** (primary):
   - Installed via: `openclaw plugins install clawsec`
   - Uses OpenClaw's hook system
   - Configuration via `clawsec.yaml`

2. **Standalone Proxy** (alternative):
   - For non-OpenClaw environments
   - Run: `npx clawsec serve --port 8080`
   - Proxies agent requests through security layer

The same codebase supports both modes - plugin hooks are primary, proxy wraps them in HTTP server.
