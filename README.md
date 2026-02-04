# Clawsec

> Security plugin for OpenClaw.ai that prevents AI agents from taking dangerous actions.

[![Tests](https://img.shields.io/badge/tests-1258%20passing-brightgreen)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

## Overview

Clawsec is a comprehensive security plugin that protects against:

- **Purchase Protection** - Blocks unauthorized purchases with spend limits
- **Website Control** - Allowlist/blocklist for URL access
- **Destructive Commands** - Detects dangerous shell, cloud, and code patterns
- **Secrets/PII Detection** - Finds API keys, tokens, and personal data
- **Data Exfiltration** - Prevents unauthorized data transfer
- **Prompt Injection** - Scans tool outputs for injection attempts

## Features

- **Hybrid Detection** - Fast pattern matching (~5ms) with optional LLM analysis
- **Multi-Channel Approval** - Native, agent-confirm, and webhook options
- **Real-time Notifications** - Slack, Discord, and Telegram alerts
- **30+ Pre-built Rules** - Ready-to-use templates for common scenarios
- **User Feedback Loop** - Improve detection with false positive/negative reporting
- **Dual Distribution** - OpenClaw plugin or standalone proxy mode

## Quick Start

### Installation

```bash
npm install clawsec
```

### Basic Configuration

Create `clawsec.yaml` in your project root:

```yaml
version: "1.0"

global:
  enabled: true
  logLevel: info

rules:
  purchase:
    enabled: true
    severity: critical
    action: block
    spendLimits:
      perTransaction: 100
      daily: 500

  destructive:
    enabled: true
    severity: critical
    action: confirm

  secrets:
    enabled: true
    severity: critical
    action: block
```

### OpenClaw Plugin Usage

```typescript
import clawsec from 'clawsec';

// Register with OpenClaw
openClaw.registerPlugin(clawsec);
```

### Standalone Proxy Mode

```bash
# Start the proxy server
npx clawsec serve --port 8080

# Configure your agent to use the proxy
CLAWSEC_PROXY=http://localhost:8080
```

## Configuration

### Global Settings

```yaml
global:
  enabled: true           # Enable/disable the plugin
  logLevel: info          # debug, info, warn, error

llm:
  enabled: true           # Enable LLM-based detection
  model: null             # Use OpenClaw's configured model
```

### Purchase Protection

```yaml
rules:
  purchase:
    enabled: true
    severity: critical
    action: block          # block, confirm, warn, log
    spendLimits:
      perTransaction: 100  # Maximum per transaction
      daily: 500           # Maximum daily total
    domains:
      mode: blocklist      # blocklist or allowlist
      blocklist:
        - "*.amazon.com"
        - "*.stripe.com"
        - "paypal.com"
```

### Website Control

```yaml
rules:
  website:
    enabled: true
    mode: blocklist        # blocklist or allowlist
    severity: high
    action: block
    blocklist:
      - "*.malware.com"
      - "phishing-*.com"
    allowlist:
      - "github.com"
      - "stackoverflow.com"
```

### Destructive Commands

```yaml
rules:
  destructive:
    enabled: true
    severity: critical
    action: confirm
    shell:
      enabled: true        # rm -rf, mkfs, dd, etc.
    cloud:
      enabled: true        # AWS, GCP, Azure delete operations
    code:
      enabled: true        # shutil.rmtree, fs.rm, etc.
```

### Secrets Detection

```yaml
rules:
  secrets:
    enabled: true
    severity: critical
    action: block
    # Detects: API keys, tokens, passwords, PII
```

### Data Exfiltration

```yaml
rules:
  exfiltration:
    enabled: true
    severity: high
    action: block
    # Detects: curl POST, wget uploads, netcat, etc.
```

### Output Sanitization

```yaml
rules:
  sanitization:
    enabled: true
    severity: high
    action: block
    minConfidence: 0.5
    redactMatches: false   # true to redact instead of block
    categories:
      instructionOverride: true
      systemLeak: true
      jailbreak: true
      encodedPayload: true
```

### Approval Flow

```yaml
approval:
  native:
    enabled: true
    timeout: 300           # 5 minutes

  agentConfirm:
    enabled: true
    parameterName: "_clawsec_confirm"

  webhook:
    enabled: false
    url: "https://api.example.com/approve"
    timeout: 30
    headers:
      Authorization: "Bearer ${WEBHOOK_TOKEN}"
```

### Notifications

```yaml
notifications:
  slack:
    enabled: true
    webhookUrl: "${SLACK_WEBHOOK_URL}"
    channel: "#security-alerts"
    minSeverity: high

  discord:
    enabled: true
    webhookUrl: "${DISCORD_WEBHOOK_URL}"
    minSeverity: critical

  telegram:
    enabled: true
    botToken: "${TELEGRAM_BOT_TOKEN}"
    chatId: "${TELEGRAM_CHAT_ID}"
    parseMode: HTML
```

## Pre-built Rule Templates

Use our 30+ built-in templates for common scenarios:

| Category | Templates |
|----------|-----------|
| Cloud Providers | `aws-security`, `gcp-security`, `azure-security` |
| Infrastructure | `kubernetes`, `docker`, `terraform`, `serverless` |
| Development | `git-operations`, `cicd-security`, `package-managers` |
| Databases | `database-sql`, `database-nosql`, `cloud-storage` |
| Secrets | `api-keys`, `authentication`, `secrets-management` |
| Compliance | `pii-protection`, `healthcare-hipaa`, `financial-pci` |
| Environment | `minimal`, `development-env`, `production-strict` |

```yaml
# Extend from a built-in template
extends:
  - builtin/aws-security
  - builtin/pii-protection

# Override specific settings
rules:
  purchase:
    spendLimits:
      perTransaction: 200
```

## CLI Commands

```bash
# Check plugin status
npx clawsec status

# Test configuration
npx clawsec test

# View audit log
npx clawsec audit --since "1 hour ago"

# Report false positive
npx clawsec feedback --false-positive <event-id>

# Report false negative
npx clawsec feedback --false-negative "description of what was missed"
```

## API Reference

### Hooks

Clawsec registers three hooks with OpenClaw:

#### `before-tool-call`

Intercepts tool calls before execution:

```typescript
interface BeforeToolCallResult {
  allow: boolean;
  modifiedInput?: Record<string, unknown>;
  blockMessage?: string;
  metadata?: {
    category?: ThreatCategory;
    severity?: Severity;
    rule?: string;
    reason?: string;
  };
}
```

#### `before-agent-start`

Injects security context into system prompts:

```typescript
interface BeforeAgentStartResult {
  systemPromptAddition?: string;
  modifiedConfig?: Record<string, unknown>;
}
```

#### `tool-result-persist`

Filters sensitive data from tool outputs:

```typescript
interface ToolResultPersistResult {
  allow: boolean;
  filteredOutput?: unknown;
  redactions?: Array<{
    type: string;
    description: string;
  }>;
}
```

### Detectors

Access detectors programmatically:

```typescript
import {
  createPurchaseDetector,
  createWebsiteDetector,
  createDestructiveDetector,
  createSecretsDetector,
  createExfiltrationDetector
} from 'clawsec/detectors';

const detector = createSecretsDetector(config);
const results = await detector.detectAll({
  toolName: 'Read',
  toolInput: { file_path: '/etc/passwd' },
  toolOutput: fileContents,
});
```

### Notifications

Send custom notifications:

```typescript
import { createNotificationManager, createSecurityEvent } from 'clawsec/notifications';

const manager = createNotificationManager({
  slack: { enabled: true, webhookUrl: '...' },
});

const event = createSecurityEvent({
  category: 'custom',
  severity: 'high',
  toolName: 'CustomTool',
  reason: 'Custom security event',
  action: 'blocked',
});

await manager.notify(event);
```

## Detection Patterns

### Destructive Commands

```
Shell:      rm -rf, mkfs, dd of=/dev/, DROP DATABASE, TRUNCATE
Cloud:      aws ec2 terminate, gcloud delete, kubectl delete ns
Git:        push --force, reset --hard, clean -f
Code:       shutil.rmtree(), fs.rm(recursive), os.RemoveAll()
```

### Secrets Detection

```
API Keys:   sk-..., AKIA..., gho_..., xoxb-...
Tokens:     Bearer ..., eyJ... (JWT), session_...
Credentials: password=, secret=, api_key=
PII:        SSN (xxx-xx-xxxx), Credit Cards (Luhn validation)
```

### Prompt Injection

```
Override:   "ignore previous", "new instructions", "system:"
Leakage:    "your system prompt", "initial instructions"
Jailbreak:  "DAN mode", "developer mode", "pretend you are"
Encoded:    Base64, hex, unicode escape sequences
```

## Approval Flow

```
Detection ─┬─► block ──────────► REJECT (no approval possible)
           │
           ├─► confirm ────────► 3 approval paths:
           │                     ├── Native: /approve <id>
           │                     ├── Agent-confirm: retry with _clawsec_confirm
           │                     └── Webhook: external system
           │
           ├─► warn ───────────► ALLOW (log warning)
           │
           └─► log ────────────► ALLOW (silent audit)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CLAWSEC PLUGIN                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Tool Call ──► Pattern Matching (≤5ms) ──┬─► BLOCK/ALLOW    │
│                                          │                   │
│                     ambiguous ───────────┘                   │
│                         │                                    │
│                         ▼                                    │
│                  LLM Analysis (~500ms) ──► BLOCK/CONFIRM     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Development

### Building

```bash
npm install
npm run build
```

### Testing

```bash
npm test                # Run all tests
npm run test:watch      # Watch mode
npm run test:coverage   # Coverage report
```

### Project Structure

```
clawsec/
├── src/
│   ├── index.ts                    # Plugin entry point
│   ├── config/                     # Configuration handling
│   ├── detectors/                  # Detection modules
│   │   ├── purchase/               # Domain + intent detection
│   │   ├── website/                # URL allowlist/blocklist
│   │   ├── destructive/            # Shell, code, cloud patterns
│   │   ├── secrets/                # API keys, tokens, PII
│   │   └── exfiltration/           # Data exfiltration detection
│   ├── engine/                     # Hybrid detection engine
│   ├── actions/                    # Block, confirm, warn, log
│   ├── approval/                   # Approval flow handlers
│   ├── hooks/                      # OpenClaw hook handlers
│   ├── sanitization/               # Output sanitization
│   ├── notifications/              # Slack, Discord, Telegram
│   ├── feedback/                   # User feedback system
│   ├── proxy/                      # Standalone proxy mode
│   └── cli/                        # CLI commands
├── rules/builtin/                  # Pre-built rule templates
└── tests/                          # Test files
```

## Troubleshooting

### Common Issues

**Plugin not blocking expected threats:**
- Check `enabled: true` in config
- Verify severity threshold matches
- Review audit log with `npx clawsec audit`

**False positives:**
- Report with `npx clawsec feedback --false-positive <id>`
- Adjust `minConfidence` in config
- Use allowlist for known-safe patterns

**Notifications not sending:**
- Verify webhook URLs are correct
- Check `minSeverity` filter
- Test with `npx clawsec test notifications`

**Performance issues:**
- Disable LLM analysis if not needed
- Use `log` action for low-severity rules
- Increase `minConfidence` threshold

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Submit a pull request

## License

MIT

## Credits

Built by the Clawsec team. Inspired by ClawGuardian and the need for comprehensive AI agent security.
