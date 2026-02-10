/**
 * Clawsec Configuration Schema
 * Zod schemas and TypeScript types for the security plugin configuration
 */

import { z } from 'zod';

// =============================================================================
// ENUMS
// =============================================================================

/**
 * Severity levels for security detections
 */
export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low']);
export type Severity = z.infer<typeof SeveritySchema>;

/**
 * Actions that can be taken when a threat is detected
 */
export const ActionSchema = z.enum(['block', 'confirm', 'agent-confirm', 'warn', 'log']);
export type Action = z.infer<typeof ActionSchema>;

/**
 * Log levels for the plugin
 */
export const LogLevelSchema = z.enum(['debug', 'info', 'warn', 'error']);
export type LogLevel = z.infer<typeof LogLevelSchema>;

/**
 * Mode for domain/website filtering
 */
export const FilterModeSchema = z.enum(['blocklist', 'allowlist']);
export type FilterMode = z.infer<typeof FilterModeSchema>;

// =============================================================================
// GLOBAL CONFIGURATION
// =============================================================================

/**
 * Global plugin settings
 */
export const GlobalConfigSchema = z.object({
  /** Whether the plugin is enabled */
  enabled: z.boolean().default(true),
  /** Log level for the plugin */
  logLevel: LogLevelSchema.default('info'),
}).default(() => ({
  enabled: true,
  logLevel: 'info' as const,
}));
export type GlobalConfig = z.infer<typeof GlobalConfigSchema>;

// =============================================================================
// LLM CONFIGURATION
// =============================================================================

/**
 * LLM integration settings
 */
export const LLMConfigSchema = z.object({
  /** Whether LLM-based detection is enabled */
  enabled: z.boolean().default(true),
  /** Model to use (null means use OpenClaw's configured model) */
  model: z.string().nullable().default(null),
}).default(() => ({
  enabled: true,
  model: null,
}));
export type LLMConfig = z.infer<typeof LLMConfigSchema>;

// =============================================================================
// PURCHASE RULE CONFIGURATION
// =============================================================================

/**
 * Spending limits for purchase protection
 */
export const SpendLimitsSchema = z.object({
  /** Maximum amount per transaction */
  perTransaction: z.number().nonnegative().default(100),
  /** Maximum daily spending amount */
  daily: z.number().nonnegative().default(500),
}).default(() => ({
  perTransaction: 100,
  daily: 500,
}));
export type SpendLimits = z.infer<typeof SpendLimitsSchema>;

/**
 * Domain filtering configuration for purchases
 */
export const PurchaseDomainsSchema = z.object({
  /** Mode for domain filtering */
  mode: FilterModeSchema.default('blocklist'),
  /** Domains to block (supports glob patterns) */
  blocklist: z.array(z.string()).default([]),
}).default(() => ({
  mode: 'blocklist' as const,
  blocklist: [],
}));
export type PurchaseDomains = z.infer<typeof PurchaseDomainsSchema>;

/**
 * Purchase protection rule configuration
 */
export const PurchaseRuleSchema = z.object({
  /** Whether purchase protection is enabled */
  enabled: z.boolean().default(true),
  /** Severity level for purchase detections */
  severity: SeveritySchema.default('critical'),
  /** Action to take when purchase is detected */
  action: ActionSchema.default('block'),
  /** Spending limits */
  spendLimits: SpendLimitsSchema.optional().default(() => ({
    perTransaction: 100,
    daily: 500,
  })),
  /** Domain configuration */
  domains: PurchaseDomainsSchema.optional().default(() => ({
    mode: 'blocklist' as const,
    blocklist: [],
  })),
}).default(() => ({
  enabled: true,
  severity: 'critical' as const,
  action: 'block' as const,
  spendLimits: { perTransaction: 100, daily: 500 },
  domains: { mode: 'blocklist' as const, blocklist: [] },
}));
export type PurchaseRule = z.infer<typeof PurchaseRuleSchema>;

// =============================================================================
// WEBSITE RULE CONFIGURATION
// =============================================================================

/**
 * Website control rule configuration
 */
export const WebsiteRuleSchema = z.object({
  /** Whether website control is enabled */
  enabled: z.boolean().default(true),
  /** Mode for website filtering */
  mode: FilterModeSchema.default('blocklist'),
  /** Severity level for website detections */
  severity: SeveritySchema.default('high'),
  /** Action to take when blocked website is accessed */
  action: ActionSchema.default('block'),
  /** Websites to block (supports glob patterns like *.malware.com) */
  blocklist: z.array(z.string()).default([]),
  /** Websites to allow (supports glob patterns) */
  allowlist: z.array(z.string()).default([]),
}).default(() => ({
  enabled: true,
  mode: 'blocklist' as const,
  severity: 'high' as const,
  action: 'block' as const,
  blocklist: [],
  allowlist: [],
}));
export type WebsiteRule = z.infer<typeof WebsiteRuleSchema>;

// =============================================================================
// DESTRUCTIVE COMMANDS RULE CONFIGURATION
// =============================================================================

/**
 * Shell command protection configuration
 */
export const ShellProtectionSchema = z.object({
  /** Whether shell command protection is enabled */
  enabled: z.boolean().default(true),
  /** Custom regex patterns for shell command detection */
  patterns: z.array(z.string()).optional(),
}).default(() => ({ enabled: true }));
export type ShellProtection = z.infer<typeof ShellProtectionSchema>;

/**
 * Cloud operation protection configuration
 */
export const CloudProtectionSchema = z.object({
  /** Whether cloud operation protection is enabled */
  enabled: z.boolean().default(true),
  /** Custom regex patterns for cloud operation detection */
  patterns: z.array(z.string()).optional(),
}).default(() => ({ enabled: true }));
export type CloudProtection = z.infer<typeof CloudProtectionSchema>;

/**
 * Code pattern protection configuration
 */
export const CodeProtectionSchema = z.object({
  /** Whether code pattern protection is enabled */
  enabled: z.boolean().default(true),
  /** Custom regex patterns for code pattern detection */
  patterns: z.array(z.string()).optional(),
}).default(() => ({ enabled: true }));
export type CodeProtection = z.infer<typeof CodeProtectionSchema>;

/**
 * Destructive commands rule configuration
 */
export const DestructiveRuleSchema = z.object({
  /** Whether destructive command protection is enabled */
  enabled: z.boolean().default(true),
  /** Severity level for destructive command detections */
  severity: SeveritySchema.default('critical'),
  /** Action to take when destructive command is detected */
  action: ActionSchema.default('confirm'),
  /** Shell command protection settings */
  shell: ShellProtectionSchema.optional().default(() => ({ enabled: true })),
  /** Cloud operation protection settings */
  cloud: CloudProtectionSchema.optional().default(() => ({ enabled: true })),
  /** Code pattern protection settings */
  code: CodeProtectionSchema.optional().default(() => ({ enabled: true })),
}).default(() => ({
  enabled: true,
  severity: 'critical' as const,
  action: 'confirm' as const,
  shell: { enabled: true },
  cloud: { enabled: true },
  code: { enabled: true },
}));
export type DestructiveRule = z.infer<typeof DestructiveRuleSchema>;

// =============================================================================
// OUTPUT SANITIZATION CONFIGURATION
// =============================================================================

/**
 * Injection scanner category configuration
 */
export const InjectionCategoriesSchema = z.object({
  /** Detect instruction override attempts */
  instructionOverride: z.boolean().default(true),
  /** Detect system prompt leak attempts */
  systemLeak: z.boolean().default(true),
  /** Detect jailbreak patterns */
  jailbreak: z.boolean().default(true),
  /** Detect encoded payloads */
  encodedPayload: z.boolean().default(true),
}).default(() => ({
  instructionOverride: true,
  systemLeak: true,
  jailbreak: true,
  encodedPayload: true,
}));
export type InjectionCategories = z.infer<typeof InjectionCategoriesSchema>;

/**
 * Output sanitization rule configuration
 */
export const SanitizationRuleSchema = z.object({
  /** Whether output sanitization is enabled */
  enabled: z.boolean().default(true),
  /** Severity level for injection detections */
  severity: SeveritySchema.default('high'),
  /** Action to take when injection is detected */
  action: ActionSchema.default('block'),
  /** Minimum confidence threshold (0.0-1.0) */
  minConfidence: z.number().min(0).max(1).default(0.5),
  /** Whether to redact detected injections (vs blocking entirely) */
  redactMatches: z.boolean().default(false),
  /** Categories to scan for */
  categories: InjectionCategoriesSchema.optional().default(() => ({
    instructionOverride: true,
    systemLeak: true,
    jailbreak: true,
    encodedPayload: true,
  })),
}).default(() => ({
  enabled: true,
  severity: 'high' as const,
  action: 'block' as const,
  minConfidence: 0.5,
  redactMatches: false,
  categories: {
    instructionOverride: true,
    systemLeak: true,
    jailbreak: true,
    encodedPayload: true,
  },
}));
export type SanitizationRule = z.infer<typeof SanitizationRuleSchema>;

// =============================================================================
// SECRETS/PII RULE CONFIGURATION
// =============================================================================

/**
 * Secrets and PII detection rule configuration
 */
export const SecretsRuleSchema = z.object({
  /** Whether secrets/PII detection is enabled */
  enabled: z.boolean().default(true),
  /** Severity level for secrets detections */
  severity: SeveritySchema.default('critical'),
  /** Action to take when secrets are detected */
  action: ActionSchema.default('block'),
  /** Custom regex patterns for secrets detection */
  patterns: z.array(z.string()).optional(),
}).default(() => ({
  enabled: true,
  severity: 'critical' as const,
  action: 'block' as const,
}));
export type SecretsRule = z.infer<typeof SecretsRuleSchema>;

// =============================================================================
// DATA EXFILTRATION RULE CONFIGURATION
// =============================================================================

/**
 * Data exfiltration detection rule configuration
 */
export const ExfiltrationRuleSchema = z.object({
  /** Whether data exfiltration detection is enabled */
  enabled: z.boolean().default(true),
  /** Severity level for exfiltration detections */
  severity: SeveritySchema.default('high'),
  /** Action to take when exfiltration is detected */
  action: ActionSchema.default('block'),
  /** Custom regex patterns for exfiltration detection */
  patterns: z.array(z.string()).optional(),
}).default(() => ({
  enabled: true,
  severity: 'high' as const,
  action: 'block' as const,
}));
export type ExfiltrationRule = z.infer<typeof ExfiltrationRuleSchema>;

// =============================================================================
// RULES CONFIGURATION
// =============================================================================

/**
 * All security rules configuration
 */
export const RulesConfigSchema = z.object({
  /** Purchase protection rules */
  purchase: PurchaseRuleSchema.optional().default(() => ({
    enabled: true,
    severity: 'critical' as const,
    action: 'block' as const,
    spendLimits: { perTransaction: 100, daily: 500 },
    domains: { mode: 'blocklist' as const, blocklist: [] },
  })),
  /** Website control rules */
  website: WebsiteRuleSchema.optional().default(() => ({
    enabled: true,
    mode: 'blocklist' as const,
    severity: 'high' as const,
    action: 'block' as const,
    blocklist: [],
    allowlist: [],
  })),
  /** Destructive command rules */
  destructive: DestructiveRuleSchema.optional().default(() => ({
    enabled: true,
    severity: 'critical' as const,
    action: 'confirm' as const,
    shell: { enabled: true },
    cloud: { enabled: true },
    code: { enabled: true },
  })),
  /** Secrets/PII detection rules */
  secrets: SecretsRuleSchema.optional().default(() => ({
    enabled: true,
    severity: 'critical' as const,
    action: 'block' as const,
  })),
  /** Data exfiltration detection rules */
  exfiltration: ExfiltrationRuleSchema.optional().default(() => ({
    enabled: true,
    severity: 'high' as const,
    action: 'block' as const,
  })),
  /** Output sanitization rules */
  sanitization: SanitizationRuleSchema.optional().default(() => ({
    enabled: true,
    severity: 'high' as const,
    action: 'block' as const,
    minConfidence: 0.5,
    redactMatches: false,
    categories: {
      instructionOverride: true,
      systemLeak: true,
      jailbreak: true,
      encodedPayload: true,
    },
  })),
}).default(() => ({
  purchase: {
    enabled: true,
    severity: 'critical' as const,
    action: 'block' as const,
    spendLimits: { perTransaction: 100, daily: 500 },
    domains: { mode: 'blocklist' as const, blocklist: [] },
  },
  website: {
    enabled: true,
    mode: 'blocklist' as const,
    severity: 'high' as const,
    action: 'block' as const,
    blocklist: [],
    allowlist: [],
  },
  destructive: {
    enabled: true,
    severity: 'critical' as const,
    action: 'confirm' as const,
    shell: { enabled: true },
    cloud: { enabled: true },
    code: { enabled: true },
  },
  secrets: {
    enabled: true,
    severity: 'critical' as const,
    action: 'block' as const,
  },
  exfiltration: {
    enabled: true,
    severity: 'high' as const,
    action: 'block' as const,
  },
  sanitization: {
    enabled: true,
    severity: 'high' as const,
    action: 'block' as const,
    minConfidence: 0.5,
    redactMatches: false,
    categories: {
      instructionOverride: true,
      systemLeak: true,
      jailbreak: true,
      encodedPayload: true,
    },
  },
}));
export type RulesConfig = z.infer<typeof RulesConfigSchema>;

// =============================================================================
// APPROVAL CONFIGURATION
// =============================================================================

/**
 * Native approval flow configuration
 */
export const NativeApprovalSchema = z.object({
  /** Whether native approval is enabled */
  enabled: z.boolean().default(true),
  /** Timeout in seconds for approval requests */
  timeout: z.number().positive().default(300),
}).default(() => ({
  enabled: true,
  timeout: 300,
}));
export type NativeApproval = z.infer<typeof NativeApprovalSchema>;

/**
 * Agent confirm approval flow configuration
 */
export const AgentConfirmSchema = z.object({
  /** Whether agent confirm is enabled */
  enabled: z.boolean().default(true),
  /** Parameter name to use for confirmation */
  parameterName: z.string().default('_clawsec_confirm'),
}).default(() => ({
  enabled: true,
  parameterName: '_clawsec_confirm',
}));
export type AgentConfirm = z.infer<typeof AgentConfirmSchema>;

/**
 * Webhook approval flow configuration
 */
export const WebhookApprovalSchema = z.object({
  /** Whether webhook approval is enabled */
  enabled: z.boolean().default(false),
  /** Webhook URL for approval requests */
  url: z.url().optional(),
  /** Timeout in seconds for webhook requests */
  timeout: z.number().positive().default(30),
  /** Custom headers to send with webhook requests */
  headers: z.record(z.string(), z.string()).default({}),
}).default(() => ({
  enabled: false,
  url: undefined,
  timeout: 30,
  headers: {},
}));
export type WebhookApproval = z.infer<typeof WebhookApprovalSchema>;

/**
 * Approval flow configuration
 */
export const ApprovalConfigSchema = z.object({
  /** Native approval settings */
  native: NativeApprovalSchema.optional().default(() => ({
    enabled: true,
    timeout: 300,
  })),
  /** Agent confirm settings */
  agentConfirm: AgentConfirmSchema.optional().default(() => ({
    enabled: true,
    parameterName: '_clawsec_confirm',
  })),
  /** Webhook approval settings */
  webhook: WebhookApprovalSchema.optional().default(() => ({
    enabled: false,
    url: undefined,
    timeout: 30,
    headers: {},
  })),
}).default(() => ({
  native: { enabled: true, timeout: 300 },
  agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
  webhook: { enabled: false, url: undefined, timeout: 30, headers: {} },
}));
export type ApprovalConfig = z.infer<typeof ApprovalConfigSchema>;

// =============================================================================
// ROOT CONFIGURATION
// =============================================================================

/**
 * Root configuration schema for clawsec.yaml
 */
export const ClawsecConfigSchema = z.object({
  /** Configuration version */
  version: z.string().default('1.0'),
  /** Template inheritance - list of builtin or custom templates to extend */
  extends: z.array(z.string()).optional(),
  /** Global plugin settings */
  global: GlobalConfigSchema.optional().default(() => ({
    enabled: true,
    logLevel: 'info' as const,
  })),
  /** LLM integration settings */
  llm: LLMConfigSchema.optional().default(() => ({
    enabled: true,
    model: null,
  })),
  /** Security rules */
  rules: RulesConfigSchema.optional().default(() => ({
    purchase: {
      enabled: true,
      severity: 'critical' as const,
      action: 'block' as const,
      spendLimits: { perTransaction: 100, daily: 500 },
      domains: { mode: 'blocklist' as const, blocklist: [] },
    },
    website: {
      enabled: true,
      mode: 'blocklist' as const,
      severity: 'high' as const,
      action: 'block' as const,
      blocklist: [],
      allowlist: [],
    },
    destructive: {
      enabled: true,
      severity: 'critical' as const,
      action: 'confirm' as const,
      shell: { enabled: true },
      cloud: { enabled: true },
      code: { enabled: true },
    },
    secrets: {
      enabled: true,
      severity: 'critical' as const,
      action: 'block' as const,
    },
    exfiltration: {
      enabled: true,
      severity: 'high' as const,
      action: 'block' as const,
    },
    sanitization: {
      enabled: true,
      severity: 'high' as const,
      action: 'block' as const,
      minConfidence: 0.5,
      redactMatches: false,
      categories: {
        instructionOverride: true,
        systemLeak: true,
        jailbreak: true,
        encodedPayload: true,
      },
    },
  })),
  /** Approval flow settings */
  approval: ApprovalConfigSchema.optional().default(() => ({
    native: { enabled: true, timeout: 300 },
    agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
    webhook: { enabled: false, url: undefined, timeout: 30, headers: {} },
  })),
}).default(() => ({
  version: '1.0',
  global: { enabled: true, logLevel: 'info' as const },
  llm: { enabled: true, model: null },
  rules: {
    purchase: {
      enabled: true,
      severity: 'critical' as const,
      action: 'block' as const,
      spendLimits: { perTransaction: 100, daily: 500 },
      domains: { mode: 'blocklist' as const, blocklist: [] },
    },
    website: {
      enabled: true,
      mode: 'blocklist' as const,
      severity: 'high' as const,
      action: 'block' as const,
      blocklist: [],
      allowlist: [],
    },
    destructive: {
      enabled: true,
      severity: 'critical' as const,
      action: 'confirm' as const,
      shell: { enabled: true },
      cloud: { enabled: true },
      code: { enabled: true },
    },
    secrets: {
      enabled: true,
      severity: 'critical' as const,
      action: 'block' as const,
    },
    exfiltration: {
      enabled: true,
      severity: 'high' as const,
      action: 'block' as const,
    },
    sanitization: {
      enabled: true,
      severity: 'high' as const,
      action: 'block' as const,
      minConfidence: 0.5,
      redactMatches: false,
      categories: {
        instructionOverride: true,
        systemLeak: true,
        jailbreak: true,
        encodedPayload: true,
      },
    },
  },
  approval: {
    native: { enabled: true, timeout: 300 },
    agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
    webhook: { enabled: false, url: undefined, timeout: 30, headers: {} },
  },
}));

/**
 * Main configuration type for Clawsec
 */
export type ClawsecConfig = z.infer<typeof ClawsecConfigSchema>;

/**
 * Partial configuration type (for merging with defaults)
 */
export type PartialClawsecConfig = z.input<typeof ClawsecConfigSchema>;
