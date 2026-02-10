/**
 * Confirm Action Handler
 * Handles requesting approval for potentially risky tool calls
 */

import type {
  ActionContext,
  ActionHandler,
  ActionResult,
  ActionLogger,
  ApprovalMethod,
  PendingApproval,
} from "./types.js";
import { noOpLogger } from "./types.js";
import { getDefaultApprovalStore } from "../approval/store.js";
import type { PendingApprovalInput } from "../approval/types.js";

/**
 * Generate a UUID v4
 * Uses crypto.randomUUID if available, falls back to manual implementation
 */
export function generateApprovalId(): string {
  // Use native crypto if available (Node.js 16+, modern browsers)
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }

  // Fallback implementation
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Determine which approval methods are enabled based on config
 */
export function getEnabledApprovalMethods(
  context: ActionContext,
): ApprovalMethod[] {
  const { config } = context;
  const methods: ApprovalMethod[] = [];

  // Check native approval
  if (config.approval?.native?.enabled !== false) {
    methods.push("native");
  }

  // Check agent-confirm
  if (config.approval?.agentConfirm?.enabled !== false) {
    methods.push("agent-confirm");
  }

  // Check webhook (only if URL is configured)
  if (config.approval?.webhook?.enabled && config.approval.webhook.url) {
    methods.push("webhook");
  }

  return methods;
}

/**
 * Get the timeout for approval requests (in seconds)
 */
export function getApprovalTimeout(context: ActionContext): number {
  const { config } = context;

  // Use native timeout as the primary timeout
  return config.approval?.native?.timeout ?? 300;
}

/**
 * Format a severity level for display
 */
function formatSeverity(severity: string): string {
  return severity.toUpperCase();
}

/**
 * Format a threat category for display
 */
function formatCategory(category: string): string {
  const categoryNames: Record<string, string> = {
    purchase: "Purchase/Payment",
    website: "Website Access",
    destructive: "Destructive Command",
    secrets: "Secrets/PII",
    exfiltration: "Data Transfer",
    unknown: "Manual Approval",
  };
  return categoryNames[category] || category;
}

/**
 * Generate approval instructions based on enabled methods
 */
function generateApprovalInstructions(
  methods: ApprovalMethod[],
  approvalId: string,
  context: ActionContext,
): string {
  const instructions: string[] = [];

  // if (methods.includes('native')) {
  //   instructions.push(`  - Type: /approve ${approvalId}`);
  // }

  if (methods.includes("agent-confirm")) {
    const paramName =
      context.config.approval?.agentConfirm?.parameterName ??
      "_clawsec_confirm";
    instructions.push(`  - Retry with parameter: ${paramName}="${approvalId}"`);
  }

  // if (methods.includes('webhook')) {
  //   instructions.push(`  - Webhook approval is enabled (external system will be notified)`);
  // }

  return instructions.join("\n");
}

/**
 * Generate a message explaining the confirmation requirement
 */
export function generateConfirmMessage(
  context: ActionContext,
  approval: PendingApproval,
): string {
  const { analysis, toolCall } = context;
  const { primaryDetection } = analysis;

  let message = "";

  if (primaryDetection) {
    const category = formatCategory(primaryDetection.category);
    const severity = formatSeverity(primaryDetection.severity);
    message = `ClawSec Protection: [${severity}] ${category} requires approval\n`;
    message += `Tool: ${toolCall.toolName}\n`;
    message += `Reason: ${primaryDetection.reason}\n\n`;
  } else {
    message = `ClawSec Protection: Action requires approval\n`;
    message += `Tool: ${toolCall.toolName}\n\n`;
  }

  message += `Approval ID: ${approval.id}\n`;
  message += `Timeout: ${approval.timeout} seconds\n\n`;
  message += `To approve:\n`;
  message += generateApprovalInstructions(
    approval.methods,
    approval.id,
    context,
  );

  return message;
}

/**
 * Confirm action handler implementation
 */
export class ConfirmHandler implements ActionHandler {
  private logger: ActionLogger;

  constructor(logger: ActionLogger = noOpLogger) {
    this.logger = logger;
  }

  async execute(context: ActionContext): Promise<ActionResult> {
    const { analysis, toolCall } = context;

    // Generate unique approval ID
    const approvalId = generateApprovalId();

    // Determine enabled approval methods
    const methods = getEnabledApprovalMethods(context);

    // Get timeout
    const timeout = getApprovalTimeout(context);

    // Create full approval record for storage
    const now = Date.now();
    const approvalInput: PendingApprovalInput = {
      id: approvalId,
      createdAt: now,
      expiresAt: now + timeout * 1000,
      detection: analysis.primaryDetection
        ? {
            category: analysis.primaryDetection.category,
            severity: analysis.primaryDetection.severity,
            confidence: analysis.primaryDetection.confidence,
            reason: analysis.primaryDetection.reason,
          }
        : {
            category: "unknown", // No specific threat detected - manual approval
            severity: "medium",
            confidence: 0.5,
            reason: "Manual approval required",
          },
      toolCall: {
        toolName: toolCall.toolName,
        toolInput: toolCall.toolInput || {},
      },
    };

    // Store the approval record
    const store = getDefaultApprovalStore();
    store.add(approvalInput);

    // Create lightweight object for ActionResult
    const pendingApproval: PendingApproval = {
      id: approvalId,
      timeout,
      methods,
    };

    const message = generateConfirmMessage(context, pendingApproval);

    // Log the confirmation request
    this.logger.info("Action requires approval", {
      toolName: toolCall.toolName,
      approvalId,
      category: analysis.primaryDetection?.category,
      severity: analysis.primaryDetection?.severity,
      reason: analysis.primaryDetection?.reason,
      methods,
      timeout,
    });

    return {
      allowed: false,
      message,
      pendingApproval,
      logged: true,
    };
  }
}

/**
 * Create a confirm action handler with the given logger
 */
export function createConfirmHandler(logger?: ActionLogger): ConfirmHandler {
  return new ConfirmHandler(logger);
}
