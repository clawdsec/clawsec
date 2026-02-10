/**
 * Warn Action Handler
 * Handles warning about potentially risky tool calls while still allowing them
 */

import type { ActionContext, ActionHandler, ActionResult, ActionLogger } from './types.js';
import { noOpLogger } from './types.js';

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
    purchase: 'Purchase/Payment',
    website: 'Website Access',
    destructive: 'Destructive Command',
    secrets: 'Secrets/PII',
    exfiltration: 'Data Transfer',
  };
  return categoryNames[category] || category;
}

/**
 * Generate a warning message about the detected threat
 */
export function generateWarnMessage(context: ActionContext): string {
  const { analysis, toolCall } = context;
  const { primaryDetection, detections } = analysis;

  if (!primaryDetection) {
    return `ClawSec Warning: ${toolCall.toolName} executed with security notice.`;
  }

  const category = formatCategory(primaryDetection.category);
  const severity = formatSeverity(primaryDetection.severity);
  const reason = primaryDetection.reason;

  let message = `ClawSec Warning: [${severity}] ${category} detected\n`;
  message += `Tool: ${toolCall.toolName}\n`;
  message += `Reason: ${reason}\n`;
  message += `\nAction allowed but logged for audit.`;

  // Include additional detections if any
  if (detections.length > 1) {
    message += `\n\nAdditional warnings (${detections.length - 1}):`;
    for (const detection of detections) {
      if (detection !== primaryDetection) {
        message += `\n- ${formatCategory(detection.category)}: ${detection.reason}`;
      }
    }
  }

  return message;
}

/**
 * Warn action handler implementation
 */
export class WarnHandler implements ActionHandler {
  private logger: ActionLogger;

  constructor(logger: ActionLogger = noOpLogger) {
    this.logger = logger;
  }

  async execute(context: ActionContext): Promise<ActionResult> {
    const { analysis, toolCall } = context;
    const message = generateWarnMessage(context);

    // Log the warning
    this.logger.warn('Action executed with warning', {
      toolName: toolCall.toolName,
      category: analysis.primaryDetection?.category,
      severity: analysis.primaryDetection?.severity,
      reason: analysis.primaryDetection?.reason,
      detectionCount: analysis.detections.length,
    });

    return {
      allowed: true,
      message,
      logged: true,
    };
  }
}

/**
 * Create a warn action handler with the given logger
 */
export function createWarnHandler(logger?: ActionLogger): WarnHandler {
  return new WarnHandler(logger);
}
