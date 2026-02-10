/**
 * Block Action Handler
 * Handles blocking tool calls when critical threats are detected
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
    website: 'Malicious Website',
    destructive: 'Destructive Command',
    secrets: 'Secrets/PII Exposure',
    exfiltration: 'Data Exfiltration',
  };
  return categoryNames[category] || category;
}

/**
 * Generate a clear message explaining why the action was blocked
 */
export function generateBlockMessage(context: ActionContext): string {
  const { analysis, toolCall } = context;
  const { primaryDetection, detections } = analysis;

  if (!primaryDetection) {
    return `Blocked by ClawSec: ${toolCall.toolName} was blocked by security policy.`;
  }

  const category = formatCategory(primaryDetection.category);
  const severity = formatSeverity(primaryDetection.severity);
  const reason = primaryDetection.reason;

  let message = `Blocked by ClawSec: [${severity}] ${category} detected\n`;
  message += `Tool: ${toolCall.toolName}\n`;
  message += `Reason: ${reason}`;

  // Include additional detections if any
  if (detections.length > 1) {
    message += `\n\nAdditional detections (${detections.length - 1}):`;
    for (const detection of detections) {
      if (detection !== primaryDetection) {
        message += `\n- ${formatCategory(detection.category)}: ${detection.reason}`;
      }
    }
  }

  return message;
}

/**
 * Block action handler implementation
 */
export class BlockHandler implements ActionHandler {
  private logger: ActionLogger;

  constructor(logger: ActionLogger = noOpLogger) {
    this.logger = logger;
  }

  async execute(context: ActionContext): Promise<ActionResult> {
    const { analysis, toolCall } = context;
    const message = generateBlockMessage(context);

    // Log the block event
    this.logger.warn('Action blocked', {
      toolName: toolCall.toolName,
      category: analysis.primaryDetection?.category,
      severity: analysis.primaryDetection?.severity,
      reason: analysis.primaryDetection?.reason,
      detectionCount: analysis.detections.length,
    });

    return {
      allowed: false,
      message,
      logged: true,
    };
  }
}

/**
 * Create a block action handler with the given logger
 */
export function createBlockHandler(logger?: ActionLogger): BlockHandler {
  return new BlockHandler(logger);
}
