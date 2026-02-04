/**
 * Before Agent Start Hook - Prompt Templates
 *
 * Templates for security context injection into agent system prompts.
 */

import type { ClawsecConfig } from '../../config/schema.js';

/**
 * Security context header
 */
export const SECURITY_CONTEXT_HEADER = '[CLAWSEC SECURITY CONTEXT]';

/**
 * Base security introduction
 */
export const BASE_SECURITY_INTRO = 'This session has security protections enabled:';

/**
 * Category-specific security reminders
 */
export const CATEGORY_REMINDERS = {
  purchase: '- Purchase Protection: Transactions require approval',
  destructive: '- Destructive Commands: Commands like rm -rf, DROP TABLE are monitored',
  secrets: '- Secrets Detection: API keys and credentials in outputs are filtered',
  website: '- Website Control: Some domains may be restricted',
  exfiltration: '- Data Exfiltration: Outbound data transfers are monitored',
} as const;

/**
 * Instructions for when actions are blocked
 */
export const BLOCKED_ACTION_INSTRUCTIONS = `If an action is blocked:
1. You'll receive a message explaining why
2. For confirmable actions, retry with _clawsec_confirm="<approval-id>"
3. Some actions cannot be approved and are permanently blocked`;

/**
 * Custom agent-confirm instructions with parameter name
 */
export function getAgentConfirmInstructions(parameterName: string): string {
  return `If an action is blocked:
1. You'll receive a message explaining why
2. For confirmable actions, retry with ${parameterName}="<approval-id>"
3. Some actions cannot be approved and are permanently blocked`;
}

/**
 * Footer for the security context
 */
export const SECURITY_CONTEXT_FOOTER = 'Work safely within these protections.';

/**
 * Get enabled category reminders based on config
 */
export function getEnabledCategoryReminders(config: ClawsecConfig): string[] {
  const reminders: string[] = [];
  const rules = config.rules;

  if (rules?.purchase?.enabled) {
    reminders.push(CATEGORY_REMINDERS.purchase);
  }
  if (rules?.destructive?.enabled) {
    reminders.push(CATEGORY_REMINDERS.destructive);
  }
  if (rules?.secrets?.enabled) {
    reminders.push(CATEGORY_REMINDERS.secrets);
  }
  if (rules?.website?.enabled) {
    reminders.push(CATEGORY_REMINDERS.website);
  }
  if (rules?.exfiltration?.enabled) {
    reminders.push(CATEGORY_REMINDERS.exfiltration);
  }

  return reminders;
}

/**
 * Build the full security context prompt
 *
 * @param config - Clawsec configuration
 * @returns The complete security context prompt or undefined if no protections enabled
 */
export function buildSecurityContextPrompt(config: ClawsecConfig): string | undefined {
  // Check if plugin is globally enabled
  if (config.global?.enabled === false) {
    return undefined;
  }

  // Get enabled category reminders
  const reminders = getEnabledCategoryReminders(config);

  // If no categories are enabled, return undefined
  if (reminders.length === 0) {
    return undefined;
  }

  // Build the prompt sections
  const sections: string[] = [
    SECURITY_CONTEXT_HEADER,
    '',
    BASE_SECURITY_INTRO,
    '',
    ...reminders,
  ];

  // Add agent-confirm instructions if enabled
  if (config.approval?.agentConfirm?.enabled !== false) {
    const parameterName = config.approval?.agentConfirm?.parameterName ?? '_clawsec_confirm';
    sections.push('');
    sections.push(getAgentConfirmInstructions(parameterName));
  }

  // Add footer
  sections.push('');
  sections.push(SECURITY_CONTEXT_FOOTER);

  return sections.join('\n');
}
