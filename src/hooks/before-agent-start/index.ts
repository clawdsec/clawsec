/**
 * Before Agent Start Hook
 * Re-exports for the before-agent-start hook
 */

export type { BeforeAgentStartHandlerOptions } from './handler.js';

export {
  createBeforeAgentStartHandler,
  createDefaultBeforeAgentStartHandler,
} from './handler.js';

export {
  SECURITY_CONTEXT_HEADER,
  BASE_SECURITY_INTRO,
  CATEGORY_REMINDERS,
  BLOCKED_ACTION_INSTRUCTIONS,
  SECURITY_CONTEXT_FOOTER,
  getAgentConfirmInstructions,
  getEnabledCategoryReminders,
  buildSecurityContextPrompt,
} from './prompts.js';
