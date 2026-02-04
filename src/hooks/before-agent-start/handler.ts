/**
 * Before Agent Start Hook Handler
 *
 * Hook handler that injects security context into the agent's system prompt
 * when an agent session starts.
 */

import type {
  AgentStartContext,
  BeforeAgentStartResult,
  BeforeAgentStartHandler,
} from '../../index.js';
import type { ClawsecConfig } from '../../config/schema.js';
import { buildSecurityContextPrompt } from './prompts.js';

/**
 * Options for creating a before-agent-start handler
 */
export interface BeforeAgentStartHandlerOptions {
  /**
   * Whether to inject security context into the system prompt
   * @default true
   */
  injectPrompt?: boolean;
}

/**
 * Create the before-agent-start handler
 *
 * This handler runs when an agent session starts and injects security context
 * into the system prompt to help the agent understand:
 * - What security protections are active
 * - How to handle blocked actions
 * - How to use agent-confirm for acknowledged risks
 *
 * @param config - Clawsec configuration
 * @param options - Optional handler options
 * @returns BeforeAgentStartHandler function
 */
export function createBeforeAgentStartHandler(
  config: ClawsecConfig,
  options?: BeforeAgentStartHandlerOptions
): BeforeAgentStartHandler {
  const injectPrompt = options?.injectPrompt ?? true;

  return async (_context: AgentStartContext): Promise<BeforeAgentStartResult> => {
    // If prompt injection is disabled via options, return empty result
    if (!injectPrompt) {
      return {};
    }

    // Build the security context prompt based on config
    const systemPromptAddition = buildSecurityContextPrompt(config);

    // Return the result with the prompt addition (if any)
    if (systemPromptAddition) {
      return {
        systemPromptAddition,
      };
    }

    return {};
  };
}

/**
 * Create a default before-agent-start handler with default configuration
 */
export function createDefaultBeforeAgentStartHandler(): BeforeAgentStartHandler {
  const defaultConfig: ClawsecConfig = {
    version: '1.0',
    global: {
      enabled: true,
      logLevel: 'info',
    },
    llm: {
      enabled: true,
      model: null,
    },
    rules: {
      purchase: {
        enabled: true,
        severity: 'critical',
        action: 'block',
        spendLimits: { perTransaction: 100, daily: 500 },
        domains: { mode: 'blocklist', blocklist: [] },
      },
      website: {
        enabled: true,
        mode: 'blocklist',
        severity: 'high',
        action: 'block',
        blocklist: [],
        allowlist: [],
      },
      destructive: {
        enabled: true,
        severity: 'critical',
        action: 'confirm',
        shell: { enabled: true },
        cloud: { enabled: true },
        code: { enabled: true },
      },
      secrets: {
        enabled: true,
        severity: 'critical',
        action: 'block',
      },
      exfiltration: {
        enabled: true,
        severity: 'high',
        action: 'block',
      },
    },
    approval: {
      native: { enabled: true, timeout: 300 },
      agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
      webhook: { enabled: false, url: undefined, timeout: 30, headers: {} },
    },
  };

  return createBeforeAgentStartHandler(defaultConfig);
}
