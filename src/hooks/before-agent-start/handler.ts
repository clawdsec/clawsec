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
import { createLogger, type Logger } from '../../utils/logger.js';

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
 * @param logger - Optional logger instance
 * @returns BeforeAgentStartHandler function
 */
export function createBeforeAgentStartHandler(
  config: ClawsecConfig,
  options?: BeforeAgentStartHandlerOptions,
  logger?: Logger
): BeforeAgentStartHandler {
  const log = logger ?? createLogger(null, null);
  const injectPrompt = options?.injectPrompt ?? true;

  // Track which sessions have already received security context
  const injectedSessions = new Set<string>();

  return async (context: AgentStartContext): Promise<BeforeAgentStartResult> => {
    try {
      // Normalize context: Extract/generate sessionId if missing
      let sessionId: string | undefined = context.sessionId;

      if (!sessionId && context.messages && context.messages.length > 0) {
        // Try to extract from first message timestamp
        const firstMsg = context.messages[0];
        sessionId = `session_${firstMsg.timestamp || Date.now()}`;
      } else if (!sessionId) {
        // Generate from current timestamp
        sessionId = `session_${context.timestamp || Date.now()}`;
      }

      // Validate we have essential data
      if (!context || !sessionId) {
        log.error(`[Hook:before-agent-start] Invalid context received`, context);
        return {}; // Fail-open for invalid context
      }

      log.info(`[Hook:before-agent-start] Entry: session=${sessionId}`);

      // CHECK: If already injected for this session, return empty result
      if (injectedSessions.has(sessionId)) {
        log.debug(`[Hook:before-agent-start] Security context already injected for session=${sessionId}, skipping`);
        return {}; // Empty result - no re-injection
      }

      // If prompt injection is disabled via options, return empty result
      if (!injectPrompt) {
        log.info(`[Hook:before-agent-start] Prompt injection disabled`);
        return {};
      }

      // Build the security context prompt based on config
      let prependContext: string | undefined;
      try {
        prependContext = buildSecurityContextPrompt(config);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error(`[Hook:before-agent-start] Error building prompt: ${errorMessage}`, error);
        return {}; // Fail-open: allow agent to start without security context
      }

      // Return the result with prependContext (OpenClaw's actual API field)
      if (prependContext) {
        injectedSessions.add(sessionId); // Mark this session as injected
        log.info(`[Hook:before-agent-start] Exit: session=${sessionId}, injected=${prependContext.length} chars`);
        return {
          prependContext,
        };
      }

      log.info(`[Hook:before-agent-start] Exit: session=${sessionId}, no prompt (rules disabled)`);
      return {};
    } catch (error) {
      // Top-level catch for any unexpected errors
      const errorMessage = error instanceof Error ? error.message : String(error);
      log.error(`[Hook:before-agent-start] Unhandled error: ${errorMessage}`, error);
      return {}; // Fail-open: allow agent to start without security context
    }
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
      sanitization: {
        enabled: true,
        severity: 'high',
        action: 'block',
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
  };

  return createBeforeAgentStartHandler(defaultConfig);
}
