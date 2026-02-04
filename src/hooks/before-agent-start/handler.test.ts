/**
 * Tests for the Before Agent Start Hook Handler
 */

import { describe, it, expect } from 'vitest';
import {
  createBeforeAgentStartHandler,
  createDefaultBeforeAgentStartHandler,
  buildSecurityContextPrompt,
  getEnabledCategoryReminders,
  SECURITY_CONTEXT_HEADER,
  BASE_SECURITY_INTRO,
  CATEGORY_REMINDERS,
  SECURITY_CONTEXT_FOOTER,
} from './index.js';
import type { AgentStartContext } from '../../index.js';
import type { ClawsecConfig } from '../../config/schema.js';

// =============================================================================
// TEST HELPERS
// =============================================================================

/**
 * Create a test Clawsec configuration
 */
function createTestConfig(overrides: Partial<ClawsecConfig> = {}): ClawsecConfig {
  return {
    version: '1.0',
    global: {
      enabled: true,
      logLevel: 'info',
    },
    llm: {
      enabled: false,
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
      native: {
        enabled: true,
        timeout: 300,
      },
      agentConfirm: {
        enabled: true,
        parameterName: '_clawsec_confirm',
      },
      webhook: {
        enabled: false,
        timeout: 30,
        headers: {},
      },
    },
    ...overrides,
  };
}

/**
 * Create a test agent start context
 */
function createTestContext(
  overrides: Partial<AgentStartContext> = {}
): AgentStartContext {
  return {
    sessionId: 'test-session-123',
    timestamp: Date.now(),
    ...overrides,
  };
}

// =============================================================================
// TESTS
// =============================================================================

describe('BeforeAgentStartHandler', () => {
  // ===========================================================================
  // FULL PROMPT GENERATION
  // ===========================================================================

  describe('Full prompt generation', () => {
    it('should generate complete security context prompt with all rules enabled', async () => {
      const config = createTestConfig();
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      expect(result.systemPromptAddition).toBeDefined();
      expect(result.systemPromptAddition).toContain(SECURITY_CONTEXT_HEADER);
      expect(result.systemPromptAddition).toContain(BASE_SECURITY_INTRO);
      expect(result.systemPromptAddition).toContain(CATEGORY_REMINDERS.purchase);
      expect(result.systemPromptAddition).toContain(CATEGORY_REMINDERS.destructive);
      expect(result.systemPromptAddition).toContain(CATEGORY_REMINDERS.secrets);
      expect(result.systemPromptAddition).toContain(CATEGORY_REMINDERS.website);
      expect(result.systemPromptAddition).toContain(CATEGORY_REMINDERS.exfiltration);
      expect(result.systemPromptAddition).toContain(SECURITY_CONTEXT_FOOTER);
    });

    it('should include all sections in correct order', async () => {
      const config = createTestConfig();
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);
      const prompt = result.systemPromptAddition!;

      // Check order: header -> intro -> reminders -> instructions -> footer
      const headerIndex = prompt.indexOf(SECURITY_CONTEXT_HEADER);
      const introIndex = prompt.indexOf(BASE_SECURITY_INTRO);
      const purchaseIndex = prompt.indexOf(CATEGORY_REMINDERS.purchase);
      const footerIndex = prompt.indexOf(SECURITY_CONTEXT_FOOTER);

      expect(headerIndex).toBeLessThan(introIndex);
      expect(introIndex).toBeLessThan(purchaseIndex);
      expect(purchaseIndex).toBeLessThan(footerIndex);
    });

    it('should generate prompt with default config values', async () => {
      const handler = createDefaultBeforeAgentStartHandler();
      const context = createTestContext();

      const result = await handler(context);

      expect(result.systemPromptAddition).toBeDefined();
      expect(result.systemPromptAddition).toContain(SECURITY_CONTEXT_HEADER);
    });
  });

  // ===========================================================================
  // PER-CATEGORY ENABLE/DISABLE
  // ===========================================================================

  describe('Per-category enable/disable', () => {
    it('should only include purchase reminder when purchase rule enabled', async () => {
      const config = createTestConfig({
        rules: {
          purchase: {
            enabled: true,
            severity: 'critical',
            action: 'block',
            spendLimits: { perTransaction: 100, daily: 500 },
            domains: { mode: 'blocklist', blocklist: [] },
          },
          website: {
            enabled: false,
            mode: 'blocklist',
            severity: 'high',
            action: 'block',
            blocklist: [],
            allowlist: [],
          },
          destructive: {
            enabled: false,
            severity: 'critical',
            action: 'confirm',
            shell: { enabled: true },
            cloud: { enabled: true },
            code: { enabled: true },
          },
          secrets: {
            enabled: false,
            severity: 'critical',
            action: 'block',
          },
          exfiltration: {
            enabled: false,
            severity: 'high',
            action: 'block',
          },
        },
      });
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      expect(result.systemPromptAddition).toContain(CATEGORY_REMINDERS.purchase);
      expect(result.systemPromptAddition).not.toContain(CATEGORY_REMINDERS.website);
      expect(result.systemPromptAddition).not.toContain(CATEGORY_REMINDERS.destructive);
      expect(result.systemPromptAddition).not.toContain(CATEGORY_REMINDERS.secrets);
      expect(result.systemPromptAddition).not.toContain(CATEGORY_REMINDERS.exfiltration);
    });

    it('should only include destructive reminder when destructive rule enabled', async () => {
      const config = createTestConfig({
        rules: {
          purchase: {
            enabled: false,
            severity: 'critical',
            action: 'block',
            spendLimits: { perTransaction: 100, daily: 500 },
            domains: { mode: 'blocklist', blocklist: [] },
          },
          website: {
            enabled: false,
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
            enabled: false,
            severity: 'critical',
            action: 'block',
          },
          exfiltration: {
            enabled: false,
            severity: 'high',
            action: 'block',
          },
        },
      });
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      expect(result.systemPromptAddition).toContain(CATEGORY_REMINDERS.destructive);
      expect(result.systemPromptAddition).not.toContain(CATEGORY_REMINDERS.purchase);
    });

    it('should only include secrets reminder when secrets rule enabled', async () => {
      const config = createTestConfig({
        rules: {
          purchase: {
            enabled: false,
            severity: 'critical',
            action: 'block',
            spendLimits: { perTransaction: 100, daily: 500 },
            domains: { mode: 'blocklist', blocklist: [] },
          },
          website: {
            enabled: false,
            mode: 'blocklist',
            severity: 'high',
            action: 'block',
            blocklist: [],
            allowlist: [],
          },
          destructive: {
            enabled: false,
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
            enabled: false,
            severity: 'high',
            action: 'block',
          },
        },
      });
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      expect(result.systemPromptAddition).toContain(CATEGORY_REMINDERS.secrets);
      expect(result.systemPromptAddition).not.toContain(CATEGORY_REMINDERS.purchase);
    });

    it('should include multiple reminders when multiple rules enabled', async () => {
      const config = createTestConfig({
        rules: {
          purchase: {
            enabled: true,
            severity: 'critical',
            action: 'block',
            spendLimits: { perTransaction: 100, daily: 500 },
            domains: { mode: 'blocklist', blocklist: [] },
          },
          website: {
            enabled: false,
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
            enabled: false,
            severity: 'critical',
            action: 'block',
          },
          exfiltration: {
            enabled: true,
            severity: 'high',
            action: 'block',
          },
        },
      });
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      expect(result.systemPromptAddition).toContain(CATEGORY_REMINDERS.purchase);
      expect(result.systemPromptAddition).toContain(CATEGORY_REMINDERS.destructive);
      expect(result.systemPromptAddition).toContain(CATEGORY_REMINDERS.exfiltration);
      expect(result.systemPromptAddition).not.toContain(CATEGORY_REMINDERS.website);
      expect(result.systemPromptAddition).not.toContain(CATEGORY_REMINDERS.secrets);
    });
  });

  // ===========================================================================
  // PLUGIN DISABLED
  // ===========================================================================

  describe('Plugin disabled', () => {
    it('should return empty result when plugin is globally disabled', async () => {
      const config = createTestConfig({
        global: { enabled: false, logLevel: 'info' },
      });
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      expect(result.systemPromptAddition).toBeUndefined();
    });

    it('should return empty result when prompt injection is disabled via options', async () => {
      const config = createTestConfig();
      const handler = createBeforeAgentStartHandler(config, { injectPrompt: false });
      const context = createTestContext();

      const result = await handler(context);

      expect(result.systemPromptAddition).toBeUndefined();
    });
  });

  // ===========================================================================
  // AGENT-CONFIRM INSTRUCTIONS
  // ===========================================================================

  describe('Agent-confirm instructions', () => {
    it('should include agent-confirm instructions when enabled', async () => {
      const config = createTestConfig({
        approval: {
          native: { enabled: true, timeout: 300 },
          agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
          webhook: { enabled: false, timeout: 30, headers: {} },
        },
      });
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      expect(result.systemPromptAddition).toContain('_clawsec_confirm');
      expect(result.systemPromptAddition).toContain('approval-id');
      expect(result.systemPromptAddition).toContain('confirmable actions');
    });

    it('should use custom parameter name in instructions', async () => {
      const config = createTestConfig({
        approval: {
          native: { enabled: true, timeout: 300 },
          agentConfirm: { enabled: true, parameterName: '_custom_approve' },
          webhook: { enabled: false, timeout: 30, headers: {} },
        },
      });
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      expect(result.systemPromptAddition).toContain('_custom_approve');
      expect(result.systemPromptAddition).not.toContain('_clawsec_confirm');
    });

    it('should not include agent-confirm instructions when disabled', async () => {
      const config = createTestConfig({
        approval: {
          native: { enabled: true, timeout: 300 },
          agentConfirm: { enabled: false, parameterName: '_clawsec_confirm' },
          webhook: { enabled: false, timeout: 30, headers: {} },
        },
      });
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      // Should still have the prompt but without agent-confirm instructions
      expect(result.systemPromptAddition).toBeDefined();
      expect(result.systemPromptAddition).not.toContain('_clawsec_confirm');
      expect(result.systemPromptAddition).not.toContain('confirmable actions');
    });
  });

  // ===========================================================================
  // EMPTY PROMPT WHEN ALL RULES DISABLED
  // ===========================================================================

  describe('Empty prompt when all rules disabled', () => {
    it('should return empty result when all rules are disabled', async () => {
      const config = createTestConfig({
        rules: {
          purchase: {
            enabled: false,
            severity: 'critical',
            action: 'block',
            spendLimits: { perTransaction: 100, daily: 500 },
            domains: { mode: 'blocklist', blocklist: [] },
          },
          website: {
            enabled: false,
            mode: 'blocklist',
            severity: 'high',
            action: 'block',
            blocklist: [],
            allowlist: [],
          },
          destructive: {
            enabled: false,
            severity: 'critical',
            action: 'confirm',
            shell: { enabled: true },
            cloud: { enabled: true },
            code: { enabled: true },
          },
          secrets: {
            enabled: false,
            severity: 'critical',
            action: 'block',
          },
          exfiltration: {
            enabled: false,
            severity: 'high',
            action: 'block',
          },
        },
      });
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      expect(result.systemPromptAddition).toBeUndefined();
    });

    it('should return empty modifiedConfig when not provided', async () => {
      const config = createTestConfig();
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      expect(result.modifiedConfig).toBeUndefined();
    });
  });

  // ===========================================================================
  // CONTEXT HANDLING
  // ===========================================================================

  describe('Context handling', () => {
    it('should handle context with userId', async () => {
      const config = createTestConfig();
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext({
        userId: 'user-123',
      });

      const result = await handler(context);

      expect(result.systemPromptAddition).toBeDefined();
    });

    it('should handle context with systemPrompt', async () => {
      const config = createTestConfig();
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext({
        systemPrompt: 'You are a helpful assistant.',
      });

      const result = await handler(context);

      expect(result.systemPromptAddition).toBeDefined();
    });

    it('should handle context with agentConfig', async () => {
      const config = createTestConfig();
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext({
        agentConfig: { temperature: 0.7, maxTokens: 1000 },
      });

      const result = await handler(context);

      expect(result.systemPromptAddition).toBeDefined();
    });
  });

  // ===========================================================================
  // PROMPT HELPERS
  // ===========================================================================

  describe('Prompt helpers', () => {
    describe('getEnabledCategoryReminders', () => {
      it('should return all reminders when all rules enabled', () => {
        const config = createTestConfig();
        const reminders = getEnabledCategoryReminders(config);

        expect(reminders).toHaveLength(5);
        expect(reminders).toContain(CATEGORY_REMINDERS.purchase);
        expect(reminders).toContain(CATEGORY_REMINDERS.destructive);
        expect(reminders).toContain(CATEGORY_REMINDERS.secrets);
        expect(reminders).toContain(CATEGORY_REMINDERS.website);
        expect(reminders).toContain(CATEGORY_REMINDERS.exfiltration);
      });

      it('should return empty array when all rules disabled', () => {
        const config = createTestConfig({
          rules: {
            purchase: {
              enabled: false,
              severity: 'critical',
              action: 'block',
              spendLimits: { perTransaction: 100, daily: 500 },
              domains: { mode: 'blocklist', blocklist: [] },
            },
            website: {
              enabled: false,
              mode: 'blocklist',
              severity: 'high',
              action: 'block',
              blocklist: [],
              allowlist: [],
            },
            destructive: {
              enabled: false,
              severity: 'critical',
              action: 'confirm',
              shell: { enabled: true },
              cloud: { enabled: true },
              code: { enabled: true },
            },
            secrets: {
              enabled: false,
              severity: 'critical',
              action: 'block',
            },
            exfiltration: {
              enabled: false,
              severity: 'high',
              action: 'block',
            },
          },
        });
        const reminders = getEnabledCategoryReminders(config);

        expect(reminders).toHaveLength(0);
      });

      it('should return only enabled reminders', () => {
        const config = createTestConfig({
          rules: {
            purchase: {
              enabled: true,
              severity: 'critical',
              action: 'block',
              spendLimits: { perTransaction: 100, daily: 500 },
              domains: { mode: 'blocklist', blocklist: [] },
            },
            website: {
              enabled: false,
              mode: 'blocklist',
              severity: 'high',
              action: 'block',
              blocklist: [],
              allowlist: [],
            },
            destructive: {
              enabled: false,
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
              enabled: false,
              severity: 'high',
              action: 'block',
            },
          },
        });
        const reminders = getEnabledCategoryReminders(config);

        expect(reminders).toHaveLength(2);
        expect(reminders).toContain(CATEGORY_REMINDERS.purchase);
        expect(reminders).toContain(CATEGORY_REMINDERS.secrets);
      });
    });

    describe('buildSecurityContextPrompt', () => {
      it('should return undefined when plugin disabled', () => {
        const config = createTestConfig({
          global: { enabled: false, logLevel: 'info' },
        });
        const prompt = buildSecurityContextPrompt(config);

        expect(prompt).toBeUndefined();
      });

      it('should return undefined when no rules enabled', () => {
        const config = createTestConfig({
          rules: {
            purchase: {
              enabled: false,
              severity: 'critical',
              action: 'block',
              spendLimits: { perTransaction: 100, daily: 500 },
              domains: { mode: 'blocklist', blocklist: [] },
            },
            website: {
              enabled: false,
              mode: 'blocklist',
              severity: 'high',
              action: 'block',
              blocklist: [],
              allowlist: [],
            },
            destructive: {
              enabled: false,
              severity: 'critical',
              action: 'confirm',
              shell: { enabled: true },
              cloud: { enabled: true },
              code: { enabled: true },
            },
            secrets: {
              enabled: false,
              severity: 'critical',
              action: 'block',
            },
            exfiltration: {
              enabled: false,
              severity: 'high',
              action: 'block',
            },
          },
        });
        const prompt = buildSecurityContextPrompt(config);

        expect(prompt).toBeUndefined();
      });

      it('should build complete prompt with all sections', () => {
        const config = createTestConfig();
        const prompt = buildSecurityContextPrompt(config)!;

        expect(prompt).toContain(SECURITY_CONTEXT_HEADER);
        expect(prompt).toContain(BASE_SECURITY_INTRO);
        expect(prompt).toContain(SECURITY_CONTEXT_FOOTER);
      });
    });
  });

  // ===========================================================================
  // DEFAULT HANDLER
  // ===========================================================================

  describe('createDefaultBeforeAgentStartHandler', () => {
    it('should create handler with default config', async () => {
      const handler = createDefaultBeforeAgentStartHandler();

      expect(typeof handler).toBe('function');
    });

    it('should return valid result', async () => {
      const handler = createDefaultBeforeAgentStartHandler();
      const context = createTestContext();

      const result = await handler(context);

      expect(result).toHaveProperty('systemPromptAddition');
      expect(result.systemPromptAddition).toContain(SECURITY_CONTEXT_HEADER);
    });
  });

  // ===========================================================================
  // EDGE CASES
  // ===========================================================================

  describe('Edge cases', () => {
    it('should handle undefined rules gracefully', async () => {
      const config: ClawsecConfig = {
        version: '1.0',
        global: { enabled: true, logLevel: 'info' },
        llm: { enabled: false, model: null },
        rules: undefined as unknown as ClawsecConfig['rules'],
        approval: {
          native: { enabled: true, timeout: 300 },
          agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
          webhook: { enabled: false, timeout: 30, headers: {} },
        },
      };
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      expect(result.systemPromptAddition).toBeUndefined();
    });

    it('should handle undefined approval gracefully', async () => {
      const config: ClawsecConfig = {
        version: '1.0',
        global: { enabled: true, logLevel: 'info' },
        llm: { enabled: false, model: null },
        rules: {
          purchase: {
            enabled: true,
            severity: 'critical',
            action: 'block',
            spendLimits: { perTransaction: 100, daily: 500 },
            domains: { mode: 'blocklist', blocklist: [] },
          },
          website: {
            enabled: false,
            mode: 'blocklist',
            severity: 'high',
            action: 'block',
            blocklist: [],
            allowlist: [],
          },
          destructive: {
            enabled: false,
            severity: 'critical',
            action: 'confirm',
            shell: { enabled: true },
            cloud: { enabled: true },
            code: { enabled: true },
          },
          secrets: {
            enabled: false,
            severity: 'critical',
            action: 'block',
          },
          exfiltration: {
            enabled: false,
            severity: 'high',
            action: 'block',
          },
        },
        approval: undefined as unknown as ClawsecConfig['approval'],
      };
      const handler = createBeforeAgentStartHandler(config);
      const context = createTestContext();

      const result = await handler(context);

      // Should still work with default agent-confirm parameter
      expect(result.systemPromptAddition).toBeDefined();
      expect(result.systemPromptAddition).toContain('_clawsec_confirm');
    });

    it('should handle empty context', async () => {
      const config = createTestConfig();
      const handler = createBeforeAgentStartHandler(config);
      const context: AgentStartContext = {
        sessionId: '',
        timestamp: 0,
      };

      const result = await handler(context);

      expect(result.systemPromptAddition).toBeDefined();
    });
  });
});
