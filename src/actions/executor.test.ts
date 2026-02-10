/**
 * Tests for the Action Executor Module
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createActionExecutor,
  createDefaultActionExecutor,
  DefaultActionExecutor,
  BlockHandler,
  ConfirmHandler,
  WarnHandler,
  LogHandler,
  createBlockHandler,
  createConfirmHandler,
  createWarnHandler,
  createLogHandler,
  generateBlockMessage,
  generateConfirmMessage,
  generateWarnMessage,
  generateApprovalId,
  getEnabledApprovalMethods,
  getApprovalTimeout,
  noOpLogger,
  createLogger,
  consoleLogger,
} from './index.js';
import type { ActionContext, ActionResult, ActionLogger, PendingApproval } from './types.js';
import type { ClawsecConfig } from '../config/index.js';
import type { AnalysisResult, ToolCallContext, Detection } from '../engine/types.js';

// =============================================================================
// TEST HELPERS
// =============================================================================

/**
 * Create a test configuration
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
 * Create a test tool call context
 */
function createTestToolCall(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    toolName: 'test_tool',
    toolInput: { arg: 'value' },
    ...overrides,
  };
}

/**
 * Create a test detection
 */
function createTestDetection(overrides: Partial<Detection> = {}): Detection {
  return {
    category: 'destructive',
    severity: 'critical',
    confidence: 0.95,
    reason: 'Detected rm -rf command which could delete files',
    ...overrides,
  };
}

/**
 * Create a test analysis result
 */
function createTestAnalysis(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  const detection = createTestDetection();
  return {
    action: 'block',
    detections: [detection],
    primaryDetection: detection,
    requiresLLM: false,
    cached: false,
    ...overrides,
  };
}

/**
 * Create a test action context
 */
function createTestContext(overrides: {
  analysis?: Partial<AnalysisResult>;
  toolCall?: Partial<ToolCallContext>;
  config?: Partial<ClawsecConfig>;
} = {}): ActionContext {
  return {
    analysis: createTestAnalysis(overrides.analysis),
    toolCall: createTestToolCall(overrides.toolCall),
    config: createTestConfig(overrides.config),
  };
}

/**
 * Create a mock logger that tracks calls
 */
function createMockLogger(): ActionLogger & { calls: Record<string, Array<[string, Record<string, unknown>?]>> } {
  const calls: Record<string, Array<[string, Record<string, unknown>?]>> = {
    debug: [],
    info: [],
    warn: [],
    error: [],
  };

  return {
    calls,
    debug: (message, data) => calls.debug.push([message, data]),
    info: (message, data) => calls.info.push([message, data]),
    warn: (message, data) => calls.warn.push([message, data]),
    error: (message, data) => calls.error.push([message, data]),
  };
}

// =============================================================================
// BLOCK HANDLER TESTS
// =============================================================================

describe('BlockHandler', () => {
  describe('execute', () => {
    it('should return allowed: false', async () => {
      const handler = createBlockHandler();
      const context = createTestContext();

      const result = await handler.execute(context);

      expect(result.allowed).toBe(false);
      expect(result.logged).toBe(true);
    });

    it('should include message with detection details', async () => {
      const handler = createBlockHandler();
      const context = createTestContext({
        analysis: {
          primaryDetection: createTestDetection({
            category: 'secrets',
            severity: 'critical',
            reason: 'API key detected in output',
          }),
        },
      });

      const result = await handler.execute(context);

      expect(result.message).toContain('CRITICAL');
      expect(result.message).toContain('Secrets/PII Exposure');
      expect(result.message).toContain('API key detected in output');
    });

    it('should log the block event', async () => {
      const mockLogger = createMockLogger();
      const handler = createBlockHandler(mockLogger);
      const context = createTestContext();

      await handler.execute(context);

      expect(mockLogger.calls.warn.length).toBe(1);
      expect(mockLogger.calls.warn[0][0]).toBe('Action blocked');
      expect(mockLogger.calls.warn[0][1]).toHaveProperty('toolName', 'test_tool');
    });

    it('should handle context without primary detection', async () => {
      const handler = createBlockHandler();
      const context = createTestContext({
        analysis: {
          action: 'block',
          detections: [],
          primaryDetection: undefined,
        },
      });

      const result = await handler.execute(context);

      expect(result.allowed).toBe(false);
      expect(result.message).toContain('blocked by security policy');
    });

    it('should include additional detections in message', async () => {
      const handler = createBlockHandler();
      const primaryDetection = createTestDetection({ category: 'destructive' });
      const additionalDetection = createTestDetection({
        category: 'exfiltration',
        reason: 'Uploading to external server',
      });

      const context = createTestContext({
        analysis: {
          detections: [primaryDetection, additionalDetection],
          primaryDetection,
        },
      });

      const result = await handler.execute(context);

      expect(result.message).toContain('Additional detections');
      expect(result.message).toContain('Data Exfiltration');
      expect(result.message).toContain('Uploading to external server');
    });
  });

  describe('generateBlockMessage', () => {
    it('should format severity correctly', () => {
      const context = createTestContext({
        analysis: {
          primaryDetection: createTestDetection({ severity: 'high' }),
        },
      });

      const message = generateBlockMessage(context);

      expect(message).toContain('[HIGH]');
    });

    it('should format all category types', () => {
      const categories = ['purchase', 'website', 'destructive', 'secrets', 'exfiltration'] as const;
      const expectedNames = ['Purchase/Payment', 'Malicious Website', 'Destructive Command', 'Secrets/PII Exposure', 'Data Exfiltration'];

      for (let i = 0; i < categories.length; i++) {
        const context = createTestContext({
          analysis: {
            primaryDetection: createTestDetection({ category: categories[i] }),
          },
        });

        const message = generateBlockMessage(context);
        expect(message).toContain(expectedNames[i]);
      }
    });
  });
});

// =============================================================================
// CONFIRM HANDLER TESTS
// =============================================================================

describe('ConfirmHandler', () => {
  describe('execute', () => {
    it('should return allowed: false with pendingApproval', async () => {
      const handler = createConfirmHandler();
      const context = createTestContext({ analysis: { action: 'confirm' } });

      const result = await handler.execute(context);

      expect(result.allowed).toBe(false);
      expect(result.pendingApproval).toBeDefined();
      expect(result.logged).toBe(true);
    });

    it('should generate unique approval ID', async () => {
      const handler = createConfirmHandler();
      const context = createTestContext({ analysis: { action: 'confirm' } });

      const result1 = await handler.execute(context);
      const result2 = await handler.execute(context);

      expect(result1.pendingApproval?.id).toBeDefined();
      expect(result2.pendingApproval?.id).toBeDefined();
      expect(result1.pendingApproval?.id).not.toBe(result2.pendingApproval?.id);
    });

    it('should include enabled approval methods', async () => {
      const handler = createConfirmHandler();
      const context = createTestContext({ analysis: { action: 'confirm' } });

      const result = await handler.execute(context);

      expect(result.pendingApproval?.methods).toContain('native');
      expect(result.pendingApproval?.methods).toContain('agent-confirm');
      expect(result.pendingApproval?.methods).not.toContain('webhook');
    });

    it('should include webhook when enabled with URL', async () => {
      const handler = createConfirmHandler();
      const context = createTestContext({
        analysis: { action: 'confirm' },
        config: {
          approval: {
            native: { enabled: true, timeout: 300 },
            agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
            webhook: {
              enabled: true,
              url: 'https://example.com/approve',
              timeout: 30,
              headers: {},
            },
          },
        },
      });

      const result = await handler.execute(context);

      expect(result.pendingApproval?.methods).toContain('webhook');
    });

    it('should include timeout from config', async () => {
      const handler = createConfirmHandler();
      const context = createTestContext({
        analysis: { action: 'confirm' },
        config: {
          approval: {
            native: { enabled: true, timeout: 600 },
            agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
            webhook: { enabled: false, timeout: 30, headers: {} },
          },
        },
      });

      const result = await handler.execute(context);

      expect(result.pendingApproval?.timeout).toBe(600);
    });

    it('should include approval instructions in message', async () => {
      const handler = createConfirmHandler();
      const context = createTestContext({ analysis: { action: 'confirm' } });

      const result = await handler.execute(context);

      expect(result.message).toContain('_clawsec_confirm');
    });

    it('should log the confirmation request', async () => {
      const mockLogger = createMockLogger();
      const handler = createConfirmHandler(mockLogger);
      const context = createTestContext({ analysis: { action: 'confirm' } });

      await handler.execute(context);

      expect(mockLogger.calls.info.length).toBe(1);
      expect(mockLogger.calls.info[0][0]).toBe('Action requires approval');
    });
  });

  describe('generateApprovalId', () => {
    it('should generate valid UUID format', () => {
      const id = generateApprovalId();

      // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(id).toMatch(uuidRegex);
    });

    it('should generate unique IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateApprovalId());
      }
      expect(ids.size).toBe(100);
    });
  });

  describe('getEnabledApprovalMethods', () => {
    it('should return all enabled methods', () => {
      const context = createTestContext({
        config: {
          approval: {
            native: { enabled: true, timeout: 300 },
            agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
            webhook: { enabled: true, url: 'https://example.com', timeout: 30, headers: {} },
          },
        },
      });

      const methods = getEnabledApprovalMethods(context);

      expect(methods).toContain('native');
      expect(methods).toContain('agent-confirm');
      expect(methods).toContain('webhook');
    });

    it('should exclude disabled methods', () => {
      const context = createTestContext({
        config: {
          approval: {
            native: { enabled: false, timeout: 300 },
            agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
            webhook: { enabled: false, timeout: 30, headers: {} },
          },
        },
      });

      const methods = getEnabledApprovalMethods(context);

      expect(methods).not.toContain('native');
      expect(methods).toContain('agent-confirm');
      expect(methods).not.toContain('webhook');
    });

    it('should exclude webhook without URL', () => {
      const context = createTestContext({
        config: {
          approval: {
            native: { enabled: true, timeout: 300 },
            agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
            webhook: { enabled: true, timeout: 30, headers: {} }, // No URL
          },
        },
      });

      const methods = getEnabledApprovalMethods(context);

      expect(methods).not.toContain('webhook');
    });
  });

  describe('getApprovalTimeout', () => {
    it('should return configured timeout', () => {
      const context = createTestContext({
        config: {
          approval: {
            native: { enabled: true, timeout: 600 },
          },
        },
      });

      const timeout = getApprovalTimeout(context);

      expect(timeout).toBe(600);
    });

    it('should return default timeout when not configured', () => {
      const context = createTestContext({
        config: {
          approval: {},
        },
      });

      const timeout = getApprovalTimeout(context);

      expect(timeout).toBe(300); // Default
    });
  });
});

// =============================================================================
// WARN HANDLER TESTS
// =============================================================================

describe('WarnHandler', () => {
  describe('execute', () => {
    it('should return allowed: true', async () => {
      const handler = createWarnHandler();
      const context = createTestContext({ analysis: { action: 'warn' } });

      const result = await handler.execute(context);

      expect(result.allowed).toBe(true);
      expect(result.logged).toBe(true);
    });

    it('should include warning message with detection details', async () => {
      const handler = createWarnHandler();
      const context = createTestContext({
        analysis: {
          action: 'warn',
          primaryDetection: createTestDetection({
            category: 'website',
            severity: 'medium',
            reason: 'Accessing unusual domain',
          }),
        },
      });

      const result = await handler.execute(context);

      expect(result.message).toContain('Warning');
      expect(result.message).toContain('MEDIUM');
      expect(result.message).toContain('Website Access');
      expect(result.message).toContain('Accessing unusual domain');
      expect(result.message).toContain('allowed but logged');
    });

    it('should log the warning', async () => {
      const mockLogger = createMockLogger();
      const handler = createWarnHandler(mockLogger);
      const context = createTestContext({ analysis: { action: 'warn' } });

      await handler.execute(context);

      expect(mockLogger.calls.warn.length).toBe(1);
      expect(mockLogger.calls.warn[0][0]).toBe('Action executed with warning');
    });

    it('should include additional warnings in message', async () => {
      const handler = createWarnHandler();
      const primaryDetection = createTestDetection({ category: 'website' });
      const additionalDetection = createTestDetection({
        category: 'exfiltration',
        reason: 'Large data transfer detected',
      });

      const context = createTestContext({
        analysis: {
          action: 'warn',
          detections: [primaryDetection, additionalDetection],
          primaryDetection,
        },
      });

      const result = await handler.execute(context);

      expect(result.message).toContain('Additional warnings');
      expect(result.message).toContain('Data Transfer');
    });
  });

  describe('generateWarnMessage', () => {
    it('should handle context without primary detection', () => {
      const context = createTestContext({
        analysis: {
          action: 'warn',
          detections: [],
          primaryDetection: undefined,
        },
      });

      const message = generateWarnMessage(context);

      expect(message).toContain('Warning');
      expect(message).toContain('security notice');
    });
  });
});

// =============================================================================
// LOG HANDLER TESTS
// =============================================================================

describe('LogHandler', () => {
  describe('execute', () => {
    it('should return allowed: true', async () => {
      const handler = createLogHandler();
      const context = createTestContext({ analysis: { action: 'log' } });

      const result = await handler.execute(context);

      expect(result.allowed).toBe(true);
      expect(result.logged).toBe(true);
    });

    it('should not include user-visible message', async () => {
      const handler = createLogHandler();
      const context = createTestContext({ analysis: { action: 'log' } });

      const result = await handler.execute(context);

      expect(result.message).toBeUndefined();
    });

    it('should log for audit with detection details', async () => {
      const mockLogger = createMockLogger();
      const handler = createLogHandler(mockLogger);
      const context = createTestContext({
        analysis: {
          action: 'log',
          primaryDetection: createTestDetection({
            category: 'purchase',
            reason: 'Small transaction detected',
          }),
        },
      });

      await handler.execute(context);

      expect(mockLogger.calls.info.length).toBe(1);
      expect(mockLogger.calls.info[0][0]).toBe('Action logged for audit');
      expect(mockLogger.calls.info[0][1]).toHaveProperty('category', 'purchase');
    });

    it('should log debug when no detection', async () => {
      const mockLogger = createMockLogger();
      const handler = createLogHandler(mockLogger);
      const context = createTestContext({
        analysis: {
          action: 'log',
          detections: [],
          primaryDetection: undefined,
        },
      });

      await handler.execute(context);

      expect(mockLogger.calls.debug.length).toBe(1);
      expect(mockLogger.calls.debug[0][0]).toContain('no detections');
    });
  });
});

// =============================================================================
// EXECUTOR TESTS
// =============================================================================

describe('DefaultActionExecutor', () => {
  describe('execute', () => {
    it('should route allow action correctly', async () => {
      const mockLogger = createMockLogger();
      const executor = createActionExecutor({ logger: mockLogger });
      const context = createTestContext({
        analysis: {
          action: 'allow',
          detections: [],
          primaryDetection: undefined,
        },
      });

      const result = await executor.execute(context);

      expect(result.allowed).toBe(true);
      expect(result.logged).toBe(false);
      // Executor now logs: Entry, Routing, handleAllow, Exit = 4 debug calls
      expect(mockLogger.calls.debug.length).toBe(4);
    });

    it('should route block action correctly', async () => {
      const executor = createActionExecutor();
      const context = createTestContext({ analysis: { action: 'block' } });

      const result = await executor.execute(context);

      expect(result.allowed).toBe(false);
      expect(result.message).toBeDefined();
      expect(result.pendingApproval).toBeUndefined();
    });

    it('should route confirm action correctly', async () => {
      const executor = createActionExecutor();
      const context = createTestContext({ analysis: { action: 'confirm' } });

      const result = await executor.execute(context);

      expect(result.allowed).toBe(false);
      expect(result.pendingApproval).toBeDefined();
      expect(result.pendingApproval?.id).toBeDefined();
    });

    it('should route warn action correctly', async () => {
      const executor = createActionExecutor();
      const context = createTestContext({ analysis: { action: 'warn' } });

      const result = await executor.execute(context);

      expect(result.allowed).toBe(true);
      expect(result.message).toContain('Warning');
    });

    it('should route log action correctly', async () => {
      const executor = createActionExecutor();
      const context = createTestContext({ analysis: { action: 'log' } });

      const result = await executor.execute(context);

      expect(result.allowed).toBe(true);
      expect(result.message).toBeUndefined();
    });

    it('should handle disabled plugin', async () => {
      const mockLogger = createMockLogger();
      const executor = createActionExecutor({ logger: mockLogger });
      const context = createTestContext({
        analysis: { action: 'block' },
        config: { global: { enabled: false, logLevel: 'info' } },
      });

      const result = await executor.execute(context);

      expect(result.allowed).toBe(true);
      expect(result.logged).toBe(false);
      // Executor logs: Entry, "Plugin disabled", Exit = 3 debug calls
      expect(mockLogger.calls.debug.length).toBe(3);
      expect(mockLogger.calls.debug[1][0]).toContain('disabled');
    });

    it('should handle unknown action type', async () => {
      const mockLogger = createMockLogger();
      const executor = createActionExecutor({ logger: mockLogger });
      const context = createTestContext({
        analysis: { action: 'unknown' as any },
      });

      const result = await executor.execute(context);

      expect(result.allowed).toBe(true);
      expect(result.logged).toBe(true);
      expect(mockLogger.calls.warn.length).toBe(1);
      expect(mockLogger.calls.warn[0][0]).toContain('Unknown action type');
    });
  });

  describe('custom handlers', () => {
    it('should use custom block handler', async () => {
      const customHandler = {
        execute: vi.fn().mockResolvedValue({
          allowed: false,
          message: 'Custom block message',
          logged: true,
        }),
      };

      const executor = createActionExecutor({ blockHandler: customHandler });
      const context = createTestContext({ analysis: { action: 'block' } });

      const result = await executor.execute(context);

      expect(customHandler.execute).toHaveBeenCalledWith(context);
      expect(result.message).toBe('Custom block message');
    });

    it('should use custom confirm handler', async () => {
      const customHandler = {
        execute: vi.fn().mockResolvedValue({
          allowed: false,
          message: 'Custom confirm message',
          pendingApproval: { id: 'custom-id', timeout: 100, methods: ['native'] },
          logged: true,
        }),
      };

      const executor = createActionExecutor({ confirmHandler: customHandler });
      const context = createTestContext({ analysis: { action: 'confirm' } });

      const result = await executor.execute(context);

      expect(customHandler.execute).toHaveBeenCalledWith(context);
      expect(result.pendingApproval?.id).toBe('custom-id');
    });
  });
});

describe('createDefaultActionExecutor', () => {
  it('should create executor with logger at specified level', () => {
    const executor = createDefaultActionExecutor('debug');

    expect(executor).toBeInstanceOf(DefaultActionExecutor);
  });

  it('should default to info log level', () => {
    const executor = createDefaultActionExecutor();

    expect(executor).toBeInstanceOf(DefaultActionExecutor);
  });
});

// =============================================================================
// LOGGER TESTS
// =============================================================================

describe('Loggers', () => {
  describe('noOpLogger', () => {
    it('should not throw on any log level', () => {
      expect(() => noOpLogger.debug('test')).not.toThrow();
      expect(() => noOpLogger.info('test')).not.toThrow();
      expect(() => noOpLogger.warn('test')).not.toThrow();
      expect(() => noOpLogger.error('test')).not.toThrow();
    });
  });

  describe('createLogger', () => {
    it('should respect log level filtering', () => {
      // We can't easily test console output, but we can verify it doesn't throw
      const debugLogger = createLogger('debug');
      const errorLogger = createLogger('error');

      expect(() => debugLogger.debug('test')).not.toThrow();
      expect(() => errorLogger.debug('test')).not.toThrow();
    });
  });

  describe('consoleLogger', () => {
    it('should handle calls with and without data', () => {
      const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});

      consoleLogger.debug('test message');
      consoleLogger.debug('test message', { key: 'value' });

      expect(spy).toHaveBeenCalledTimes(2);
      spy.mockRestore();
    });
  });
});

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

describe('Integration', () => {
  it('should handle complete block flow', async () => {
    const mockLogger = createMockLogger();
    const executor = createActionExecutor({ logger: mockLogger });

    const context: ActionContext = {
      analysis: {
        action: 'block',
        detections: [
          {
            category: 'secrets',
            severity: 'critical',
            confidence: 0.99,
            reason: 'AWS secret key detected: AKIA...',
          },
        ],
        primaryDetection: {
          category: 'secrets',
          severity: 'critical',
          confidence: 0.99,
          reason: 'AWS secret key detected: AKIA...',
        },
        requiresLLM: false,
        cached: false,
      },
      toolCall: {
        toolName: 'bash',
        toolInput: { command: 'echo $AWS_SECRET_KEY' },
      },
      config: createTestConfig(),
    };

    const result = await executor.execute(context);

    expect(result.allowed).toBe(false);
    expect(result.message).toContain('CRITICAL');
    expect(result.message).toContain('Secrets/PII');
    expect(result.logged).toBe(true);
    expect(mockLogger.calls.warn.length).toBe(1);
  });

  it('should handle complete confirm flow', async () => {
    const mockLogger = createMockLogger();
    const executor = createActionExecutor({ logger: mockLogger });

    const context: ActionContext = {
      analysis: {
        action: 'confirm',
        detections: [
          {
            category: 'destructive',
            severity: 'high',
            confidence: 0.85,
            reason: 'rm command detected',
          },
        ],
        primaryDetection: {
          category: 'destructive',
          severity: 'high',
          confidence: 0.85,
          reason: 'rm command detected',
        },
        requiresLLM: false,
        cached: false,
      },
      toolCall: {
        toolName: 'bash',
        toolInput: { command: 'rm old_file.txt' },
      },
      config: createTestConfig(),
    };

    const result = await executor.execute(context);

    expect(result.allowed).toBe(false);
    expect(result.pendingApproval).toBeDefined();
    expect(result.pendingApproval?.methods).toContain('native');
    expect(result.pendingApproval?.methods).toContain('agent-confirm');
    expect(result.message).toContain('Approval ID');
    expect(mockLogger.calls.info.length).toBe(1);
  });

  it('should handle warn with multiple detections', async () => {
    const executor = createActionExecutor();

    const context: ActionContext = {
      analysis: {
        action: 'warn',
        detections: [
          {
            category: 'website',
            severity: 'medium',
            confidence: 0.7,
            reason: 'Accessing less common domain',
          },
          {
            category: 'exfiltration',
            severity: 'low',
            confidence: 0.5,
            reason: 'Possible data upload',
          },
        ],
        primaryDetection: {
          category: 'website',
          severity: 'medium',
          confidence: 0.7,
          reason: 'Accessing less common domain',
        },
        requiresLLM: false,
        cached: false,
      },
      toolCall: {
        toolName: 'http_request',
        toolInput: { url: 'https://unusual-domain.io/upload' },
      },
      config: createTestConfig(),
    };

    const result = await executor.execute(context);

    expect(result.allowed).toBe(true);
    expect(result.message).toContain('Warning');
    expect(result.message).toContain('Additional warnings');
  });
});
