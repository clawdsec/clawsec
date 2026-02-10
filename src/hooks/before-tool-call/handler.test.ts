/**
 * Tests for the Before Tool Call Hook Handler
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createBeforeToolCallHandler,
  createDefaultBeforeToolCallHandler,
} from './handler.js';
import type { BeforeToolCallHandlerOptions } from './handler.js';
import type {
  ToolCallContext,
  BeforeToolCallResult,
} from '../../index.js';
import type {
  Analyzer,
  AnalysisResult,
  ToolCallContext as EngineToolCallContext,
  Detection,
} from '../../engine/types.js';
import type { ActionExecutor, ActionContext, ActionResult } from '../../actions/types.js';
import type { AgentConfirmHandler, AgentConfirmResult } from '../../approval/agent-confirm.js';
import type { ClawsecConfig } from '../../config/schema.js';
import { resetDefaultApprovalStore } from '../../approval/store.js';
import { resetDefaultAgentConfirmHandler } from '../../approval/agent-confirm.js';

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
 * Create a test tool call context
 */
function createTestToolCallContext(
  overrides: Partial<ToolCallContext> = {}
): ToolCallContext {
  return {
    sessionId: 'test-session-123',
    timestamp: Date.now(),
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
    reason: 'Detected dangerous command',
    ...overrides,
  };
}

/**
 * Create a test analysis result
 */
function createTestAnalysisResult(
  overrides: Partial<AnalysisResult> = {}
): AnalysisResult {
  return {
    action: 'allow',
    detections: [],
    requiresLLM: false,
    cached: false,
    durationMs: 5,
    ...overrides,
  };
}

/**
 * Create a mock analyzer
 */
function createMockAnalyzer(result: AnalysisResult): Analyzer {
  return {
    analyze: vi.fn().mockResolvedValue(result),
    clearCache: vi.fn(),
    getCacheStats: vi.fn().mockReturnValue({ size: 0, enabled: true }),
  };
}

/**
 * Create a mock action executor
 */
function createMockExecutor(result: ActionResult): ActionExecutor {
  return {
    execute: vi.fn().mockResolvedValue(result),
  };
}

/**
 * Create a mock agent confirm handler
 */
function createMockAgentConfirm(options: {
  checkResult?: AgentConfirmResult;
  processResult?: AgentConfirmResult;
  strippedInput?: Record<string, unknown>;
}): AgentConfirmHandler {
  return {
    checkConfirmation: vi.fn().mockReturnValue(
      options.checkResult ?? { confirmed: false, valid: false }
    ),
    processConfirmation: vi.fn().mockReturnValue(
      options.processResult ?? { confirmed: false, valid: false }
    ),
    stripConfirmParameter: vi.fn().mockReturnValue(
      options.strippedInput ?? {}
    ),
  };
}

// =============================================================================
// TESTS
// =============================================================================

describe('BeforeToolCallHandler', () => {
  beforeEach(() => {
    // Reset singletons before each test
    resetDefaultApprovalStore();
    resetDefaultAgentConfirmHandler();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  // ===========================================================================
  // ALLOW (NO DETECTION)
  // ===========================================================================

  describe('Allow (no detection)', () => {
    it('should allow tool call when analyzer returns allow action', async () => {
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({ action: 'allow', detections: [] })
      );

      const handler = createBeforeToolCallHandler(config, { analyzer: mockAnalyzer });
      const context = createTestToolCallContext();

      const result = await handler(context);

      expect(result.block).toBe(false);
      expect(result.blockReason).toBeUndefined();
      expect(mockAnalyzer.analyze).toHaveBeenCalledTimes(1);
    });

    it('should allow tool call with no modifications when no threats detected', async () => {
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({ action: 'allow' })
      );

      const handler = createBeforeToolCallHandler(config, { analyzer: mockAnalyzer });
      const context = createTestToolCallContext({
        toolInput: { command: 'ls -la' },
      });

      const result = await handler(context);

      expect(result.block).toBe(false);
      expect(result.params).toBeUndefined();
    });
  });

  // ===========================================================================
  // BLOCK (CRITICAL DETECTION)
  // ===========================================================================

  describe('Block (critical detection)', () => {
    it('should block tool call when analyzer returns block action', async () => {
      const detection = createTestDetection({
        category: 'destructive',
        severity: 'critical',
        reason: 'Detected rm -rf / command',
      });
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({
          action: 'block',
          detections: [detection],
          primaryDetection: detection,
        })
      );
      const mockExecutor = createMockExecutor({
        allowed: false,
        message: 'Blocked: destructive command detected',
        logged: true,
      });

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        executor: mockExecutor,
      });
      const context = createTestToolCallContext({
        toolInput: { command: 'rm -rf /' },
      });

      const result = await handler(context);

      expect(result.block).toBe(true);
      expect(result.blockReason).toBe('Blocked: destructive command detected');
      expect(result.metadata?.category).toBe('destructive');
      expect(result.metadata?.severity).toBe('critical');
      expect(result.metadata?.reason).toBe('Detected rm -rf / command');
    });

    it('should block secrets detection', async () => {
      const detection = createTestDetection({
        category: 'secrets',
        severity: 'critical',
        reason: 'API key detected in output',
        metadata: { rule: 'api-key-detection' },
      });
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({
          action: 'block',
          detections: [detection],
          primaryDetection: detection,
        })
      );
      const mockExecutor = createMockExecutor({
        allowed: false,
        message: 'Blocked: API key detected',
        logged: true,
      });

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        executor: mockExecutor,
      });
      const context = createTestToolCallContext();

      const result = await handler(context);

      expect(result.block).toBe(true);
      expect(result.metadata?.category).toBe('secrets');
      expect(result.metadata?.rule).toBe('api-key-detection');
    });

    it('should block exfiltration detection', async () => {
      const detection = createTestDetection({
        category: 'exfiltration',
        severity: 'high',
        reason: 'Data exfiltration attempt detected',
      });
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({
          action: 'block',
          detections: [detection],
          primaryDetection: detection,
        })
      );
      const mockExecutor = createMockExecutor({
        allowed: false,
        message: 'Blocked: Data exfiltration detected',
        logged: true,
      });

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        executor: mockExecutor,
      });
      const context = createTestToolCallContext();

      const result = await handler(context);

      expect(result.block).toBe(true);
      expect(result.metadata?.category).toBe('exfiltration');
    });
  });

  // ===========================================================================
  // CONFIRM (NEEDS APPROVAL)
  // ===========================================================================

  describe('Confirm (needs approval)', () => {
    it('should block with pending approval for confirm action', async () => {
      const detection = createTestDetection({
        category: 'destructive',
        severity: 'critical',
        reason: 'Dangerous shell command detected',
      });
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({
          action: 'confirm',
          detections: [detection],
          primaryDetection: detection,
        })
      );
      const mockExecutor = createMockExecutor({
        allowed: false,
        message: 'Approval required for destructive operation',
        logged: true,
        pendingApproval: {
          id: 'approval-123',
          timeout: 300,
          methods: ['native', 'agent-confirm'],
        },
      });

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        executor: mockExecutor,
      });
      const context = createTestToolCallContext({
        toolInput: { command: 'rm -rf ./data' },
      });

      const result = await handler(context);

      expect(result.block).toBe(true);
      expect(result.blockReason).toContain('Approval required');
      expect(result.blockReason).toContain('approval-123');
      expect(result.blockReason).toContain('300s');
      expect(result.blockReason).toContain('native');
      expect(result.blockReason).toContain('agent-confirm');
    });

    it('should include approval instructions in block message', async () => {
      const detection = createTestDetection();
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({
          action: 'confirm',
          detections: [detection],
          primaryDetection: detection,
        })
      );
      const mockExecutor = createMockExecutor({
        allowed: false,
        message: 'Confirmation needed',
        logged: true,
        pendingApproval: {
          id: 'test-approval-id',
          timeout: 120,
          methods: ['webhook'],
        },
      });

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        executor: mockExecutor,
      });
      const context = createTestToolCallContext();

      const result = await handler(context);

      expect(result.blockReason).toContain('Approval ID: test-approval-id');
      expect(result.blockReason).toContain('Timeout: 120s');
      expect(result.blockReason).toContain('Methods: webhook');
    });
  });

  // ===========================================================================
  // WARN (LOGGED WARNING)
  // ===========================================================================

  describe('Warn (logged warning)', () => {
    it('should allow tool call but log warning for warn action', async () => {
      const detection = createTestDetection({
        category: 'website',
        severity: 'medium',
        reason: 'Accessing external website',
      });
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({
          action: 'warn',
          detections: [detection],
          primaryDetection: detection,
        })
      );
      const mockExecutor = createMockExecutor({
        allowed: true,
        message: 'Warning: accessing external website',
        logged: true,
      });

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        executor: mockExecutor,
      });
      const context = createTestToolCallContext({
        toolInput: { url: 'https://example.com' },
      });

      const result = await handler(context);

      expect(result.block).toBe(false);
      expect(mockExecutor.execute).toHaveBeenCalled();
    });
  });

  // ===========================================================================
  // AGENT-CONFIRM FLOW
  // ===========================================================================

  describe('Agent-confirm flow', () => {
    it('should allow when valid agent-confirm parameter is present', async () => {
      const config = createTestConfig();
      const mockAgentConfirm = createMockAgentConfirm({
        checkResult: { confirmed: true, approvalId: 'approval-123', valid: true },
        processResult: { confirmed: true, approvalId: 'approval-123', valid: true },
        strippedInput: { command: 'rm -rf ./temp' },
      });
      const mockAnalyzer = createMockAnalyzer(createTestAnalysisResult());

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        agentConfirm: mockAgentConfirm,
      });
      const context = createTestToolCallContext({
        toolInput: {
          command: 'rm -rf ./temp',
          _clawsec_confirm: 'approval-123',
        },
      });

      const result = await handler(context);

      expect(result.block).toBe(false);
      expect(result.params).toEqual({ command: 'rm -rf ./temp' });
      // Analyzer should NOT be called when agent-confirm is valid
      expect(mockAnalyzer.analyze).not.toHaveBeenCalled();
    });

    it('should block when invalid agent-confirm parameter is present', async () => {
      const config = createTestConfig();
      const mockAgentConfirm = createMockAgentConfirm({
        checkResult: { confirmed: true, approvalId: 'invalid-id', valid: false },
        processResult: {
          confirmed: true,
          approvalId: 'invalid-id',
          valid: false,
          error: 'Approval not found or expired',
        },
      });
      const mockAnalyzer = createMockAnalyzer(createTestAnalysisResult());

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        agentConfirm: mockAgentConfirm,
      });
      const context = createTestToolCallContext({
        toolInput: {
          command: 'rm -rf ./temp',
          _clawsec_confirm: 'invalid-id',
        },
      });

      const result = await handler(context);

      expect(result.block).toBe(true);
      expect(result.blockReason).toBe('Approval not found or expired');
      // Analyzer should NOT be called when agent-confirm is present (even if invalid)
      expect(mockAnalyzer.analyze).not.toHaveBeenCalled();
    });

    it('should proceed with analysis when no agent-confirm parameter', async () => {
      const config = createTestConfig();
      const mockAgentConfirm = createMockAgentConfirm({
        checkResult: { confirmed: false, valid: false },
      });
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({ action: 'allow' })
      );

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        agentConfirm: mockAgentConfirm,
      });
      const context = createTestToolCallContext({
        toolInput: { command: 'ls -la' },
      });

      const result = await handler(context);

      expect(result.block).toBe(false);
      expect(mockAnalyzer.analyze).toHaveBeenCalledTimes(1);
    });

    it('should skip agent-confirm check when disabled in config', async () => {
      const config = createTestConfig({
        approval: {
          native: { enabled: true, timeout: 300 },
          agentConfirm: { enabled: false, parameterName: '_clawsec_confirm' },
          webhook: { enabled: false, timeout: 30, headers: {} },
        },
      });
      const mockAgentConfirm = createMockAgentConfirm({
        checkResult: { confirmed: true, approvalId: 'test', valid: true },
        processResult: { confirmed: true, approvalId: 'test', valid: true },
      });
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({ action: 'allow' })
      );

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        agentConfirm: mockAgentConfirm,
      });
      const context = createTestToolCallContext({
        toolInput: { _clawsec_confirm: 'test' },
      });

      const result = await handler(context);

      // Should skip agent-confirm and go straight to analyzer
      expect(mockAgentConfirm.checkConfirmation).not.toHaveBeenCalled();
      expect(mockAnalyzer.analyze).toHaveBeenCalled();
    });

    it('should use custom parameter name from config', async () => {
      const config = createTestConfig({
        approval: {
          native: { enabled: true, timeout: 300 },
          agentConfirm: { enabled: true, parameterName: '_custom_confirm' },
          webhook: { enabled: false, timeout: 30, headers: {} },
        },
      });
      const mockAgentConfirm = createMockAgentConfirm({
        checkResult: { confirmed: false, valid: false },
      });
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({ action: 'allow' })
      );

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        agentConfirm: mockAgentConfirm,
      });
      const context = createTestToolCallContext();

      await handler(context);

      expect(mockAgentConfirm.checkConfirmation).toHaveBeenCalledWith(
        context.toolInput,
        '_custom_confirm'
      );
    });
  });

  // ===========================================================================
  // CONFIG DISABLED
  // ===========================================================================

  describe('Config disabled', () => {
    it('should allow all tool calls when plugin is disabled', async () => {
      const config = createTestConfig({
        global: { enabled: false, logLevel: 'info' },
      });
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({ action: 'block' })
      );

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
      });
      const context = createTestToolCallContext({
        toolInput: { command: 'rm -rf /' },
      });

      const result = await handler(context);

      expect(result.block).toBe(false);
      expect(mockAnalyzer.analyze).not.toHaveBeenCalled();
    });

    it('should skip analysis when globally disabled', async () => {
      const config = createTestConfig({
        global: { enabled: false, logLevel: 'warn' },
      });
      const mockAnalyzer = createMockAnalyzer(createTestAnalysisResult());
      const mockExecutor = createMockExecutor({ allowed: false, logged: false });

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        executor: mockExecutor,
      });
      const context = createTestToolCallContext();

      await handler(context);

      expect(mockAnalyzer.analyze).not.toHaveBeenCalled();
      expect(mockExecutor.execute).not.toHaveBeenCalled();
    });
  });

  // ===========================================================================
  // MULTIPLE DETECTIONS
  // ===========================================================================

  describe('Multiple detections', () => {
    it('should use primary detection for metadata', async () => {
      const criticalDetection = createTestDetection({
        category: 'destructive',
        severity: 'critical',
        confidence: 0.99,
        reason: 'Critical: rm -rf command',
      });
      const highDetection = createTestDetection({
        category: 'exfiltration',
        severity: 'high',
        confidence: 0.85,
        reason: 'High: potential data exfiltration',
      });
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({
          action: 'block',
          detections: [criticalDetection, highDetection],
          primaryDetection: criticalDetection,
        })
      );
      const mockExecutor = createMockExecutor({
        allowed: false,
        message: 'Multiple threats detected',
        logged: true,
      });

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        executor: mockExecutor,
      });
      const context = createTestToolCallContext();

      const result = await handler(context);

      expect(result.block).toBe(true);
      expect(result.metadata?.category).toBe('destructive');
      expect(result.metadata?.severity).toBe('critical');
      expect(result.metadata?.reason).toBe('Critical: rm -rf command');
    });

    it('should handle detections with missing primary', async () => {
      const detection = createTestDetection();
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({
          action: 'block',
          detections: [detection],
          // primaryDetection intentionally undefined
        })
      );
      const mockExecutor = createMockExecutor({
        allowed: false,
        message: 'Threat detected',
        logged: true,
      });

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        executor: mockExecutor,
      });
      const context = createTestToolCallContext();

      const result = await handler(context);

      expect(result.block).toBe(true);
      expect(result.metadata).toBeUndefined();
    });
  });

  // ===========================================================================
  // CONTEXT CONVERSION
  // ===========================================================================

  describe('Context conversion', () => {
    it('should convert hook context to engine context', async () => {
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({ action: 'allow' })
      );

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
      });
      const context = createTestToolCallContext({
        sessionId: 'session-456',
        userId: 'user-789',
        timestamp: 1234567890,
        toolName: 'browser_navigate',
        toolInput: { url: 'https://example.com', arg: 'value' },
      });

      await handler(context);

      expect(mockAnalyzer.analyze).toHaveBeenCalledWith({
        toolName: 'browser_navigate',
        toolInput: { url: 'https://example.com', arg: 'value' },
        url: 'https://example.com',
      });
    });

    it('should handle context without url in toolInput', async () => {
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({ action: 'allow' })
      );

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
      });
      const context = createTestToolCallContext({
        toolName: 'shell_execute',
        toolInput: { command: 'ls -la' },
      });

      await handler(context);

      expect(mockAnalyzer.analyze).toHaveBeenCalledWith({
        toolName: 'shell_execute',
        toolInput: { command: 'ls -la' },
        url: undefined,
      });
    });
  });

  // ===========================================================================
  // DEFAULT HANDLER
  // ===========================================================================

  describe('createDefaultBeforeToolCallHandler', () => {
    it('should create handler with default config', async () => {
      const handler = createDefaultBeforeToolCallHandler();

      // Should be a function
      expect(typeof handler).toBe('function');

      // Should process a simple tool call
      const context = createTestToolCallContext({
        toolName: 'test',
        toolInput: { safe: 'input' },
      });

      const result = await handler(context);

      // Should return a valid result
      expect(result).toHaveProperty('block');
    });
  });

  // ===========================================================================
  // EDGE CASES
  // ===========================================================================

  describe('Edge cases', () => {
    it('should handle empty tool input', async () => {
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({ action: 'allow' })
      );

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
      });
      const context = createTestToolCallContext({
        toolInput: {},
      });

      const result = await handler(context);

      expect(result.block).toBe(false);
    });

    it('should handle analyzer errors gracefully', async () => {
      const config = createTestConfig();
      const mockAnalyzer: Analyzer = {
        analyze: vi.fn().mockRejectedValue(new Error('Analyzer failed')),
        clearCache: vi.fn(),
        getCacheStats: vi.fn().mockReturnValue({ size: 0, enabled: true }),
      };

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
      });
      const context = createTestToolCallContext();

      // With error handling, errors are caught and handler returns allow (fail-open)
      const result = await handler(context);
      expect(result.block).toBe(false); // Fail-open on error
    });

    it('should handle executor errors gracefully', async () => {
      const detection = createTestDetection();
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({
          action: 'block',
          detections: [detection],
          primaryDetection: detection,
        })
      );
      const mockExecutor: ActionExecutor = {
        execute: vi.fn().mockRejectedValue(new Error('Executor failed')),
      };

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        executor: mockExecutor,
      });
      const context = createTestToolCallContext();

      // With error handling, errors are caught and handler returns allow (fail-open)
      const result = await handler(context);
      expect(result.block).toBe(false); // Fail-open on error
    });

    it('should handle log action', async () => {
      const detection = createTestDetection({
        category: 'website',
        severity: 'low',
        reason: 'Website access logged',
      });
      const config = createTestConfig();
      const mockAnalyzer = createMockAnalyzer(
        createTestAnalysisResult({
          action: 'log',
          detections: [detection],
          primaryDetection: detection,
        })
      );
      const mockExecutor = createMockExecutor({
        allowed: true,
        logged: true,
      });

      const handler = createBeforeToolCallHandler(config, {
        analyzer: mockAnalyzer,
        executor: mockExecutor,
      });
      const context = createTestToolCallContext();

      const result = await handler(context);

      expect(result.block).toBe(false);
    });
  });
});
