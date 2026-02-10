/**
 * Tests for Confirm Action Handler
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ConfirmHandler, generateApprovalId, getEnabledApprovalMethods, getApprovalTimeout } from './confirm.js';
import { getDefaultApprovalStore } from '../approval/store.js';
import type { ActionContext } from './types.js';
import type { ClawsecConfig } from '../config/index.js';
import type { DetectionResult } from '../detectors/types.js';

describe('ConfirmHandler', () => {
  beforeEach(() => {
    // Clear approval store before each test
    const store = getDefaultApprovalStore();
    store.clear();
  });

  describe('generateApprovalId', () => {
    it('should generate a valid UUID', () => {
      const id = generateApprovalId();
      expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    });

    it('should generate unique IDs', () => {
      const id1 = generateApprovalId();
      const id2 = generateApprovalId();
      expect(id1).not.toBe(id2);
    });
  });

  describe('getEnabledApprovalMethods', () => {
    it('should return all methods when all are enabled', () => {
      const context: ActionContext = {
        toolCall: { toolName: 'test', toolInput: {} },
        analysis: { detected: false, detections: [] },
        config: {
          approval: {
            native: { enabled: true },
            agentConfirm: { enabled: true },
            webhook: { enabled: true, url: 'https://example.com/webhook' },
          },
        } as ClawsecConfig,
      };

      const methods = getEnabledApprovalMethods(context);
      expect(methods).toEqual(['native', 'agent-confirm', 'webhook']);
    });

    it('should exclude disabled methods', () => {
      const context: ActionContext = {
        toolCall: { toolName: 'test', toolInput: {} },
        analysis: { detected: false, detections: [] },
        config: {
          approval: {
            native: { enabled: false },
            agentConfirm: { enabled: true },
            webhook: { enabled: false },
          },
        } as ClawsecConfig,
      };

      const methods = getEnabledApprovalMethods(context);
      expect(methods).toEqual(['agent-confirm']);
    });

    it('should not include webhook if URL is not configured', () => {
      const context: ActionContext = {
        toolCall: { toolName: 'test', toolInput: {} },
        analysis: { detected: false, detections: [] },
        config: {
          approval: {
            native: { enabled: true },
            agentConfirm: { enabled: true },
            webhook: { enabled: true }, // No URL
          },
        } as ClawsecConfig,
      };

      const methods = getEnabledApprovalMethods(context);
      expect(methods).toEqual(['native', 'agent-confirm']);
    });
  });

  describe('getApprovalTimeout', () => {
    it('should return configured timeout', () => {
      const context: ActionContext = {
        toolCall: { toolName: 'test', toolInput: {} },
        analysis: { detected: false, detections: [] },
        config: {
          approval: {
            native: { timeout: 600 },
          },
        } as ClawsecConfig,
      };

      const timeout = getApprovalTimeout(context);
      expect(timeout).toBe(600);
    });

    it('should return default timeout when not configured', () => {
      const context: ActionContext = {
        toolCall: { toolName: 'test', toolInput: {} },
        analysis: { detected: false, detections: [] },
        config: {} as ClawsecConfig,
      };

      const timeout = getApprovalTimeout(context);
      expect(timeout).toBe(300); // Default
    });
  });

  describe('ConfirmHandler.execute', () => {
    it('should store approval in approval store', async () => {
      const handler = new ConfirmHandler();
      const store = getDefaultApprovalStore();

      const primaryDetection: DetectionResult = {
        category: 'purchase',
        severity: 'critical',
        confidence: 0.9,
        reason: 'Purchase detected',
      };

      const context: ActionContext = {
        toolCall: {
          toolName: 'purchase',
          toolInput: { item: 'laptop', amount: 1000 },
        },
        analysis: {
          detected: true,
          detections: [primaryDetection],
          primaryDetection,
        },
        config: {
          approval: {
            native: { enabled: true, timeout: 300 },
            agentConfirm: { enabled: true },
          },
        } as ClawsecConfig,
      };

      const result = await handler.execute(context);

      // Should return approval ID
      expect(result.allowed).toBe(false);
      expect(result.pendingApproval).toBeDefined();
      expect(result.pendingApproval?.id).toBeDefined();

      // Approval should be retrievable from store
      const approvalId = result.pendingApproval!.id;
      const storedApproval = store.get(approvalId);

      expect(storedApproval).toBeDefined();
      expect(storedApproval?.id).toBe(approvalId);
      expect(storedApproval?.status).toBe('pending');
      expect(storedApproval?.detection.category).toBe('purchase');
      expect(storedApproval?.detection.severity).toBe('critical');
      expect(storedApproval?.detection.confidence).toBe(0.9);
      expect(storedApproval?.toolCall.toolName).toBe('purchase');
    });

    it('should handle missing primary detection', async () => {
      const handler = new ConfirmHandler();
      const store = getDefaultApprovalStore();

      const context: ActionContext = {
        toolCall: {
          toolName: 'risky-action',
          toolInput: { param: 'value' },
        },
        analysis: {
          detected: false,
          detections: [],
          // No primaryDetection
        },
        config: {
          approval: {
            native: { enabled: true, timeout: 300 },
          },
        } as ClawsecConfig,
      };

      const result = await handler.execute(context);

      expect(result.allowed).toBe(false);
      expect(result.pendingApproval).toBeDefined();

      const approvalId = result.pendingApproval!.id;
      const storedApproval = store.get(approvalId);

      expect(storedApproval).toBeDefined();
      expect(storedApproval?.detection.category).toBe('unknown'); // No specific threat detected
      expect(storedApproval?.detection.severity).toBe('medium');
      expect(storedApproval?.detection.reason).toBe('Manual approval required');
    });

    it('should include timeout in approval record', async () => {
      const handler = new ConfirmHandler();
      const store = getDefaultApprovalStore();

      const context: ActionContext = {
        toolCall: { toolName: 'test', toolInput: {} },
        analysis: {
          detected: true,
          detections: [],
          primaryDetection: {
            category: 'destructive',
            severity: 'high',
            confidence: 0.8,
            reason: 'Destructive command',
          },
        },
        config: {
          approval: {
            native: { enabled: true, timeout: 600 },
          },
        } as ClawsecConfig,
      };

      const result = await handler.execute(context);
      const approvalId = result.pendingApproval!.id;
      const storedApproval = store.get(approvalId);

      expect(storedApproval).toBeDefined();
      expect(storedApproval?.expiresAt).toBeGreaterThan(storedApproval!.createdAt);
      expect(storedApproval?.expiresAt - storedApproval!.createdAt).toBe(600 * 1000);
    });

    it('should return approval instructions in message', async () => {
      const handler = new ConfirmHandler();

      const context: ActionContext = {
        toolCall: { toolName: 'test', toolInput: {} },
        analysis: {
          detected: true,
          detections: [],
          primaryDetection: {
            category: 'purchase',
            severity: 'critical',
            confidence: 0.9,
            reason: 'Purchase detected',
          },
        },
        config: {
          approval: {
            native: { enabled: true, timeout: 300 },
            agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
          },
        } as ClawsecConfig,
      };

      const result = await handler.execute(context);

      expect(result.message).toContain('Approval ID:');
      expect(result.message).toContain('Timeout: 300 seconds');
      expect(result.message).toContain('_clawsec_confirm=');
    });
  });
});
