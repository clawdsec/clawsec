/**
 * Tests for the Approval Module
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  InMemoryApprovalStore,
  createApprovalStore,
  getDefaultApprovalStore,
  resetDefaultApprovalStore,
  DefaultNativeApprovalHandler,
  createNativeApprovalHandler,
  getDefaultNativeApprovalHandler,
  resetDefaultNativeApprovalHandler,
} from './index.js';
import type {
  PendingApprovalRecord,
  PendingApprovalInput,
  ApprovalStore,
  Detection,
  ToolCallContext,
} from './types.js';

// =============================================================================
// TEST HELPERS
// =============================================================================

/**
 * Create a test detection
 */
function createTestDetection(overrides: Partial<Detection> = {}): Detection {
  return {
    category: 'destructive',
    severity: 'critical',
    confidence: 0.95,
    reason: 'Detected rm -rf command',
    ...overrides,
  };
}

/**
 * Create a test tool call context
 */
function createTestToolCall(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    toolName: 'bash',
    toolInput: { command: 'rm -rf /tmp/test' },
    ...overrides,
  };
}

/**
 * Create a test approval input
 */
function createTestApprovalInput(overrides: Partial<PendingApprovalInput> = {}): PendingApprovalInput {
  const now = Date.now();
  return {
    id: `test-${now}-${Math.random().toString(36).slice(2)}`,
    createdAt: now,
    expiresAt: now + 300_000, // 5 minutes
    detection: createTestDetection(),
    toolCall: createTestToolCall(),
    ...overrides,
  };
}

// =============================================================================
// APPROVAL STORE TESTS
// =============================================================================

describe('InMemoryApprovalStore', () => {
  let store: InMemoryApprovalStore;

  beforeEach(() => {
    // Create store without auto-cleanup for testing
    store = createApprovalStore({ cleanupIntervalMs: 0 });
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
  });

  describe('add', () => {
    it('should add a new approval record with pending status', () => {
      const input = createTestApprovalInput({ id: 'test-add-1' });

      store.add(input);

      const record = store.get('test-add-1');
      expect(record).toBeDefined();
      expect(record?.status).toBe('pending');
      expect(record?.id).toBe('test-add-1');
    });

    it('should store all fields from input', () => {
      const detection = createTestDetection({ category: 'secrets' });
      const toolCall = createTestToolCall({ toolName: 'write_file' });
      const input = createTestApprovalInput({
        id: 'test-fields',
        detection,
        toolCall,
      });

      store.add(input);

      const record = store.get('test-fields');
      expect(record?.detection).toEqual(detection);
      expect(record?.toolCall).toEqual(toolCall);
      expect(record?.createdAt).toBe(input.createdAt);
      expect(record?.expiresAt).toBe(input.expiresAt);
    });

    it('should overwrite existing record with same ID', () => {
      const input1 = createTestApprovalInput({ id: 'test-overwrite' });
      const input2 = createTestApprovalInput({
        id: 'test-overwrite',
        detection: createTestDetection({ category: 'purchase' }),
      });

      store.add(input1);
      store.add(input2);

      const record = store.get('test-overwrite');
      expect(record?.detection.category).toBe('purchase');
    });
  });

  describe('get', () => {
    it('should return undefined for non-existent ID', () => {
      const record = store.get('non-existent-id');
      expect(record).toBeUndefined();
    });

    it('should return the record for existing ID', () => {
      const input = createTestApprovalInput({ id: 'test-get' });
      store.add(input);

      const record = store.get('test-get');
      expect(record).toBeDefined();
      expect(record?.id).toBe('test-get');
    });

    it('should mark expired records as expired', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'test-expired',
        createdAt: pastTime - 300_000,
        expiresAt: pastTime,
      });
      store.add(input);

      const record = store.get('test-expired');
      expect(record?.status).toBe('expired');
    });

    it('should not change status of non-pending expired records', () => {
      // Create a record that expires in the future
      const futureTime = Date.now() + 60_000;
      const input = createTestApprovalInput({
        id: 'test-approved-expired',
        expiresAt: futureTime,
      });
      store.add(input);

      // Approve while still pending
      store.approve('test-approved-expired');
      expect(store.get('test-approved-expired')?.status).toBe('approved');

      // Now manually set expiresAt to the past to simulate time passing
      // This tests that approved records don't get marked as expired
      const record = store.get('test-approved-expired')!;
      record.expiresAt = Date.now() - 1000;

      // Getting the record again should still show approved, not expired
      const recordAgain = store.get('test-approved-expired');
      expect(recordAgain?.status).toBe('approved');
    });
  });

  describe('approve', () => {
    it('should mark pending approval as approved', () => {
      const input = createTestApprovalInput({ id: 'test-approve' });
      store.add(input);

      const result = store.approve('test-approve');

      expect(result).toBe(true);
      const record = store.get('test-approve');
      expect(record?.status).toBe('approved');
    });

    it('should set approvedBy when provided', () => {
      const input = createTestApprovalInput({ id: 'test-approver' });
      store.add(input);

      store.approve('test-approver', 'user@example.com');

      const record = store.get('test-approver');
      expect(record?.approvedBy).toBe('user@example.com');
    });

    it('should set approvedAt timestamp', () => {
      const input = createTestApprovalInput({ id: 'test-timestamp' });
      store.add(input);

      const beforeApprove = Date.now();
      store.approve('test-timestamp');
      const afterApprove = Date.now();

      const record = store.get('test-timestamp');
      expect(record?.approvedAt).toBeGreaterThanOrEqual(beforeApprove);
      expect(record?.approvedAt).toBeLessThanOrEqual(afterApprove);
    });

    it('should return false for non-existent ID', () => {
      const result = store.approve('non-existent');
      expect(result).toBe(false);
    });

    it('should return false for already approved record', () => {
      const input = createTestApprovalInput({ id: 'test-already-approved' });
      store.add(input);
      store.approve('test-already-approved');

      const result = store.approve('test-already-approved');
      expect(result).toBe(false);
    });

    it('should return false for denied record', () => {
      const input = createTestApprovalInput({ id: 'test-denied' });
      store.add(input);
      store.deny('test-denied');

      const result = store.approve('test-denied');
      expect(result).toBe(false);
    });

    it('should return false for expired record', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'test-expired-approve',
        expiresAt: pastTime,
      });
      store.add(input);

      const result = store.approve('test-expired-approve');
      expect(result).toBe(false);
    });
  });

  describe('deny', () => {
    it('should mark pending approval as denied', () => {
      const input = createTestApprovalInput({ id: 'test-deny' });
      store.add(input);

      const result = store.deny('test-deny');

      expect(result).toBe(true);
      const record = store.get('test-deny');
      expect(record?.status).toBe('denied');
    });

    it('should return false for non-existent ID', () => {
      const result = store.deny('non-existent');
      expect(result).toBe(false);
    });

    it('should return false for already denied record', () => {
      const input = createTestApprovalInput({ id: 'test-already-denied' });
      store.add(input);
      store.deny('test-already-denied');

      const result = store.deny('test-already-denied');
      expect(result).toBe(false);
    });

    it('should return false for approved record', () => {
      const input = createTestApprovalInput({ id: 'test-approved-deny' });
      store.add(input);
      store.approve('test-approved-deny');

      const result = store.deny('test-approved-deny');
      expect(result).toBe(false);
    });

    it('should return false for expired record', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'test-expired-deny',
        expiresAt: pastTime,
      });
      store.add(input);

      const result = store.deny('test-expired-deny');
      expect(result).toBe(false);
    });
  });

  describe('remove', () => {
    it('should remove an existing record', () => {
      const input = createTestApprovalInput({ id: 'test-remove' });
      store.add(input);

      store.remove('test-remove');

      expect(store.get('test-remove')).toBeUndefined();
    });

    it('should not throw for non-existent ID', () => {
      expect(() => store.remove('non-existent')).not.toThrow();
    });
  });

  describe('cleanup', () => {
    it('should mark expired pending records as expired', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'test-cleanup-expired',
        expiresAt: pastTime,
      });
      store.add(input);

      store.cleanup();

      const record = store.get('test-cleanup-expired');
      expect(record?.status).toBe('expired');
    });

    it('should not change non-pending records', () => {
      const input = createTestApprovalInput({ id: 'test-cleanup-approved' });
      store.add(input);
      store.approve('test-cleanup-approved');

      store.cleanup();

      const record = store.get('test-cleanup-approved');
      expect(record?.status).toBe('approved');
    });

    it('should remove processed records when removeOnExpiry is true', () => {
      const storeWithRemoval = createApprovalStore({
        cleanupIntervalMs: 0,
        removeOnExpiry: true,
      });

      const pastTime = Date.now() - 1000;
      const input1 = createTestApprovalInput({
        id: 'test-remove-expired',
        expiresAt: pastTime,
      });
      const input2 = createTestApprovalInput({ id: 'test-remove-approved' });

      storeWithRemoval.add(input1);
      storeWithRemoval.add(input2);
      storeWithRemoval.approve('test-remove-approved');

      storeWithRemoval.cleanup();

      expect(storeWithRemoval.get('test-remove-expired')).toBeUndefined();
      expect(storeWithRemoval.get('test-remove-approved')).toBeUndefined();

      storeWithRemoval.stopCleanupTimer();
    });

    it('should keep pending non-expired records', () => {
      const storeWithRemoval = createApprovalStore({
        cleanupIntervalMs: 0,
        removeOnExpiry: true,
      });

      const input = createTestApprovalInput({ id: 'test-keep-pending' });
      storeWithRemoval.add(input);

      storeWithRemoval.cleanup();

      expect(storeWithRemoval.get('test-keep-pending')).toBeDefined();
      expect(storeWithRemoval.get('test-keep-pending')?.status).toBe('pending');

      storeWithRemoval.stopCleanupTimer();
    });
  });

  describe('getPending', () => {
    it('should return empty array when no records', () => {
      const pending = store.getPending();
      expect(pending).toEqual([]);
    });

    it('should return only pending records', () => {
      store.add(createTestApprovalInput({ id: 'pending-1' }));
      store.add(createTestApprovalInput({ id: 'pending-2' }));
      store.add(createTestApprovalInput({ id: 'approved-1' }));
      store.add(createTestApprovalInput({ id: 'denied-1' }));

      store.approve('approved-1');
      store.deny('denied-1');

      const pending = store.getPending();

      expect(pending.length).toBe(2);
      expect(pending.map(r => r.id).sort()).toEqual(['pending-1', 'pending-2']);
    });

    it('should not return expired records', () => {
      const pastTime = Date.now() - 1000;
      store.add(createTestApprovalInput({ id: 'pending-1' }));
      store.add(createTestApprovalInput({
        id: 'expired-1',
        expiresAt: pastTime,
      }));

      const pending = store.getPending();

      expect(pending.length).toBe(1);
      expect(pending[0].id).toBe('pending-1');
    });

    it('should update status of expired records when retrieved', () => {
      const pastTime = Date.now() - 1000;
      store.add(createTestApprovalInput({
        id: 'expired-check',
        expiresAt: pastTime,
      }));

      store.getPending();

      const record = store.get('expired-check');
      expect(record?.status).toBe('expired');
    });
  });

  describe('size', () => {
    it('should return 0 for empty store', () => {
      expect(store.size()).toBe(0);
    });

    it('should return correct count of records', () => {
      store.add(createTestApprovalInput({ id: 'size-1' }));
      store.add(createTestApprovalInput({ id: 'size-2' }));
      store.add(createTestApprovalInput({ id: 'size-3' }));

      expect(store.size()).toBe(3);
    });
  });

  describe('clear', () => {
    it('should remove all records', () => {
      store.add(createTestApprovalInput({ id: 'clear-1' }));
      store.add(createTestApprovalInput({ id: 'clear-2' }));

      store.clear();

      expect(store.size()).toBe(0);
    });
  });

  describe('auto cleanup', () => {
    it('should run cleanup on interval', async () => {
      const storeWithCleanup = createApprovalStore({ cleanupIntervalMs: 50 });
      const pastTime = Date.now() - 1000;

      storeWithCleanup.add(createTestApprovalInput({
        id: 'auto-cleanup',
        expiresAt: pastTime,
      }));

      // Wait for cleanup to run
      await new Promise(resolve => setTimeout(resolve, 100));

      const record = storeWithCleanup.get('auto-cleanup');
      expect(record?.status).toBe('expired');

      storeWithCleanup.stopCleanupTimer();
    });
  });
});

describe('Default approval store singleton', () => {
  afterEach(() => {
    resetDefaultApprovalStore();
  });

  it('should return the same instance on multiple calls', () => {
    const store1 = getDefaultApprovalStore();
    const store2 = getDefaultApprovalStore();

    expect(store1).toBe(store2);
  });

  it('should create new instance after reset', () => {
    const store1 = getDefaultApprovalStore();
    resetDefaultApprovalStore();
    const store2 = getDefaultApprovalStore();

    expect(store1).not.toBe(store2);
  });

  it('should clear data on reset', () => {
    const store = getDefaultApprovalStore();
    store.add(createTestApprovalInput({ id: 'singleton-test' }));

    resetDefaultApprovalStore();

    const newStore = getDefaultApprovalStore();
    expect(newStore.get('singleton-test')).toBeUndefined();
  });
});

// =============================================================================
// NATIVE APPROVAL HANDLER TESTS
// =============================================================================

describe('DefaultNativeApprovalHandler', () => {
  let store: InMemoryApprovalStore;
  let handler: DefaultNativeApprovalHandler;

  beforeEach(() => {
    store = createApprovalStore({ cleanupIntervalMs: 0 });
    handler = createNativeApprovalHandler({ store });
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
  });

  describe('handleApprove', () => {
    it('should approve pending approval and return success', () => {
      const input = createTestApprovalInput({ id: 'handle-approve-1' });
      store.add(input);

      const result = handler.handleApprove('handle-approve-1');

      expect(result.success).toBe(true);
      expect(result.message).toContain('Approved');
      expect(result.record?.status).toBe('approved');
    });

    it('should include tool name in success message', () => {
      const input = createTestApprovalInput({
        id: 'approve-tool-name',
        toolCall: createTestToolCall({ toolName: 'dangerous_tool' }),
      });
      store.add(input);

      const result = handler.handleApprove('approve-tool-name');

      expect(result.message).toContain('dangerous_tool');
    });

    it('should include category in success message', () => {
      const input = createTestApprovalInput({
        id: 'approve-category',
        detection: createTestDetection({ category: 'destructive' }),
      });
      store.add(input);

      const result = handler.handleApprove('approve-category');

      expect(result.message.toLowerCase()).toContain('destructive');
    });

    it('should set approvedBy when userId is provided', () => {
      const input = createTestApprovalInput({ id: 'approve-user' });
      store.add(input);

      handler.handleApprove('approve-user', 'test-user');

      const record = store.get('approve-user');
      expect(record?.approvedBy).toBe('test-user');
    });

    it('should return error for empty ID', () => {
      const result = handler.handleApprove('');

      expect(result.success).toBe(false);
      expect(result.message).toContain('Invalid');
    });

    it('should return error for whitespace-only ID', () => {
      const result = handler.handleApprove('   ');

      expect(result.success).toBe(false);
      expect(result.message).toContain('Invalid');
    });

    it('should trim whitespace from ID', () => {
      const input = createTestApprovalInput({ id: 'trimmed-id' });
      store.add(input);

      const result = handler.handleApprove('  trimmed-id  ');

      expect(result.success).toBe(true);
    });

    it('should return error for non-existent ID', () => {
      const result = handler.handleApprove('non-existent-id');

      expect(result.success).toBe(false);
      expect(result.message).toContain('not found');
      expect(result.message).toContain('non-existent-id');
    });

    it('should return error for expired approval', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'expired-approval',
        expiresAt: pastTime,
      });
      store.add(input);

      const result = handler.handleApprove('expired-approval');

      expect(result.success).toBe(false);
      expect(result.message).toContain('expired');
      expect(result.record).toBeDefined();
      expect(result.record?.status).toBe('expired');
    });

    it('should return error for already approved', () => {
      const input = createTestApprovalInput({ id: 'already-approved' });
      store.add(input);
      store.approve('already-approved');

      const result = handler.handleApprove('already-approved');

      expect(result.success).toBe(false);
      expect(result.message).toContain('already approved');
      expect(result.record?.status).toBe('approved');
    });

    it('should return error for already denied', () => {
      const input = createTestApprovalInput({ id: 'already-denied' });
      store.add(input);
      store.deny('already-denied');

      const result = handler.handleApprove('already-denied');

      expect(result.success).toBe(false);
      expect(result.message).toContain('already denied');
      expect(result.record?.status).toBe('denied');
    });
  });

  describe('handleDeny', () => {
    it('should deny pending approval and return success', () => {
      const input = createTestApprovalInput({ id: 'handle-deny-1' });
      store.add(input);

      const result = handler.handleDeny('handle-deny-1');

      expect(result.success).toBe(true);
      expect(result.message).toContain('Denied');
      expect(result.record?.status).toBe('denied');
    });

    it('should include tool name in deny message', () => {
      const input = createTestApprovalInput({
        id: 'deny-tool-name',
        toolCall: createTestToolCall({ toolName: 'risky_operation' }),
      });
      store.add(input);

      const result = handler.handleDeny('deny-tool-name');

      expect(result.message).toContain('risky_operation');
    });

    it('should return error for empty ID', () => {
      const result = handler.handleDeny('');

      expect(result.success).toBe(false);
      expect(result.message).toContain('Invalid');
    });

    it('should return error for non-existent ID', () => {
      const result = handler.handleDeny('non-existent');

      expect(result.success).toBe(false);
      expect(result.message).toContain('not found');
    });

    it('should return error for expired approval', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'expired-deny',
        expiresAt: pastTime,
      });
      store.add(input);

      const result = handler.handleDeny('expired-deny');

      expect(result.success).toBe(false);
      expect(result.message).toContain('expired');
    });

    it('should return error for already approved', () => {
      const input = createTestApprovalInput({ id: 'approved-deny' });
      store.add(input);
      store.approve('approved-deny');

      const result = handler.handleDeny('approved-deny');

      expect(result.success).toBe(false);
      expect(result.message).toContain('already approved');
      expect(result.message).toContain('cannot be denied');
    });

    it('should return error for already denied', () => {
      const input = createTestApprovalInput({ id: 'denied-deny' });
      store.add(input);
      store.deny('denied-deny');

      const result = handler.handleDeny('denied-deny');

      expect(result.success).toBe(false);
      expect(result.message).toContain('already denied');
    });
  });

  describe('isApproved', () => {
    it('should return true for approved record', () => {
      const input = createTestApprovalInput({ id: 'is-approved-yes' });
      store.add(input);
      store.approve('is-approved-yes');

      expect(handler.isApproved('is-approved-yes')).toBe(true);
    });

    it('should return false for pending record', () => {
      const input = createTestApprovalInput({ id: 'is-approved-pending' });
      store.add(input);

      expect(handler.isApproved('is-approved-pending')).toBe(false);
    });

    it('should return false for denied record', () => {
      const input = createTestApprovalInput({ id: 'is-approved-denied' });
      store.add(input);
      store.deny('is-approved-denied');

      expect(handler.isApproved('is-approved-denied')).toBe(false);
    });

    it('should return false for expired record', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'is-approved-expired',
        expiresAt: pastTime,
      });
      store.add(input);

      expect(handler.isApproved('is-approved-expired')).toBe(false);
    });

    it('should return false for non-existent ID', () => {
      expect(handler.isApproved('non-existent')).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(handler.isApproved('')).toBe(false);
    });

    it('should handle whitespace in ID', () => {
      const input = createTestApprovalInput({ id: 'whitespace-test' });
      store.add(input);
      store.approve('whitespace-test');

      expect(handler.isApproved('  whitespace-test  ')).toBe(true);
    });
  });

  describe('getPendingApprovals', () => {
    it('should return empty array when no approvals', () => {
      const pending = handler.getPendingApprovals();
      expect(pending).toEqual([]);
    });

    it('should return only pending approvals', () => {
      store.add(createTestApprovalInput({ id: 'get-pending-1' }));
      store.add(createTestApprovalInput({ id: 'get-pending-2' }));
      store.add(createTestApprovalInput({ id: 'get-approved' }));
      store.approve('get-approved');

      const pending = handler.getPendingApprovals();

      expect(pending.length).toBe(2);
      expect(pending.map(r => r.id).sort()).toEqual(['get-pending-1', 'get-pending-2']);
    });

    it('should not return expired approvals', () => {
      const pastTime = Date.now() - 1000;
      store.add(createTestApprovalInput({ id: 'get-pending-valid' }));
      store.add(createTestApprovalInput({
        id: 'get-pending-expired',
        expiresAt: pastTime,
      }));

      const pending = handler.getPendingApprovals();

      expect(pending.length).toBe(1);
      expect(pending[0].id).toBe('get-pending-valid');
    });
  });
});

describe('Default native approval handler singleton', () => {
  afterEach(() => {
    resetDefaultNativeApprovalHandler();
    resetDefaultApprovalStore();
  });

  it('should return the same instance on multiple calls', () => {
    const handler1 = getDefaultNativeApprovalHandler();
    const handler2 = getDefaultNativeApprovalHandler();

    expect(handler1).toBe(handler2);
  });

  it('should create new instance after reset', () => {
    const handler1 = getDefaultNativeApprovalHandler();
    resetDefaultNativeApprovalHandler();
    const handler2 = getDefaultNativeApprovalHandler();

    expect(handler1).not.toBe(handler2);
  });

  it('should use default store', () => {
    const defaultStore = getDefaultApprovalStore();
    const input = createTestApprovalInput({ id: 'default-store-test' });
    defaultStore.add(input);

    const handler = getDefaultNativeApprovalHandler();
    const result = handler.handleApprove('default-store-test');

    expect(result.success).toBe(true);
  });
});

// =============================================================================
// STATUS TRANSITION TESTS
// =============================================================================

describe('Status Transitions', () => {
  let store: InMemoryApprovalStore;

  beforeEach(() => {
    store = createApprovalStore({ cleanupIntervalMs: 0 });
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
  });

  it('pending -> approved', () => {
    store.add(createTestApprovalInput({ id: 'trans-1' }));
    expect(store.get('trans-1')?.status).toBe('pending');

    store.approve('trans-1');
    expect(store.get('trans-1')?.status).toBe('approved');
  });

  it('pending -> denied', () => {
    store.add(createTestApprovalInput({ id: 'trans-2' }));
    expect(store.get('trans-2')?.status).toBe('pending');

    store.deny('trans-2');
    expect(store.get('trans-2')?.status).toBe('denied');
  });

  it('pending -> expired (via time)', () => {
    const pastTime = Date.now() - 1000;
    store.add(createTestApprovalInput({
      id: 'trans-3',
      expiresAt: pastTime,
    }));

    // Get triggers expiry check
    expect(store.get('trans-3')?.status).toBe('expired');
  });

  it('approved -> cannot approve again', () => {
    store.add(createTestApprovalInput({ id: 'trans-4' }));
    store.approve('trans-4');

    expect(store.approve('trans-4')).toBe(false);
    expect(store.get('trans-4')?.status).toBe('approved');
  });

  it('approved -> cannot deny', () => {
    store.add(createTestApprovalInput({ id: 'trans-5' }));
    store.approve('trans-5');

    expect(store.deny('trans-5')).toBe(false);
    expect(store.get('trans-5')?.status).toBe('approved');
  });

  it('denied -> cannot approve', () => {
    store.add(createTestApprovalInput({ id: 'trans-6' }));
    store.deny('trans-6');

    expect(store.approve('trans-6')).toBe(false);
    expect(store.get('trans-6')?.status).toBe('denied');
  });

  it('denied -> cannot deny again', () => {
    store.add(createTestApprovalInput({ id: 'trans-7' }));
    store.deny('trans-7');

    expect(store.deny('trans-7')).toBe(false);
    expect(store.get('trans-7')?.status).toBe('denied');
  });

  it('expired -> cannot approve', () => {
    const pastTime = Date.now() - 1000;
    store.add(createTestApprovalInput({
      id: 'trans-8',
      expiresAt: pastTime,
    }));

    expect(store.approve('trans-8')).toBe(false);
    expect(store.get('trans-8')?.status).toBe('expired');
  });

  it('expired -> cannot deny', () => {
    const pastTime = Date.now() - 1000;
    store.add(createTestApprovalInput({
      id: 'trans-9',
      expiresAt: pastTime,
    }));

    expect(store.deny('trans-9')).toBe(false);
    expect(store.get('trans-9')?.status).toBe('expired');
  });
});

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

describe('Integration', () => {
  let store: InMemoryApprovalStore;
  let handler: DefaultNativeApprovalHandler;

  beforeEach(() => {
    store = createApprovalStore({ cleanupIntervalMs: 0 });
    handler = createNativeApprovalHandler({ store });
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
  });

  it('should handle complete approval flow', () => {
    // 1. Create pending approval
    const input = createTestApprovalInput({
      id: 'integration-1',
      detection: createTestDetection({
        category: 'destructive',
        reason: 'rm -rf detected',
      }),
      toolCall: createTestToolCall({
        toolName: 'bash',
        toolInput: { command: 'rm -rf /tmp/old' },
      }),
    });
    store.add(input);

    // 2. Verify pending
    expect(handler.isApproved('integration-1')).toBe(false);
    expect(handler.getPendingApprovals().length).toBe(1);

    // 3. Approve
    const result = handler.handleApprove('integration-1', 'admin');

    // 4. Verify approved
    expect(result.success).toBe(true);
    expect(result.message).toContain('Approved');
    expect(result.message).toContain('bash');
    expect(handler.isApproved('integration-1')).toBe(true);
    expect(handler.getPendingApprovals().length).toBe(0);

    // 5. Verify record details
    const record = store.get('integration-1');
    expect(record?.status).toBe('approved');
    expect(record?.approvedBy).toBe('admin');
    expect(record?.approvedAt).toBeDefined();
  });

  it('should handle complete deny flow', () => {
    const input = createTestApprovalInput({
      id: 'integration-2',
      toolCall: createTestToolCall({ toolName: 'dangerous_tool' }),
    });
    store.add(input);

    expect(handler.getPendingApprovals().length).toBe(1);

    const result = handler.handleDeny('integration-2');

    expect(result.success).toBe(true);
    expect(result.message).toContain('Denied');
    expect(result.message).toContain('dangerous_tool');
    expect(handler.isApproved('integration-2')).toBe(false);
    expect(handler.getPendingApprovals().length).toBe(0);
    expect(store.get('integration-2')?.status).toBe('denied');
  });

  it('should handle expiration flow', () => {
    const pastTime = Date.now() - 1000;
    const input = createTestApprovalInput({
      id: 'integration-3',
      createdAt: pastTime - 300_000,
      expiresAt: pastTime,
    });
    store.add(input);

    // Trying to approve expired
    const approveResult = handler.handleApprove('integration-3');
    expect(approveResult.success).toBe(false);
    expect(approveResult.message).toContain('expired');

    // Trying to deny expired
    const denyResult = handler.handleDeny('integration-3');
    expect(denyResult.success).toBe(false);
    expect(denyResult.message).toContain('expired');

    // Check status
    expect(handler.isApproved('integration-3')).toBe(false);
    expect(handler.getPendingApprovals().length).toBe(0);
  });

  it('should handle multiple concurrent approvals', () => {
    // Create multiple approvals
    for (let i = 1; i <= 5; i++) {
      store.add(createTestApprovalInput({
        id: `multi-${i}`,
        toolCall: createTestToolCall({ toolName: `tool-${i}` }),
      }));
    }

    expect(handler.getPendingApprovals().length).toBe(5);

    // Approve some
    handler.handleApprove('multi-1');
    handler.handleApprove('multi-3');

    // Deny some
    handler.handleDeny('multi-2');

    // Check states
    expect(handler.isApproved('multi-1')).toBe(true);
    expect(handler.isApproved('multi-2')).toBe(false);
    expect(handler.isApproved('multi-3')).toBe(true);
    expect(handler.isApproved('multi-4')).toBe(false);
    expect(handler.isApproved('multi-5')).toBe(false);

    expect(handler.getPendingApprovals().length).toBe(2);
    expect(handler.getPendingApprovals().map(r => r.id).sort()).toEqual(['multi-4', 'multi-5']);
  });
});
