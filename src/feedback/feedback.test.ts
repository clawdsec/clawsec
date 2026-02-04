/**
 * Feedback Module Tests
 * Tests for feedback storage and CLI commands
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtemp, rm, readFile, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  FileFeedbackStore,
  createFeedbackStore,
  getFeedbackStore,
  resetGlobalFeedbackStore,
} from './store.js';
import type { FeedbackEntry, FeedbackInput } from './types.js';
import {
  feedbackCommand,
  formatFeedbackResult,
  formatFeedbackSummary,
} from '../cli/commands/feedback.js';
import { addAuditEntry, clearAuditLog } from '../cli/commands/audit.js';

// =============================================================================
// STORE TESTS
// =============================================================================

describe('FileFeedbackStore', () => {
  let tempDir: string;
  let store: FileFeedbackStore;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'clawsec-feedback-test-'));
    store = createFeedbackStore(tempDir);
  });

  afterEach(async () => {
    store.clear();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe('add', () => {
    it('should add a false positive entry', () => {
      const input: FeedbackInput = {
        type: 'false-positive',
        detectionId: '123',
        detection: {
          category: 'secrets',
          severity: 'critical',
          reason: 'API key detected',
          toolName: 'bash',
          toolInput: { command: 'echo test' },
        },
      };

      const entry = store.add(input);

      expect(entry.id).toBeDefined();
      expect(entry.id.length).toBeGreaterThan(0);
      expect(entry.type).toBe('false-positive');
      expect(entry.timestamp).toBeDefined();
      expect(entry.timestamp).toBeGreaterThan(0);
      expect(entry.status).toBe('pending');
      expect(entry.detectionId).toBe('123');
      expect(entry.detection?.category).toBe('secrets');
    });

    it('should add a false negative entry', () => {
      const input: FeedbackInput = {
        type: 'false-negative',
        description: 'API key leaked in output',
        suggestedCategory: 'secrets',
      };

      const entry = store.add(input);

      expect(entry.id).toBeDefined();
      expect(entry.type).toBe('false-negative');
      expect(entry.status).toBe('pending');
      expect(entry.description).toBe('API key leaked in output');
      expect(entry.suggestedCategory).toBe('secrets');
    });

    it('should generate unique IDs for entries', () => {
      const entry1 = store.add({ type: 'false-positive', detectionId: '1' });
      const entry2 = store.add({ type: 'false-positive', detectionId: '2' });

      expect(entry1.id).not.toBe(entry2.id);
    });
  });

  describe('get', () => {
    it('should retrieve an entry by ID', () => {
      const added = store.add({ type: 'false-positive', detectionId: '123' });
      const retrieved = store.get(added.id);

      expect(retrieved).toBeDefined();
      expect(retrieved?.id).toBe(added.id);
      expect(retrieved?.detectionId).toBe('123');
    });

    it('should return undefined for non-existent ID', () => {
      const result = store.get('non-existent-id');
      expect(result).toBeUndefined();
    });
  });

  describe('getAll', () => {
    it('should return all entries sorted by timestamp (newest first)', async () => {
      store.add({ type: 'false-positive', detectionId: '1' });
      await new Promise(r => setTimeout(r, 10));
      store.add({ type: 'false-negative', description: 'test' });
      await new Promise(r => setTimeout(r, 10));
      store.add({ type: 'false-positive', detectionId: '2' });

      const all = store.getAll();

      expect(all).toHaveLength(3);
      expect(all[0].detectionId).toBe('2'); // Newest
      expect(all[2].detectionId).toBe('1'); // Oldest
    });

    it('should return empty array when no entries', () => {
      const all = store.getAll();
      expect(all).toHaveLength(0);
    });
  });

  describe('getByType', () => {
    it('should filter entries by type', () => {
      store.add({ type: 'false-positive', detectionId: '1' });
      store.add({ type: 'false-negative', description: 'test 1' });
      store.add({ type: 'false-positive', detectionId: '2' });
      store.add({ type: 'false-negative', description: 'test 2' });

      const falsePositives = store.getByType('false-positive');
      const falseNegatives = store.getByType('false-negative');

      expect(falsePositives).toHaveLength(2);
      expect(falseNegatives).toHaveLength(2);
      expect(falsePositives.every(e => e.type === 'false-positive')).toBe(true);
      expect(falseNegatives.every(e => e.type === 'false-negative')).toBe(true);
    });
  });

  describe('updateStatus', () => {
    it('should update the status of an entry', () => {
      const entry = store.add({ type: 'false-positive', detectionId: '1' });

      const result = store.updateStatus(entry.id, 'reviewed');

      expect(result).toBe(true);
      expect(store.get(entry.id)?.status).toBe('reviewed');
    });

    it('should update status and notes', () => {
      const entry = store.add({ type: 'false-positive', detectionId: '1' });

      store.updateStatus(entry.id, 'applied', 'Pattern updated');

      const updated = store.get(entry.id);
      expect(updated?.status).toBe('applied');
      expect(updated?.notes).toBe('Pattern updated');
    });

    it('should return false for non-existent entry', () => {
      const result = store.updateStatus('non-existent', 'reviewed');
      expect(result).toBe(false);
    });
  });

  describe('remove', () => {
    it('should remove an entry', () => {
      const entry = store.add({ type: 'false-positive', detectionId: '1' });

      const result = store.remove(entry.id);

      expect(result).toBe(true);
      expect(store.get(entry.id)).toBeUndefined();
      expect(store.size()).toBe(0);
    });

    it('should return false for non-existent entry', () => {
      const result = store.remove('non-existent');
      expect(result).toBe(false);
    });
  });

  describe('persistence', () => {
    it('should save and load entries', async () => {
      const entry1 = store.add({ type: 'false-positive', detectionId: '1' });
      const entry2 = store.add({ type: 'false-negative', description: 'test' });

      await store.save();

      // Create a new store pointing to the same file
      const store2 = createFeedbackStore(tempDir);
      await store2.load();

      expect(store2.size()).toBe(2);
      expect(store2.get(entry1.id)?.detectionId).toBe('1');
      expect(store2.get(entry2.id)?.description).toBe('test');
    });

    it('should create storage directory if not exists', async () => {
      const subDir = join(tempDir, 'nested', 'path');
      const nestedStore = new FileFeedbackStore(subDir);
      nestedStore.add({ type: 'false-positive', detectionId: '1' });

      await nestedStore.save();

      // File should exist
      const filePath = nestedStore.getFilePath();
      const content = await readFile(filePath, 'utf-8');
      expect(JSON.parse(content)).toHaveLength(1);
    });

    it('should handle missing file on load', async () => {
      await store.load();

      expect(store.isLoaded()).toBe(true);
      expect(store.size()).toBe(0);
    });

    it('should handle invalid JSON on load', async () => {
      // Create invalid JSON file
      const dir = join(tempDir, '.clawsec');
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, 'feedback.json'), 'invalid json', 'utf-8');

      // Should not throw, just start with empty store
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      await store.load();

      expect(store.isLoaded()).toBe(true);
      expect(store.size()).toBe(0);
      expect(warnSpy).toHaveBeenCalled();
      warnSpy.mockRestore();
    });
  });

  describe('utility methods', () => {
    it('should report correct size', () => {
      expect(store.size()).toBe(0);

      store.add({ type: 'false-positive', detectionId: '1' });
      expect(store.size()).toBe(1);

      store.add({ type: 'false-positive', detectionId: '2' });
      expect(store.size()).toBe(2);
    });

    it('should clear all entries', () => {
      store.add({ type: 'false-positive', detectionId: '1' });
      store.add({ type: 'false-positive', detectionId: '2' });

      store.clear();

      expect(store.size()).toBe(0);
    });

    it('should return file path', () => {
      const path = store.getFilePath();
      expect(path).toContain('.clawsec');
      expect(path).toContain('feedback.json');
    });
  });
});

// =============================================================================
// GLOBAL STORE TESTS
// =============================================================================

describe('Global Feedback Store', () => {
  afterEach(() => {
    resetGlobalFeedbackStore();
  });

  it('should return the same instance on multiple calls', () => {
    const store1 = getFeedbackStore();
    const store2 = getFeedbackStore();

    expect(store1).toBe(store2);
  });

  it('should reset the global store', () => {
    const store1 = getFeedbackStore();
    store1.add({ type: 'false-positive', detectionId: '1' });

    resetGlobalFeedbackStore();

    const store2 = getFeedbackStore();
    expect(store2).not.toBe(store1);
    expect(store2.size()).toBe(0);
  });
});

// =============================================================================
// FEEDBACK COMMAND TESTS
// =============================================================================

describe('Feedback Command', () => {
  let tempDir: string;
  let store: FileFeedbackStore;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'clawsec-feedback-cmd-test-'));
    store = createFeedbackStore(tempDir);
    await store.load();
    clearAuditLog();
  });

  afterEach(async () => {
    store.clear();
    clearAuditLog();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe('false positive submission', () => {
    it('should submit a false positive', async () => {
      const result = await feedbackCommand(
        { falsePositive: '123' },
        store
      );

      expect(result.success).toBe(true);
      expect(result.entry).toBeDefined();
      expect(result.entry?.type).toBe('false-positive');
      expect(result.entry?.detectionId).toBe('123');
      expect(store.size()).toBe(1);
    });

    it('should link to audit log entry when available', async () => {
      // Add an audit entry
      addAuditEntry({
        toolName: 'bash',
        category: 'secrets',
        severity: 'critical',
        action: 'block',
        reason: 'API key detected',
        metadata: { command: 'echo $SECRET' },
      });

      const result = await feedbackCommand(
        { falsePositive: '1' },
        store
      );

      expect(result.success).toBe(true);
      expect(result.entry?.detection).toBeDefined();
      expect(result.entry?.detection?.category).toBe('secrets');
      expect(result.entry?.detection?.reason).toBe('API key detected');
    });
  });

  describe('false negative submission', () => {
    it('should submit a false negative', async () => {
      const result = await feedbackCommand(
        { falseNegative: 'API key was leaked' },
        store
      );

      expect(result.success).toBe(true);
      expect(result.entry).toBeDefined();
      expect(result.entry?.type).toBe('false-negative');
      expect(result.entry?.description).toBe('API key was leaked');
    });

    it('should submit a false negative with category', async () => {
      const result = await feedbackCommand(
        { falseNegative: 'API key was leaked', category: 'secrets' },
        store
      );

      expect(result.success).toBe(true);
      expect(result.entry?.suggestedCategory).toBe('secrets');
    });

    it('should reject invalid category', async () => {
      const result = await feedbackCommand(
        { falseNegative: 'test', category: 'invalid' as any },
        store
      );

      expect(result.success).toBe(false);
      expect(result.message).toContain('Invalid category');
    });
  });

  describe('list operation', () => {
    it('should list all entries', async () => {
      store.add({ type: 'false-positive', detectionId: '1' });
      store.add({ type: 'false-negative', description: 'test' });

      const result = await feedbackCommand({ list: true }, store);

      expect(result.success).toBe(true);
      expect(result.entries).toHaveLength(2);
    });

    it('should filter by type', async () => {
      store.add({ type: 'false-positive', detectionId: '1' });
      store.add({ type: 'false-negative', description: 'test' });
      store.add({ type: 'false-positive', detectionId: '2' });

      const result = await feedbackCommand(
        { list: true, type: 'false-positive' },
        store
      );

      expect(result.success).toBe(true);
      expect(result.entries).toHaveLength(2);
      expect(result.entries?.every(e => e.type === 'false-positive')).toBe(true);
    });

    it('should return empty list when no entries', async () => {
      const result = await feedbackCommand({ list: true }, store);

      expect(result.success).toBe(true);
      expect(result.entries).toHaveLength(0);
    });
  });

  describe('show operation', () => {
    it('should show entry details', async () => {
      const entry = store.add({ type: 'false-positive', detectionId: '123' });

      const result = await feedbackCommand({ show: entry.id }, store);

      expect(result.success).toBe(true);
      expect(result.entry).toBeDefined();
      expect(result.entry?.id).toBe(entry.id);
    });

    it('should return error for non-existent entry', async () => {
      const result = await feedbackCommand({ show: 'non-existent' }, store);

      expect(result.success).toBe(false);
      expect(result.message).toContain('not found');
    });
  });

  describe('no operation specified', () => {
    it('should return error when no operation specified', async () => {
      const result = await feedbackCommand({}, store);

      expect(result.success).toBe(false);
      expect(result.message).toContain('No operation specified');
    });
  });
});

// =============================================================================
// FORMAT FUNCTIONS TESTS
// =============================================================================

describe('Format Functions', () => {
  describe('formatFeedbackResult', () => {
    it('should format error result', () => {
      const result = {
        success: false,
        message: 'Something went wrong',
      };

      const output = formatFeedbackResult(result);

      expect(output).toContain('Error:');
      expect(output).toContain('Something went wrong');
    });

    it('should format single entry result', () => {
      const entry: FeedbackEntry = {
        id: 'abc123',
        type: 'false-positive',
        timestamp: Date.now(),
        status: 'pending',
        detectionId: '456',
        detection: {
          category: 'secrets',
          severity: 'critical',
          reason: 'API key detected',
          toolName: 'bash',
          toolInput: { command: 'echo test' },
        },
      };

      const result = {
        success: true,
        message: 'Feedback submitted',
        entry,
      };

      const output = formatFeedbackResult(result);

      expect(output).toContain('abc123');
      expect(output).toContain('false-positive');
      expect(output).toContain('pending');
      expect(output).toContain('secrets');
      expect(output).toContain('API key detected');
    });

    it('should format list result', () => {
      const entries: FeedbackEntry[] = [
        {
          id: 'abc123',
          type: 'false-positive',
          timestamp: Date.now(),
          status: 'pending',
          detectionId: '1',
        },
        {
          id: 'def456',
          type: 'false-negative',
          timestamp: Date.now(),
          status: 'reviewed',
          description: 'Missed threat',
        },
      ];

      const result = {
        success: true,
        message: 'Found 2 feedback entries',
        entries,
      };

      const output = formatFeedbackResult(result);

      expect(output).toContain('Found 2 feedback entries');
      expect(output).toContain('abc123');
      expect(output).toContain('def456');
      expect(output).toContain('Missed threat');
    });

    it('should format empty list', () => {
      const result = {
        success: true,
        message: 'Found 0 feedback entries',
        entries: [],
      };

      const output = formatFeedbackResult(result);

      expect(output).toContain('No feedback entries found');
    });
  });

  describe('formatFeedbackSummary', () => {
    it('should format false positive summary', () => {
      const entry: FeedbackEntry = {
        id: 'abc12345-6789-0123-4567-890abcdef012',
        type: 'false-positive',
        timestamp: new Date('2024-01-15').getTime(),
        status: 'pending',
        detection: {
          category: 'secrets',
          severity: 'critical',
          reason: 'API key detected',
          toolName: 'bash',
          toolInput: {},
        },
      };

      const summary = formatFeedbackSummary(entry);

      expect(summary).toContain('[abc12345]');
      expect(summary).toContain('2024-01-15');
      expect(summary).toContain('FP:');
      expect(summary).toContain('secrets');
      expect(summary).toContain('API key detected');
    });

    it('should format false negative summary', () => {
      const entry: FeedbackEntry = {
        id: 'def12345-6789-0123-4567-890abcdef012',
        type: 'false-negative',
        timestamp: new Date('2024-02-20').getTime(),
        status: 'pending',
        description: 'Password was exposed in logs',
      };

      const summary = formatFeedbackSummary(entry);

      expect(summary).toContain('[def12345]');
      expect(summary).toContain('2024-02-20');
      expect(summary).toContain('FN:');
      expect(summary).toContain('Password was exposed in logs');
    });

    it('should truncate long descriptions', () => {
      const entry: FeedbackEntry = {
        id: 'xyz12345-6789-0123-4567-890abcdef012',
        type: 'false-negative',
        timestamp: Date.now(),
        status: 'pending',
        description: 'This is a very long description that should be truncated because it exceeds fifty characters',
      };

      const summary = formatFeedbackSummary(entry);

      expect(summary.length).toBeLessThan(150);
      expect(summary).toContain('...');
    });
  });
});

// =============================================================================
// CLI INTEGRATION TESTS
// =============================================================================

describe('CLI Integration', () => {
  let tempDir: string;
  let store: FileFeedbackStore;
  let consoleOutput: string[] = [];
  let consoleError: string[] = [];
  const originalLog = console.log;
  const originalError = console.error;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'clawsec-feedback-cli-test-'));
    store = createFeedbackStore(tempDir);
    await store.load();
    clearAuditLog();
    resetGlobalFeedbackStore();

    consoleOutput = [];
    consoleError = [];
    console.log = (...args: unknown[]) => {
      consoleOutput.push(args.map(String).join(' '));
    };
    console.error = (...args: unknown[]) => {
      consoleError.push(args.map(String).join(' '));
    };
  });

  afterEach(async () => {
    console.log = originalLog;
    console.error = originalError;
    store.clear();
    clearAuditLog();
    resetGlobalFeedbackStore();
    await rm(tempDir, { recursive: true, force: true });
  });

  // We need to import runCLI dynamically to test the full CLI flow
  // For now, we test through the command function directly
  it('should run feedback list command', async () => {
    store.add({ type: 'false-positive', detectionId: '1' });
    store.add({ type: 'false-negative', description: 'test' });

    const result = await feedbackCommand({ list: true }, store);
    console.log(formatFeedbackResult(result));

    expect(consoleOutput.join('\n')).toContain('Found 2 feedback entries');
  });

  it('should run feedback with type filter', async () => {
    store.add({ type: 'false-positive', detectionId: '1' });
    store.add({ type: 'false-negative', description: 'test' });

    const result = await feedbackCommand(
      { list: true, type: 'false-negative' },
      store
    );
    console.log(formatFeedbackResult(result));

    expect(consoleOutput.join('\n')).toContain('Found 1 feedback entry');
  });
});

// =============================================================================
// LEARNER TESTS
// =============================================================================

import {
  FileWeightStore,
  PatternLearner,
  createWeightStore,
  createLearner,
  getLearner,
  getWeightStore,
  resetGlobalLearner,
} from './learner.js';
import type { PatternWeight } from './learner.js';

describe('FileWeightStore', () => {
  let tempDir: string;
  let store: FileWeightStore;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'clawsec-weight-test-'));
    store = createWeightStore(tempDir);
  });

  afterEach(async () => {
    store.clear();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe('weight adjustment math', () => {
    it('should start with weight 1.0 for unknown patterns', () => {
      const weight = store.getWeight('unknown-pattern');
      expect(weight).toBe(1.0);
    });

    it('should apply decay factor for false positives', () => {
      // False positive: adjustedWeight = baseWeight * (1 - decayFactor * fpCount)
      // With decayFactor = 0.1 and 1 FP: 1.0 * (1 - 0.1 * 1) = 0.9
      store.adjustForFalsePositive('test-pattern', 'secrets');
      expect(store.getWeight('test-pattern')).toBeCloseTo(0.9, 5);

      // With 2 FPs: 1.0 * (1 - 0.1 * 2) = 0.8
      store.adjustForFalsePositive('test-pattern', 'secrets');
      expect(store.getWeight('test-pattern')).toBeCloseTo(0.8, 5);

      // With 3 FPs: 1.0 * (1 - 0.1 * 3) = 0.7
      store.adjustForFalsePositive('test-pattern', 'secrets');
      expect(store.getWeight('test-pattern')).toBeCloseTo(0.7, 5);
    });

    it('should apply boost factor for false negatives', () => {
      // False negative: adjustedWeight = min(1, baseWeight * (1 + boostFactor * fnCount))
      // With boostFactor = 0.05 and 1 FN: 1.0 * (1 + 0.05 * 1) = 1.05 -> clamped to 1.0
      store.adjustForFalseNegative('test-pattern', 'secrets');
      expect(store.getWeight('test-pattern')).toBe(1.0);
    });

    it('should combine FP and FN adjustments correctly', () => {
      // First apply 3 FPs to get base lower
      store.adjustForFalsePositive('test-pattern', 'secrets');
      store.adjustForFalsePositive('test-pattern', 'secrets');
      store.adjustForFalsePositive('test-pattern', 'secrets');
      // 3 FPs: 1.0 * (1 - 0.1 * 3) = 0.7
      expect(store.getWeight('test-pattern')).toBeCloseTo(0.7, 5);

      // Now add 2 FNs
      store.adjustForFalseNegative('test-pattern', 'secrets');
      store.adjustForFalseNegative('test-pattern', 'secrets');
      // Formula: baseWeight * (1 - decayFactor * fpCount) * (1 + boostFactor * fnCount)
      // = 1.0 * (1 - 0.1 * 3) * (1 + 0.05 * 2) = 0.7 * 1.1 = 0.77
      expect(store.getWeight('test-pattern')).toBeCloseTo(0.77, 5);
    });

    it('should respect minimum weight of 0.1', () => {
      // Apply many FPs to try to drive weight below minimum
      for (let i = 0; i < 20; i++) {
        store.adjustForFalsePositive('test-pattern', 'secrets');
      }
      expect(store.getWeight('test-pattern')).toBe(0.1);
    });

    it('should respect maximum weight of 1.0', () => {
      // Apply many FNs
      for (let i = 0; i < 50; i++) {
        store.adjustForFalseNegative('test-pattern', 'secrets');
      }
      expect(store.getWeight('test-pattern')).toBe(1.0);
    });
  });

  describe('false positive reduces weight', () => {
    it('should reduce weight for each false positive', () => {
      store.adjustForFalsePositive('api-key-pattern', 'secrets');
      const weight1 = store.getWeight('api-key-pattern');

      store.adjustForFalsePositive('api-key-pattern', 'secrets');
      const weight2 = store.getWeight('api-key-pattern');

      expect(weight2).toBeLessThan(weight1);
      expect(weight1).toBeLessThan(1.0);
    });

    it('should track false positive count', () => {
      store.adjustForFalsePositive('test-pattern', 'destructive');
      store.adjustForFalsePositive('test-pattern', 'destructive');
      store.adjustForFalsePositive('test-pattern', 'destructive');

      const patternWeight = store.weights.get('test-pattern');
      expect(patternWeight?.falsePositives).toBe(3);
    });
  });

  describe('false negative increases weight', () => {
    it('should track false negative count', () => {
      store.adjustForFalseNegative('test-pattern', 'exfiltration');
      store.adjustForFalseNegative('test-pattern', 'exfiltration');

      const patternWeight = store.weights.get('test-pattern');
      expect(patternWeight?.falseNegatives).toBe(2);
    });

    it('should boost weight when starting from lower base', () => {
      // First reduce weight with FPs
      store.adjustForFalsePositive('test-pattern', 'secrets');
      store.adjustForFalsePositive('test-pattern', 'secrets');
      const reducedWeight = store.getWeight('test-pattern');

      // Then boost with FN
      store.adjustForFalseNegative('test-pattern', 'secrets');
      const boostedWeight = store.getWeight('test-pattern');

      expect(boostedWeight).toBeGreaterThan(reducedWeight);
    });
  });

  describe('file persistence', () => {
    it('should save and load weights', async () => {
      store.adjustForFalsePositive('pattern-1', 'secrets');
      store.adjustForFalsePositive('pattern-1', 'secrets');
      store.adjustForFalseNegative('pattern-2', 'destructive');

      await store.save();

      // Create a new store pointing to same file
      const store2 = createWeightStore(tempDir);
      await store2.load();

      expect(store2.size()).toBe(2);
      expect(store2.getWeight('pattern-1')).toBeCloseTo(store.getWeight('pattern-1'), 5);
      expect(store2.getWeight('pattern-2')).toBeCloseTo(store.getWeight('pattern-2'), 5);

      const p1 = store2.weights.get('pattern-1');
      expect(p1?.falsePositives).toBe(2);
      expect(p1?.category).toBe('secrets');
    });

    it('should create directory if not exists', async () => {
      const nestedDir = join(tempDir, 'nested', 'path');
      const nestedStore = new FileWeightStore(nestedDir);
      nestedStore.adjustForFalsePositive('test', 'secrets');

      await nestedStore.save();

      const content = await readFile(nestedStore.getFilePath(), 'utf-8');
      const data = JSON.parse(content) as PatternWeight[];
      expect(data).toHaveLength(1);
      expect(data[0].pattern).toBe('test');
    });

    it('should handle missing file on load', async () => {
      await store.load();
      expect(store.isLoaded()).toBe(true);
      expect(store.size()).toBe(0);
    });

    it('should handle invalid JSON on load', async () => {
      const dir = join(tempDir, '.clawsec');
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, 'weights.json'), 'invalid json', 'utf-8');

      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      await store.load();

      expect(store.isLoaded()).toBe(true);
      expect(store.size()).toBe(0);
      expect(warnSpy).toHaveBeenCalled();
      warnSpy.mockRestore();
    });
  });

  describe('reset', () => {
    it('should reset a specific pattern', () => {
      store.adjustForFalsePositive('pattern-1', 'secrets');
      store.adjustForFalsePositive('pattern-1', 'secrets');
      store.adjustForFalsePositive('pattern-2', 'destructive');

      store.reset('pattern-1');

      const p1 = store.weights.get('pattern-1');
      expect(p1?.adjustedWeight).toBe(p1?.baseWeight);
      expect(p1?.falsePositives).toBe(0);
      expect(p1?.falseNegatives).toBe(0);

      // pattern-2 should be unchanged
      const p2 = store.weights.get('pattern-2');
      expect(p2?.falsePositives).toBe(1);
    });

    it('should reset all patterns when no argument', () => {
      store.adjustForFalsePositive('pattern-1', 'secrets');
      store.adjustForFalsePositive('pattern-2', 'destructive');
      store.adjustForFalseNegative('pattern-3', 'exfiltration');

      store.reset();

      for (const [_, weight] of store.weights) {
        expect(weight.adjustedWeight).toBe(weight.baseWeight);
        expect(weight.falsePositives).toBe(0);
        expect(weight.falseNegatives).toBe(0);
      }
    });
  });
});

describe('PatternLearner', () => {
  let tempDir: string;
  let weightStore: FileWeightStore;
  let learner: PatternLearner;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'clawsec-learner-test-'));
    weightStore = createWeightStore(tempDir);
    learner = createLearner(weightStore);
  });

  afterEach(async () => {
    weightStore.clear();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe('processFeedback', () => {
    it('should only process feedback with applied status', async () => {
      const pendingEntry: FeedbackEntry = {
        id: '1',
        type: 'false-positive',
        timestamp: Date.now(),
        status: 'pending',
        detection: {
          category: 'secrets',
          severity: 'high',
          reason: 'API key detected',
          toolName: 'bash',
          toolInput: {},
        },
      };

      await learner.processFeedback(pendingEntry);

      expect(weightStore.size()).toBe(0);
      expect(learner.getStats().totalAdjustments).toBe(0);
    });

    it('should process false positive feedback', async () => {
      const entry: FeedbackEntry = {
        id: '1',
        type: 'false-positive',
        timestamp: Date.now(),
        status: 'applied',
        detection: {
          category: 'secrets',
          severity: 'high',
          reason: 'API key detected',
          toolName: 'bash',
          toolInput: {},
        },
      };

      await learner.processFeedback(entry);

      expect(weightStore.size()).toBe(1);
      expect(weightStore.getWeight('API key detected')).toBeLessThan(1.0);

      const stats = learner.getStats();
      expect(stats.totalAdjustments).toBe(1);
      expect(stats.falsePositivesProcessed).toBe(1);
      expect(stats.patternsAdjusted).toBe(1);
    });

    it('should process false negative feedback', async () => {
      const entry: FeedbackEntry = {
        id: '1',
        type: 'false-negative',
        timestamp: Date.now(),
        status: 'applied',
        description: 'Password leak missed',
        suggestedCategory: 'secrets',
      };

      await learner.processFeedback(entry);

      expect(weightStore.size()).toBe(1);

      const stats = learner.getStats();
      expect(stats.totalAdjustments).toBe(1);
      expect(stats.falseNegativesProcessed).toBe(1);
    });

    it('should use detection reason as pattern for false positives', async () => {
      const entry: FeedbackEntry = {
        id: '1',
        type: 'false-positive',
        timestamp: Date.now(),
        status: 'applied',
        detection: {
          category: 'destructive',
          severity: 'critical',
          reason: 'rm -rf command detected',
          toolName: 'bash',
          toolInput: { command: 'rm -rf /tmp/test' },
        },
      };

      await learner.processFeedback(entry);

      const patternWeight = weightStore.weights.get('rm -rf command detected');
      expect(patternWeight).toBeDefined();
      expect(patternWeight?.category).toBe('destructive');
    });

    it('should use description as pattern for false negatives', async () => {
      const entry: FeedbackEntry = {
        id: '1',
        type: 'false-negative',
        timestamp: Date.now(),
        status: 'applied',
        description: 'AWS credentials exposed',
        suggestedCategory: 'secrets',
      };

      await learner.processFeedback(entry);

      const patternWeight = weightStore.weights.get('AWS credentials exposed');
      expect(patternWeight).toBeDefined();
    });
  });

  describe('processFeedbackBatch', () => {
    it('should process multiple entries efficiently', async () => {
      const entries: FeedbackEntry[] = [
        {
          id: '1',
          type: 'false-positive',
          timestamp: Date.now(),
          status: 'applied',
          detection: {
            category: 'secrets',
            severity: 'high',
            reason: 'Pattern A',
            toolName: 'bash',
            toolInput: {},
          },
        },
        {
          id: '2',
          type: 'false-positive',
          timestamp: Date.now(),
          status: 'applied',
          detection: {
            category: 'secrets',
            severity: 'high',
            reason: 'Pattern B',
            toolName: 'bash',
            toolInput: {},
          },
        },
        {
          id: '3',
          type: 'false-negative',
          timestamp: Date.now(),
          status: 'applied',
          description: 'Pattern C',
          suggestedCategory: 'destructive',
        },
        {
          id: '4',
          type: 'false-positive',
          timestamp: Date.now(),
          status: 'pending', // Should be skipped
          detection: {
            category: 'secrets',
            severity: 'high',
            reason: 'Pattern D',
            toolName: 'bash',
            toolInput: {},
          },
        },
      ];

      await learner.processFeedbackBatch(entries);

      expect(weightStore.size()).toBe(3);
      expect(weightStore.weights.has('Pattern D')).toBe(false);

      const stats = learner.getStats();
      expect(stats.totalAdjustments).toBe(3);
      expect(stats.falsePositivesProcessed).toBe(2);
      expect(stats.falseNegativesProcessed).toBe(1);
      expect(stats.patternsAdjusted).toBe(3);
    });
  });

  describe('getAdjustedConfidence', () => {
    it('should return base confidence for unknown patterns', () => {
      const adjusted = learner.getAdjustedConfidence(0.85, 'unknown', 'secrets');
      expect(adjusted).toBe(0.85);
    });

    it('should reduce confidence for patterns with false positives', async () => {
      // Add false positive feedback
      const entry: FeedbackEntry = {
        id: '1',
        type: 'false-positive',
        timestamp: Date.now(),
        status: 'applied',
        detection: {
          category: 'secrets',
          severity: 'high',
          reason: 'Test pattern',
          toolName: 'bash',
          toolInput: {},
        },
      };
      await learner.processFeedback(entry);

      const adjusted = learner.getAdjustedConfidence(0.9, 'Test pattern', 'secrets');
      expect(adjusted).toBeLessThan(0.9);
      // 0.9 * 0.9 (weight after 1 FP) = 0.81
      expect(adjusted).toBeCloseTo(0.81, 5);
    });

    it('should clamp adjusted confidence to valid range', async () => {
      // Add many false positives
      for (let i = 0; i < 10; i++) {
        const entry: FeedbackEntry = {
          id: `${i}`,
          type: 'false-positive',
          timestamp: Date.now(),
          status: 'applied',
          detection: {
            category: 'secrets',
            severity: 'high',
            reason: 'Heavily penalized',
            toolName: 'bash',
            toolInput: {},
          },
        };
        await learner.processFeedback(entry);
      }

      const adjusted = learner.getAdjustedConfidence(0.9, 'Heavily penalized', 'secrets');
      expect(adjusted).toBeGreaterThanOrEqual(0);
      expect(adjusted).toBeLessThanOrEqual(1);
    });
  });

  describe('stats tracking', () => {
    it('should track statistics correctly', async () => {
      let stats = learner.getStats();
      expect(stats.totalAdjustments).toBe(0);
      expect(stats.falsePositivesProcessed).toBe(0);
      expect(stats.falseNegativesProcessed).toBe(0);
      expect(stats.patternsAdjusted).toBe(0);

      // Process some feedback
      await learner.processFeedback({
        id: '1',
        type: 'false-positive',
        timestamp: Date.now(),
        status: 'applied',
        detection: {
          category: 'secrets',
          severity: 'high',
          reason: 'Pattern 1',
          toolName: 'bash',
          toolInput: {},
        },
      });

      await learner.processFeedback({
        id: '2',
        type: 'false-positive',
        timestamp: Date.now(),
        status: 'applied',
        detection: {
          category: 'secrets',
          severity: 'high',
          reason: 'Pattern 1', // Same pattern
          toolName: 'bash',
          toolInput: {},
        },
      });

      await learner.processFeedback({
        id: '3',
        type: 'false-negative',
        timestamp: Date.now(),
        status: 'applied',
        description: 'Pattern 2',
        suggestedCategory: 'destructive',
      });

      stats = learner.getStats();
      expect(stats.totalAdjustments).toBe(3);
      expect(stats.falsePositivesProcessed).toBe(2);
      expect(stats.falseNegativesProcessed).toBe(1);
      expect(stats.patternsAdjusted).toBe(2); // Only 2 unique patterns
    });

    it('should reset stats', async () => {
      await learner.processFeedback({
        id: '1',
        type: 'false-positive',
        timestamp: Date.now(),
        status: 'applied',
        detection: {
          category: 'secrets',
          severity: 'high',
          reason: 'Test',
          toolName: 'bash',
          toolInput: {},
        },
      });

      learner.resetStats();

      const stats = learner.getStats();
      expect(stats.totalAdjustments).toBe(0);
      expect(stats.falsePositivesProcessed).toBe(0);
      expect(stats.falseNegativesProcessed).toBe(0);
      expect(stats.patternsAdjusted).toBe(0);
    });
  });
});

describe('Global Learner', () => {
  afterEach(() => {
    resetGlobalLearner();
  });

  it('should return the same learner instance', () => {
    const learner1 = getLearner();
    const learner2 = getLearner();
    expect(learner1).toBe(learner2);
  });

  it('should return the same weight store instance', () => {
    const store1 = getWeightStore();
    const store2 = getWeightStore();
    expect(store1).toBe(store2);
  });

  it('should reset global instances', () => {
    const learner1 = getLearner();
    resetGlobalLearner();
    const learner2 = getLearner();
    expect(learner2).not.toBe(learner1);
  });
});
