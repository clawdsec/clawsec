/**
 * Tests for the Tool Result Persist Hook Handler
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createToolResultPersistHandler,
  createDefaultToolResultPersistHandler,
} from './handler.js';
import {
  filterOutput,
  filterValue,
  redactString,
  redactObject,
  redactArray,
  detectionsToRedactions,
} from './filter.js';
import type { ToolResultContext, ToolResultPersistResult } from '../../index.js';
import type { ClawsecConfig } from '../../config/schema.js';
import type { SecretsDetectionResult } from '../../detectors/secrets/types.js';

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
      native: { enabled: true, timeout: 300 },
      agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
      webhook: { enabled: false, timeout: 30, headers: {} },
    },
    ...overrides,
  };
}

/**
 * Create a test tool result context
 */
function createTestToolResultContext(
  overrides: Partial<ToolResultContext> = {}
): ToolResultContext {
  return {
    sessionId: 'test-session-123',
    timestamp: Date.now(),
    toolName: 'test_tool',
    toolInput: { arg: 'value' },
    toolOutput: 'test output',
    ...overrides,
  };
}

// =============================================================================
// FILTER UNIT TESTS
// =============================================================================

describe('Filter Module', () => {
  describe('redactString', () => {
    it('should redact OpenAI API key', () => {
      const input = 'My API key is sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234';
      const result = redactString(input);

      expect(result.wasRedacted).toBe(true);
      expect(result.filteredOutput).toBe('My API key is [REDACTED:openai-api-key]');
      expect(result.redactions).toHaveLength(1);
      expect(result.redactions[0].type).toBe('openai-api-key');
    });

    it('should redact Anthropic API key', () => {
      const input = 'Using key sk-ant-api03-abc123xyz789def456ghi012jkl345mno678';
      const result = redactString(input);

      expect(result.wasRedacted).toBe(true);
      expect(result.filteredOutput).toContain('[REDACTED:anthropic-api-key]');
      expect(result.redactions.some((r) => r.type === 'anthropic-api-key')).toBe(true);
    });

    it('should redact AWS access key ID', () => {
      const input = 'AWS key: AKIAIOSFODNN7EXAMPLE';
      const result = redactString(input);

      expect(result.wasRedacted).toBe(true);
      expect(result.filteredOutput).toBe('AWS key: [REDACTED:aws-access-key]');
      expect(result.redactions[0].type).toBe('aws-access-key');
    });

    it('should redact GitHub token', () => {
      const input = 'Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const result = redactString(input);

      expect(result.wasRedacted).toBe(true);
      // The token matches the github-token pattern (broader pattern)
      expect(result.filteredOutput).toContain('[REDACTED:github-');
    });

    it('should redact Stripe API key', () => {
      const input = 'Stripe key: sk_live_abcdefghijklmnopqrstuvwxyz';
      const result = redactString(input);

      expect(result.wasRedacted).toBe(true);
      expect(result.filteredOutput).toContain('[REDACTED:stripe-api-key]');
    });

    it('should redact JWT token', () => {
      const input =
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const result = redactString(input);

      expect(result.wasRedacted).toBe(true);
      expect(result.filteredOutput).toContain('[REDACTED:jwt]');
    });

    it('should redact SSN', () => {
      const input = 'SSN: 123-45-6789';
      const result = redactString(input);

      expect(result.wasRedacted).toBe(true);
      expect(result.filteredOutput).toBe('SSN: [REDACTED:ssn]');
      expect(result.redactions[0].type).toBe('ssn');
    });

    it('should redact credit card numbers', () => {
      const input = 'Card: 4111-1111-1111-1111';
      const result = redactString(input);

      expect(result.wasRedacted).toBe(true);
      expect(result.filteredOutput).toContain('[REDACTED:credit-card]');
    });

    it('should redact private keys', () => {
      const input = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`;
      const result = redactString(input);

      expect(result.wasRedacted).toBe(true);
      expect(result.filteredOutput).toBe('[REDACTED:private-key]');
    });

    it('should redact multiple secrets in one string', () => {
      const input =
        'Key: sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234, SSN: 123-45-6789';
      const result = redactString(input);

      expect(result.wasRedacted).toBe(true);
      expect(result.filteredOutput).toContain('[REDACTED:openai-api-key]');
      expect(result.filteredOutput).toContain('[REDACTED:ssn]');
      expect(result.redactions.length).toBeGreaterThanOrEqual(2);
    });

    it('should not redact clean text', () => {
      const input = 'This is a normal message with no secrets';
      const result = redactString(input);

      expect(result.wasRedacted).toBe(false);
      expect(result.filteredOutput).toBe(input);
      expect(result.redactions).toHaveLength(0);
    });

    it('should handle empty string', () => {
      const result = redactString('');

      expect(result.wasRedacted).toBe(false);
      expect(result.filteredOutput).toBe('');
      expect(result.redactions).toHaveLength(0);
    });
  });

  describe('redactObject', () => {
    it('should redact secrets in object values', () => {
      const input = {
        name: 'Test',
        apiKey: 'sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
      };
      const result = redactObject(input);

      expect(result.wasRedacted).toBe(true);
      const filtered = result.filteredOutput as Record<string, unknown>;
      expect(filtered.name).toBe('Test');
      expect(filtered.apiKey).toBe('[REDACTED:openai-api-key]');
    });

    it('should recursively redact nested objects', () => {
      const input = {
        config: {
          credentials: {
            awsKey: 'AKIAIOSFODNN7EXAMPLE',
          },
        },
      };
      const result = redactObject(input);

      expect(result.wasRedacted).toBe(true);
      const filtered = result.filteredOutput as {
        config: { credentials: { awsKey: string } };
      };
      expect(filtered.config.credentials.awsKey).toBe('[REDACTED:aws-access-key]');
    });

    it('should handle mixed value types', () => {
      const input = {
        count: 42,
        enabled: true,
        secret: 'sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
        nothing: null,
      };
      const result = redactObject(input);

      expect(result.wasRedacted).toBe(true);
      const filtered = result.filteredOutput as Record<string, unknown>;
      expect(filtered.count).toBe(42);
      expect(filtered.enabled).toBe(true);
      expect(filtered.secret).toBe('[REDACTED:openai-api-key]');
      expect(filtered.nothing).toBe(null);
    });

    it('should handle clean objects', () => {
      const input = {
        name: 'Test',
        value: 123,
      };
      const result = redactObject(input);

      expect(result.wasRedacted).toBe(false);
      expect(result.filteredOutput).toEqual(input);
    });
  });

  describe('redactArray', () => {
    it('should redact secrets in array elements', () => {
      const input = ['normal', 'sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234'];
      const result = redactArray(input);

      expect(result.wasRedacted).toBe(true);
      const filtered = result.filteredOutput as string[];
      expect(filtered[0]).toBe('normal');
      expect(filtered[1]).toBe('[REDACTED:openai-api-key]');
    });

    it('should handle arrays with objects', () => {
      const input = [
        { key: 'sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234' },
        { key: 'normal' },
      ];
      const result = redactArray(input);

      expect(result.wasRedacted).toBe(true);
      const filtered = result.filteredOutput as Array<{ key: string }>;
      expect(filtered[0].key).toBe('[REDACTED:openai-api-key]');
      expect(filtered[1].key).toBe('normal');
    });

    it('should handle clean arrays', () => {
      const input = ['a', 'b', 'c'];
      const result = redactArray(input);

      expect(result.wasRedacted).toBe(false);
      expect(result.filteredOutput).toEqual(input);
    });
  });

  describe('filterValue', () => {
    it('should handle null', () => {
      const result = filterValue(null);

      expect(result.wasRedacted).toBe(false);
      expect(result.filteredOutput).toBe(null);
    });

    it('should handle undefined', () => {
      const result = filterValue(undefined);

      expect(result.wasRedacted).toBe(false);
      expect(result.filteredOutput).toBe(undefined);
    });

    it('should handle numbers', () => {
      const result = filterValue(42);

      expect(result.wasRedacted).toBe(false);
      expect(result.filteredOutput).toBe(42);
    });

    it('should handle booleans', () => {
      const result = filterValue(true);

      expect(result.wasRedacted).toBe(false);
      expect(result.filteredOutput).toBe(true);
    });

    it('should dispatch to string handler', () => {
      const result = filterValue('sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234');

      expect(result.wasRedacted).toBe(true);
      expect(result.filteredOutput).toBe('[REDACTED:openai-api-key]');
    });

    it('should dispatch to object handler', () => {
      const result = filterValue({
        secret: 'sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
      });

      expect(result.wasRedacted).toBe(true);
    });

    it('should dispatch to array handler', () => {
      const result = filterValue([
        'sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
      ]);

      expect(result.wasRedacted).toBe(true);
    });
  });

  describe('detectionsToRedactions', () => {
    it('should convert detections to redactions', () => {
      const detections: SecretsDetectionResult[] = [
        {
          detected: true,
          category: 'secrets',
          severity: 'critical',
          confidence: 0.95,
          reason: 'OpenAI API key detected',
          metadata: {
            type: 'api-key',
            provider: 'openai',
            redactedValue: 'sk-***...',
          },
        },
      ];

      const redactions = detectionsToRedactions(detections);

      expect(redactions).toHaveLength(1);
      expect(redactions[0].type).toBe('openai-api-key');
      expect(redactions[0].description).toBe('OpenAI API key detected');
    });

    it('should handle multiple detections', () => {
      const detections: SecretsDetectionResult[] = [
        {
          detected: true,
          category: 'secrets',
          severity: 'critical',
          confidence: 0.9,
          reason: 'AWS key detected',
          metadata: {
            type: 'api-key',
            provider: 'aws',
          },
        },
        {
          detected: true,
          category: 'secrets',
          severity: 'high',
          confidence: 0.85,
          reason: 'SSN detected',
          metadata: {
            type: 'pii',
            subtype: 'ssn',
          },
        },
      ];

      const redactions = detectionsToRedactions(detections);

      expect(redactions).toHaveLength(2);
    });

    it('should skip non-detections', () => {
      const detections: SecretsDetectionResult[] = [
        {
          detected: false,
          category: 'secrets',
          severity: 'low',
          confidence: 0.1,
          reason: 'No secrets found',
        },
      ];

      const redactions = detectionsToRedactions(detections);

      expect(redactions).toHaveLength(0);
    });

    it('should handle detections without metadata', () => {
      const detections: SecretsDetectionResult[] = [
        {
          detected: true,
          category: 'secrets',
          severity: 'medium',
          confidence: 0.7,
          reason: 'Potential secret',
        },
      ];

      const redactions = detectionsToRedactions(detections);

      expect(redactions).toHaveLength(0);
    });

    it('should deduplicate same types', () => {
      const detections: SecretsDetectionResult[] = [
        {
          detected: true,
          category: 'secrets',
          severity: 'critical',
          confidence: 0.95,
          reason: 'First API key',
          metadata: { type: 'api-key', provider: 'openai' },
        },
        {
          detected: true,
          category: 'secrets',
          severity: 'critical',
          confidence: 0.9,
          reason: 'Second API key',
          metadata: { type: 'api-key', provider: 'openai' },
        },
      ];

      const redactions = detectionsToRedactions(detections);

      expect(redactions).toHaveLength(1);
    });
  });

  describe('filterOutput', () => {
    it('should filter output and include detections', () => {
      const output = 'Key: sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234';
      const detections: SecretsDetectionResult[] = [
        {
          detected: true,
          category: 'secrets',
          severity: 'critical',
          confidence: 0.95,
          reason: 'OpenAI API key',
          metadata: { type: 'api-key', provider: 'openai' },
        },
      ];

      const result = filterOutput(output, detections);

      expect(result.wasRedacted).toBe(true);
      expect(result.filteredOutput).toBe('Key: [REDACTED:openai-api-key]');
    });

    it('should work without detections', () => {
      const output = 'Key: sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234';

      const result = filterOutput(output);

      expect(result.wasRedacted).toBe(true);
      expect(result.filteredOutput).toBe('Key: [REDACTED:openai-api-key]');
    });
  });
});

// =============================================================================
// HANDLER TESTS
// =============================================================================

describe('ToolResultPersistHandler', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('String output with secrets', () => {
    it('should redact OpenAI API key in string output', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: 'The API key is sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      expect(result.message.content).toBe(
        'The API key is [REDACTED:openai-api-key]'
      );
      expect(result.message.redactions).toBeDefined();
      expect(result.message.redactions?.some((r) => r.type === 'openai-api-key')).toBe(true);
    });

    it('should redact SSN in string output', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: 'User SSN: 123-45-6789',
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      expect(result.message.content).toBe('User SSN: [REDACTED:ssn]');
      expect(result.message.redactions?.some((r) => r.type === 'ssn')).toBe(true);
    });

    it('should redact JWT token in string output', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput:
          'Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      expect(result.message.content).toContain('[REDACTED:jwt]');
    });
  });

  describe('Object output with nested secrets', () => {
    it('should redact secrets in object values', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: {
          user: 'john',
          credentials: {
            apiKey: 'sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
          },
        },
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      const filtered = result.message.content as {
        user: string;
        credentials: { apiKey: string };
      };
      expect(filtered.user).toBe('john');
      expect(filtered.credentials.apiKey).toBe('[REDACTED:openai-api-key]');
    });

    it('should redact secrets in deeply nested objects', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: {
          level1: {
            level2: {
              level3: {
                secret: 'AKIAIOSFODNN7EXAMPLE',
              },
            },
          },
        },
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      const filtered = result.message.content as {
        level1: { level2: { level3: { secret: string } } };
      };
      expect(filtered.level1.level2.level3.secret).toBe('[REDACTED:aws-access-key]');
    });
  });

  describe('Clean output', () => {
    it('should pass through clean string output unchanged', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: 'This is a normal, clean output with no secrets',
      });

      const result = await handler(context);

      expect(result).toEqual({});
    });

    it('should pass through clean object output unchanged', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: {
          status: 'success',
          count: 42,
          items: ['a', 'b', 'c'],
        },
      });

      const result = await handler(context);

      expect(result).toEqual({});
    });

    it('should pass through primitive outputs unchanged', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);

      // Number
      let result = await handler(
        createTestToolResultContext({ toolOutput: 42 })
      );
      expect(result).toEqual({});

      // Boolean
      result = await handler(
        createTestToolResultContext({ toolOutput: true })
      );
      expect(result).toEqual({});

      // Null
      result = await handler(
        createTestToolResultContext({ toolOutput: null })
      );
      expect(result).toEqual({});
    });
  });

  describe('Multiple secret types in one output', () => {
    it('should redact multiple different secrets', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: {
          openaiKey: 'sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
          awsKey: 'AKIAIOSFODNN7EXAMPLE',
          userSsn: '123-45-6789',
        },
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      const filtered = result.message.content as Record<string, string>;
      expect(filtered.openaiKey).toBe('[REDACTED:openai-api-key]');
      expect(filtered.awsKey).toBe('[REDACTED:aws-access-key]');
      expect(filtered.userSsn).toBe('[REDACTED:ssn]');

      // Should have redactions for each type
      expect(result.message.redactions?.length).toBeGreaterThanOrEqual(3);
    });

    it('should handle array with multiple secrets', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: [
          'sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
          'AKIAIOSFODNN7EXAMPLE',
          'clean data',
        ],
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      const filtered = result.message.content as string[];
      expect(filtered[0]).toBe('[REDACTED:openai-api-key]');
      expect(filtered[1]).toBe('[REDACTED:aws-access-key]');
      expect(filtered[2]).toBe('clean data');
    });
  });

  describe('Redaction list accuracy', () => {
    it('should include accurate redaction descriptions', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: 'Key: sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      expect(result.message.redactions).toBeDefined();
      const openaiRedaction = result.message.redactions?.find(
        (r) => r.type === 'openai-api-key'
      );
      expect(openaiRedaction).toBeDefined();
      expect(openaiRedaction?.description).toBe('OpenAI API key');
    });

    it('should not duplicate redaction entries', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: {
          key1: 'sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
          key2: 'sk-def456ghi789jkl012mno345pqr678stu901vwx234yz',
        },
      });

      const result = await handler(context);

      // Should only have one redaction entry for openai-api-key type
      expect(result.message).toBeDefined();
      const openaiRedactions = result.message.redactions?.filter(
        (r) => r.type === 'openai-api-key'
      );
      expect(openaiRedactions?.length).toBe(1);
    });
  });

  describe('Filter disabled', () => {
    it('should pass through without filtering when filter option is false', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config, { filter: false });
      const context = createTestToolResultContext({
        toolOutput: 'Key: sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
      });

      const result = await handler(context);

      expect(result).toEqual({});
    });
  });

  describe('Plugin disabled', () => {
    it('should pass through when global config is disabled', async () => {
      const config = createTestConfig({
        global: { enabled: false, logLevel: 'info' },
      });
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: 'Key: sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
      });

      const result = await handler(context);

      expect(result).toEqual({});
    });

    it('should pass through when secrets rule is disabled', async () => {
      const config = createTestConfig();
      config.rules!.secrets = {
        enabled: false,
        severity: 'critical',
        action: 'block',
      };
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: 'Key: sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
      });

      const result = await handler(context);

      expect(result).toEqual({});
    });
  });

  describe('Default handler', () => {
    it('should create handler with default config', async () => {
      const handler = createDefaultToolResultPersistHandler();

      expect(typeof handler).toBe('function');

      // Should process output
      const context = createTestToolResultContext({
        toolOutput: 'clean output',
      });

      const result = await handler(context);

      expect(result).toEqual({});
    });

    it('should redact secrets with default config', async () => {
      const handler = createDefaultToolResultPersistHandler();
      const context = createTestToolResultContext({
        toolOutput: 'sk-abc123xyz789def456ghi012jkl345mno678pqr901stu234',
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      expect(result.message.content).toBe('[REDACTED:openai-api-key]');
    });
  });

  describe('Edge cases', () => {
    it('should handle empty string output', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: '',
      });

      const result = await handler(context);

      expect(result).toEqual({});
    });

    it('should handle empty object output', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: {},
      });

      const result = await handler(context);

      expect(result).toEqual({});
    });

    it('should handle empty array output', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: [],
      });

      const result = await handler(context);

      expect(result).toEqual({});
    });

    it('should handle undefined output', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: undefined,
      });

      const result = await handler(context);

      expect(result).toEqual({});
    });

    it('should handle mixed clean and secret values in complex structure', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: {
          meta: {
            status: 'success',
            count: 2,
          },
          items: [
            {
              id: 1,
              value: 'clean',
            },
            {
              id: 2,
              value: 'AKIAIOSFODNN7EXAMPLE',
            },
          ],
          timestamp: 1234567890,
        },
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      const filtered = result.message.content as {
        meta: { status: string; count: number };
        items: Array<{ id: number; value: string }>;
        timestamp: number;
      };

      // Clean values should be preserved
      expect(filtered.meta.status).toBe('success');
      expect(filtered.meta.count).toBe(2);
      expect(filtered.items[0].value).toBe('clean');
      expect(filtered.timestamp).toBe(1234567890);

      // Secret should be redacted
      expect(filtered.items[1].value).toBe('[REDACTED:aws-access-key]');
    });
  });

  describe('Various secret patterns', () => {
    it('should redact Google API key', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: 'Google key: AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI',
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      expect(result.message.content).toContain('[REDACTED:google-api-key]');
    });

    it('should redact Slack token', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: 'Slack: xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx',
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      expect(result.message.content).toContain('[REDACTED:slack-token]');
    });

    it('should redact Stripe test key', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: 'Stripe: sk_test_abcdefghijklmnopqrstuvwxyz',
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      expect(result.message.content).toContain('[REDACTED:stripe-test-key]');
    });

    it('should redact Bearer token', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: 'Auth: Bearer abc123def456ghi789jkl012mno345',
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      expect(result.message.content).toContain('[REDACTED:bearer-token]');
    });

    it('should redact Visa credit card', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: 'Card: 4532015112830366',
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      expect(result.message.content).toContain('[REDACTED:credit-card]');
    });

    it('should redact Mastercard credit card', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);
      const context = createTestToolResultContext({
        toolOutput: 'Card: 5425233430109903',
      });

      const result = await handler(context);

      expect(result.message).toBeDefined();
      expect(result.message.content).toContain('[REDACTED:credit-card]');
    });
  });

  describe('Edge cases with undefined toolInput', () => {
    it('should handle undefined toolInput without throwing', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);

      // Simulate a context where toolInput is undefined (possible at runtime)
      const context: ToolResultContext = {
        toolName: 'some_tool',
        toolInput: undefined as any, // Force undefined despite type
        toolOutput: 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno',
      };

      // Should not throw the "Cannot use 'in' operator to search for 'command' in undefined" error
      const result = await handler(context);

      // Should still filter the output
      expect(result.message).toBeDefined();
      expect(result.message.content).toContain('[REDACTED:openai-api-key]');
      expect(result.message.redactions).toBeDefined();
      expect(result.message.redactions.length).toBeGreaterThan(0);
    });

    it('should handle null toolInput without throwing', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);

      const context: ToolResultContext = {
        toolName: 'some_tool',
        toolInput: null as any, // Force null despite type
        toolOutput: 'password=supersecret123',
      };

      // Should not throw
      const result = await handler(context);

      // Should still filter the output
      expect(result.message).toBeDefined();
      expect(result.message.content).toContain('[REDACTED:');
    });

    it('should handle empty object toolInput', async () => {
      const config = createTestConfig();
      const handler = createToolResultPersistHandler(config);

      const context: ToolResultContext = {
        toolName: 'some_tool',
        toolInput: {},
        toolOutput: 'AKIA1234567890EXAMPLE',
      };

      // Should work normally
      const result = await handler(context);

      expect(result.message).toBeDefined();
      expect(result.message.content).toContain('[REDACTED:aws-access-key]');
    });
  });
});
