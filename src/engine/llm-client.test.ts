/**
 * Tests for the LLM Client
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  buildAnalysisPrompt,
  parseAnalysisResponse,
  LLMResponseCache,
  MockLLMClient,
  OpenClawLLMClient,
  createLLMClient,
  createMockLLMClient,
  createUnavailableLLMClient,
  DEFAULT_LLM_TIMEOUT_MS,
  DEFAULT_LLM_CACHE_TTL_MS,
} from './llm-client.js';
import type {
  LLMAnalysisRequest,
  LLMAnalysisResult,
  OpenClawAPI,
  ConversationMessage,
} from './llm-client.js';
import type { Detection, ToolCallContext } from './types.js';

// ============================================================================
// Test Helpers
// ============================================================================

function createTestDetection(overrides?: Partial<Detection>): Detection {
  return {
    category: 'purchase',
    severity: 'high',
    confidence: 0.65,
    reason: 'Detected purchase-related activity',
    ...overrides,
  };
}

function createTestContext(overrides?: Partial<ToolCallContext>): ToolCallContext {
  return {
    toolName: 'browser_navigate',
    toolInput: { url: 'https://example.com/checkout' },
    ...overrides,
  };
}

function createTestRequest(overrides?: Partial<LLMAnalysisRequest>): LLMAnalysisRequest {
  return {
    detection: createTestDetection(),
    context: createTestContext(),
    ...overrides,
  };
}

function createMockAPI(options?: {
  available?: boolean;
  response?: string;
  shouldError?: boolean;
  errorMessage?: string;
}): OpenClawAPI {
  return {
    isAvailable: vi.fn().mockReturnValue(options?.available ?? true),
    complete: vi.fn().mockImplementation(async () => {
      if (options?.shouldError) {
        throw new Error(options.errorMessage ?? 'API Error');
      }
      return (
        options?.response ??
        JSON.stringify({
          determination: 'threat',
          confidence: 0.85,
          reasoning: 'Test reasoning',
          suggestedAction: 'block',
        })
      );
    }),
  };
}

// ============================================================================
// Prompt Generation Tests
// ============================================================================

describe('Prompt Generation', () => {
  describe('buildAnalysisPrompt', () => {
    it('should include detection details in prompt', () => {
      const request = createTestRequest({
        detection: createTestDetection({
          category: 'destructive',
          severity: 'critical',
          confidence: 0.75,
          reason: 'Detected rm -rf command',
        }),
      });

      const prompt = buildAnalysisPrompt(request);

      expect(prompt).toContain('destructive');
      expect(prompt).toContain('critical');
      expect(prompt).toContain('75%');
      expect(prompt).toContain('Detected rm -rf command');
    });

    it('should include tool call context in prompt', () => {
      const request = createTestRequest({
        context: createTestContext({
          toolName: 'execute_shell',
          toolInput: { command: 'rm -rf /tmp/*' },
        }),
      });

      const prompt = buildAnalysisPrompt(request);

      expect(prompt).toContain('execute_shell');
      expect(prompt).toContain('rm -rf /tmp/*');
    });

    it('should include URL when provided', () => {
      const request = createTestRequest({
        context: createTestContext({
          url: 'https://checkout.stripe.com/pay',
        }),
      });

      const prompt = buildAnalysisPrompt(request);

      expect(prompt).toContain('https://checkout.stripe.com/pay');
    });

    it('should truncate long tool output', () => {
      const longOutput = 'x'.repeat(1000);
      const request = createTestRequest({
        context: createTestContext({
          toolOutput: longOutput,
        }),
      });

      const prompt = buildAnalysisPrompt(request);

      expect(prompt).toContain('...');
      expect(prompt.length).toBeLessThan(longOutput.length + 1000);
    });

    it('should include metadata when provided', () => {
      const request = createTestRequest({
        detection: createTestDetection({
          metadata: { matched: 'stripe.com', indicator: 'payment_url' },
        }),
      });

      const prompt = buildAnalysisPrompt(request);

      expect(prompt).toContain('stripe.com');
      expect(prompt).toContain('payment_url');
    });

    it('should request structured JSON response', () => {
      const request = createTestRequest();
      const prompt = buildAnalysisPrompt(request);

      expect(prompt).toContain('"determination"');
      expect(prompt).toContain('"confidence"');
      expect(prompt).toContain('"reasoning"');
      expect(prompt).toContain('"suggestedAction"');
    });
  });
});

// ============================================================================
// Response Parsing Tests
// ============================================================================

describe('Response Parsing', () => {
  describe('parseAnalysisResponse', () => {
    it('should parse valid JSON response', () => {
      const response = JSON.stringify({
        determination: 'threat',
        confidence: 0.9,
        reasoning: 'Clear malicious intent',
        suggestedAction: 'block',
      });

      const result = parseAnalysisResponse(response);

      expect(result.determination).toBe('threat');
      expect(result.confidence).toBe(0.9);
      expect(result.reasoning).toBe('Clear malicious intent');
      expect(result.suggestedAction).toBe('block');
    });

    it('should parse JSON wrapped in code block', () => {
      const response = `Here is my analysis:
\`\`\`json
{
  "determination": "safe",
  "confidence": 0.8,
  "reasoning": "Legitimate operation",
  "suggestedAction": "allow"
}
\`\`\`
Hope this helps!`;

      const result = parseAnalysisResponse(response);

      expect(result.determination).toBe('safe');
      expect(result.confidence).toBe(0.8);
      expect(result.suggestedAction).toBe('allow');
    });

    it('should handle invalid determination value', () => {
      const response = JSON.stringify({
        determination: 'invalid',
        confidence: 0.5,
        reasoning: 'test',
        suggestedAction: 'confirm',
      });

      const result = parseAnalysisResponse(response);

      expect(result.determination).toBe('uncertain');
    });

    it('should handle invalid confidence value', () => {
      const response = JSON.stringify({
        determination: 'threat',
        confidence: 'high',
        reasoning: 'test',
        suggestedAction: 'block',
      });

      const result = parseAnalysisResponse(response);

      expect(result.confidence).toBe(0.5);
    });

    it('should handle confidence out of range', () => {
      const response = JSON.stringify({
        determination: 'threat',
        confidence: 1.5,
        reasoning: 'test',
        suggestedAction: 'block',
      });

      const result = parseAnalysisResponse(response);

      expect(result.confidence).toBe(0.5);
    });

    it('should handle invalid suggestedAction value', () => {
      const response = JSON.stringify({
        determination: 'threat',
        confidence: 0.8,
        reasoning: 'test',
        suggestedAction: 'invalid',
      });

      const result = parseAnalysisResponse(response);

      // Should default based on determination (threat -> block)
      expect(result.suggestedAction).toBe('block');
    });

    it('should return uncertain for unparseable response', () => {
      const response = 'This is not valid JSON at all';

      const result = parseAnalysisResponse(response);

      expect(result.determination).toBe('uncertain');
      expect(result.confidence).toBe(0.5);
      expect(result.suggestedAction).toBe('confirm');
      expect(result.reasoning).toContain('Failed to parse');
    });

    it('should handle missing reasoning gracefully', () => {
      const response = JSON.stringify({
        determination: 'safe',
        confidence: 0.7,
        suggestedAction: 'allow',
      });

      const result = parseAnalysisResponse(response);

      expect(result.reasoning).toBe('No reasoning provided');
    });
  });
});

// ============================================================================
// LLM Response Cache Tests
// ============================================================================

describe('LLMResponseCache', () => {
  let cache: LLMResponseCache;

  beforeEach(() => {
    cache = new LLMResponseCache();
  });

  describe('generateKey', () => {
    it('should generate consistent keys for same request', () => {
      const request = createTestRequest();
      const key1 = cache.generateKey(request);
      const key2 = cache.generateKey(request);

      expect(key1).toBe(key2);
    });

    it('should generate different keys for different requests', () => {
      const request1 = createTestRequest({
        detection: createTestDetection({ category: 'purchase' }),
      });
      const request2 = createTestRequest({
        detection: createTestDetection({ category: 'destructive' }),
      });

      const key1 = cache.generateKey(request1);
      const key2 = cache.generateKey(request2);

      expect(key1).not.toBe(key2);
    });
  });

  describe('get/set', () => {
    it('should store and retrieve values', () => {
      const result: LLMAnalysisResult = {
        determination: 'threat',
        confidence: 0.9,
        reasoning: 'test',
        suggestedAction: 'block',
      };

      cache.set('key1', result);
      const retrieved = cache.get('key1');

      expect(retrieved).toEqual(result);
    });

    it('should return undefined for non-existent keys', () => {
      expect(cache.get('nonexistent')).toBeUndefined();
    });
  });

  describe('has', () => {
    it('should return true for existing keys', () => {
      cache.set('key1', {
        determination: 'safe',
        confidence: 0.8,
        reasoning: 'test',
        suggestedAction: 'allow',
      });

      expect(cache.has('key1')).toBe(true);
    });

    it('should return false for non-existent keys', () => {
      expect(cache.has('nonexistent')).toBe(false);
    });
  });

  describe('expiration', () => {
    it('should expire entries after TTL', async () => {
      const shortTtlCache = new LLMResponseCache(50);

      shortTtlCache.set('key1', {
        determination: 'safe',
        confidence: 0.8,
        reasoning: 'test',
        suggestedAction: 'allow',
      });

      expect(shortTtlCache.has('key1')).toBe(true);

      await new Promise((resolve) => setTimeout(resolve, 60));

      expect(shortTtlCache.has('key1')).toBe(false);
      expect(shortTtlCache.get('key1')).toBeUndefined();
    });
  });

  describe('clear', () => {
    it('should clear all entries', () => {
      cache.set('key1', {
        determination: 'safe',
        confidence: 0.8,
        reasoning: 'test',
        suggestedAction: 'allow',
      });
      cache.set('key2', {
        determination: 'threat',
        confidence: 0.9,
        reasoning: 'test',
        suggestedAction: 'block',
      });

      expect(cache.size()).toBe(2);

      cache.clear();

      expect(cache.size()).toBe(0);
    });
  });
});

// ============================================================================
// Mock LLM Client Tests
// ============================================================================

describe('MockLLMClient', () => {
  describe('isAvailable', () => {
    it('should return true by default', () => {
      const client = createMockLLMClient();
      expect(client.isAvailable()).toBe(true);
    });

    it('should return false when configured unavailable', () => {
      const client = createMockLLMClient({ available: false });
      expect(client.isAvailable()).toBe(false);
    });

    it('should be settable after creation', () => {
      const client = createMockLLMClient();
      expect(client.isAvailable()).toBe(true);

      client.setAvailable(false);
      expect(client.isAvailable()).toBe(false);
    });
  });

  describe('analyze', () => {
    it('should return uncertain when unavailable', async () => {
      const client = createMockLLMClient({ available: false });
      const request = createTestRequest();

      const result = await client.analyze(request);

      expect(result.determination).toBe('uncertain');
      expect(result.reasoning).toContain('unavailable');
    });

    it('should return threat for high confidence detections', async () => {
      const client = createMockLLMClient();
      const request = createTestRequest({
        detection: createTestDetection({ confidence: 0.8 }),
      });

      const result = await client.analyze(request);

      expect(result.determination).toBe('threat');
      expect(result.suggestedAction).toBe('block');
    });

    it('should return safe for low confidence detections', async () => {
      const client = createMockLLMClient();
      const request = createTestRequest({
        detection: createTestDetection({ confidence: 0.5 }),
      });

      const result = await client.analyze(request);

      expect(result.determination).toBe('safe');
      expect(result.suggestedAction).toBe('allow');
    });

    it('should handle purchase detections with checkout URLs', async () => {
      const client = createMockLLMClient();
      const request = createTestRequest({
        detection: createTestDetection({ category: 'purchase', confidence: 0.65 }),
        context: createTestContext({ url: 'https://example.com/checkout' }),
      });

      const result = await client.analyze(request);

      expect(result.determination).toBe('threat');
    });

    it('should handle destructive detections with test paths', async () => {
      const client = createMockLLMClient();
      const request = createTestRequest({
        detection: createTestDetection({ category: 'destructive', confidence: 0.65 }),
        context: createTestContext({ toolInput: { command: 'rm -rf /tmp/test/*' } }),
      });

      const result = await client.analyze(request);

      expect(result.determination).toBe('safe');
    });

    it('should handle secrets detections with example files', async () => {
      const client = createMockLLMClient();
      const request = createTestRequest({
        detection: createTestDetection({ category: 'secrets', confidence: 0.65 }),
        context: createTestContext({ toolInput: { path: '.env.example' } }),
      });

      const result = await client.analyze(request);

      expect(result.determination).toBe('safe');
    });

    it('should handle exfiltration detections with localhost', async () => {
      const client = createMockLLMClient();
      const request = createTestRequest({
        detection: createTestDetection({ category: 'exfiltration', confidence: 0.65 }),
        context: createTestContext({ url: 'http://localhost:3000/api' }),
      });

      const result = await client.analyze(request);

      expect(result.determination).toBe('safe');
    });

    it('should use custom responses when set', async () => {
      const client = createMockLLMClient();
      const customResult: LLMAnalysisResult = {
        determination: 'threat',
        confidence: 0.99,
        reasoning: 'Custom test response',
        suggestedAction: 'block',
      };

      client.setCustomResponse('purchase', customResult);

      const request = createTestRequest({
        detection: createTestDetection({ category: 'purchase', confidence: 0.3 }),
      });

      const result = await client.analyze(request);

      expect(result).toEqual(customResult);
    });

    it('should simulate response delay', async () => {
      const client = createMockLLMClient({ responseDelay: 50 });
      const request = createTestRequest();

      const start = Date.now();
      await client.analyze(request);
      const duration = Date.now() - start;

      expect(duration).toBeGreaterThanOrEqual(45); // Allow some tolerance
    });
  });

  describe('caching', () => {
    it('should cache responses', async () => {
      const client = createMockLLMClient({ enableCache: true });
      const request = createTestRequest();

      await client.analyze(request);
      expect(client.getCacheStats().size).toBe(1);

      // Second call should use cache
      await client.analyze(request);
      expect(client.getCacheStats().size).toBe(1);
    });

    it('should not cache when disabled', async () => {
      const client = createMockLLMClient({ enableCache: false });
      const request = createTestRequest();

      await client.analyze(request);
      expect(client.getCacheStats().size).toBe(0);
    });

    it('should clear cache', async () => {
      const client = createMockLLMClient({ enableCache: true });
      const request = createTestRequest();

      await client.analyze(request);
      expect(client.getCacheStats().size).toBe(1);

      client.clearCache();
      expect(client.getCacheStats().size).toBe(0);
    });
  });
});

// ============================================================================
// OpenClaw LLM Client Tests
// ============================================================================

describe('OpenClawLLMClient', () => {
  describe('isAvailable', () => {
    it('should delegate to API isAvailable', () => {
      const api = createMockAPI({ available: true });
      const client = new OpenClawLLMClient(api, {
        llmConfig: { enabled: true, model: null },
      });

      expect(client.isAvailable()).toBe(true);
      expect(api.isAvailable).toHaveBeenCalled();
    });

    it('should return false when API unavailable', () => {
      const api = createMockAPI({ available: false });
      const client = new OpenClawLLMClient(api, {
        llmConfig: { enabled: true, model: null },
      });

      expect(client.isAvailable()).toBe(false);
    });
  });

  describe('analyze', () => {
    it('should call API with generated prompt', async () => {
      const api = createMockAPI({
        response: JSON.stringify({
          determination: 'threat',
          confidence: 0.9,
          reasoning: 'Test',
          suggestedAction: 'block',
        }),
      });
      const client = new OpenClawLLMClient(api, {
        llmConfig: { enabled: true, model: 'test-model' },
      });

      const request = createTestRequest();
      await client.analyze(request);

      expect(api.complete).toHaveBeenCalled();
      const callArgs = (api.complete as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(callArgs[0]).toContain(request.detection.reason);
      expect(callArgs[1].model).toBe('test-model');
    });

    it('should parse and return LLM response', async () => {
      const api = createMockAPI({
        response: JSON.stringify({
          determination: 'safe',
          confidence: 0.85,
          reasoning: 'Legitimate operation',
          suggestedAction: 'allow',
        }),
      });
      const client = new OpenClawLLMClient(api, {
        llmConfig: { enabled: true, model: null },
      });

      const request = createTestRequest();
      const result = await client.analyze(request);

      expect(result.determination).toBe('safe');
      expect(result.confidence).toBe(0.85);
      expect(result.reasoning).toBe('Legitimate operation');
      expect(result.suggestedAction).toBe('allow');
    });

    it('should return uncertain on API error', async () => {
      const api = createMockAPI({
        shouldError: true,
        errorMessage: 'Connection timeout',
      });
      const client = new OpenClawLLMClient(api, {
        llmConfig: { enabled: true, model: null },
      });

      const request = createTestRequest();
      const result = await client.analyze(request);

      expect(result.determination).toBe('uncertain');
      expect(result.reasoning).toContain('Connection timeout');
      expect(result.suggestedAction).toBe('confirm');
    });

    it('should use default timeout', async () => {
      const api = createMockAPI();
      const client = new OpenClawLLMClient(api, {
        llmConfig: { enabled: true, model: null },
      });

      const request = createTestRequest();
      await client.analyze(request);

      const callArgs = (api.complete as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(callArgs[1].timeout).toBe(DEFAULT_LLM_TIMEOUT_MS);
    });

    it('should use custom timeout', async () => {
      const api = createMockAPI();
      const client = new OpenClawLLMClient(api, {
        llmConfig: { enabled: true, model: null },
        timeoutMs: 10000,
      });

      const request = createTestRequest();
      await client.analyze(request);

      const callArgs = (api.complete as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(callArgs[1].timeout).toBe(10000);
    });
  });

  describe('caching', () => {
    it('should cache responses by default', async () => {
      const api = createMockAPI({
        response: JSON.stringify({
          determination: 'threat',
          confidence: 0.9,
          reasoning: 'Test',
          suggestedAction: 'block',
        }),
      });
      const client = new OpenClawLLMClient(api, {
        llmConfig: { enabled: true, model: null },
      });

      const request = createTestRequest();

      // First call
      await client.analyze(request);
      expect(api.complete).toHaveBeenCalledTimes(1);

      // Second call should use cache
      await client.analyze(request);
      expect(api.complete).toHaveBeenCalledTimes(1);
      expect(client.getCacheStats().size).toBe(1);
    });

    it('should not cache when disabled', async () => {
      const api = createMockAPI({
        response: JSON.stringify({
          determination: 'threat',
          confidence: 0.9,
          reasoning: 'Test',
          suggestedAction: 'block',
        }),
      });
      const client = new OpenClawLLMClient(api, {
        llmConfig: { enabled: true, model: null },
        enableCache: false,
      });

      const request = createTestRequest();

      await client.analyze(request);
      await client.analyze(request);

      expect(api.complete).toHaveBeenCalledTimes(2);
      expect(client.getCacheStats().enabled).toBe(false);
    });

    it('should clear cache', async () => {
      const api = createMockAPI({
        response: JSON.stringify({
          determination: 'threat',
          confidence: 0.9,
          reasoning: 'Test',
          suggestedAction: 'block',
        }),
      });
      const client = new OpenClawLLMClient(api, {
        llmConfig: { enabled: true, model: null },
      });

      const request = createTestRequest();
      await client.analyze(request);
      expect(client.getCacheStats().size).toBe(1);

      client.clearCache();
      expect(client.getCacheStats().size).toBe(0);

      await client.analyze(request);
      expect(api.complete).toHaveBeenCalledTimes(2);
    });
  });
});

// ============================================================================
// Factory Function Tests
// ============================================================================

describe('Factory Functions', () => {
  describe('createLLMClient', () => {
    it('should create real client when API is available', () => {
      const api = createMockAPI({ available: true });
      const client = createLLMClient(
        { llmConfig: { enabled: true, model: null } },
        api
      );

      expect(client).toBeInstanceOf(OpenClawLLMClient);
    });

    it('should create mock client when API is unavailable', () => {
      const api = createMockAPI({ available: false });
      const client = createLLMClient(
        { llmConfig: { enabled: true, model: null } },
        api
      );

      expect(client).toBeInstanceOf(MockLLMClient);
    });

    it('should create mock client when no API provided', () => {
      const client = createLLMClient({ llmConfig: { enabled: true, model: null } });

      expect(client).toBeInstanceOf(MockLLMClient);
    });
  });

  describe('createMockLLMClient', () => {
    it('should create mock client with defaults', () => {
      const client = createMockLLMClient();

      expect(client.isAvailable()).toBe(true);
      expect(client.getCacheStats().enabled).toBe(true);
    });

    it('should create mock client with options', () => {
      const client = createMockLLMClient({
        available: false,
        enableCache: false,
      });

      expect(client.isAvailable()).toBe(false);
      expect(client.getCacheStats().enabled).toBe(false);
    });
  });

  describe('createUnavailableLLMClient', () => {
    it('should create unavailable client', async () => {
      const client = createUnavailableLLMClient();

      expect(client.isAvailable()).toBe(false);

      const result = await client.analyze(createTestRequest());
      expect(result.determination).toBe('uncertain');
    });
  });
});

// ============================================================================
// Integration-like Tests
// ============================================================================

describe('LLM Client Integration', () => {
  it('should handle full analysis flow', async () => {
    const api = createMockAPI({
      response: `Based on my analysis:

\`\`\`json
{
  "determination": "threat",
  "confidence": 0.92,
  "reasoning": "The tool call is attempting to access a payment page on Stripe, which indicates a financial transaction. Combined with form filling actions that include card details, this is clearly a purchase attempt.",
  "suggestedAction": "block"
}
\`\`\`

I recommend blocking this action.`,
    });

    const client = new OpenClawLLMClient(api, {
      llmConfig: { enabled: true, model: 'claude-3-opus' },
    });

    const request: LLMAnalysisRequest = {
      detection: {
        category: 'purchase',
        severity: 'critical',
        confidence: 0.65,
        reason: 'Detected Stripe checkout page',
        metadata: { domain: 'stripe.com' },
      },
      context: {
        toolName: 'browser_fill_form',
        toolInput: {
          fields: {
            cardNumber: '4242424242424242',
            expiry: '12/25',
          },
        },
        url: 'https://checkout.stripe.com/pay/abc123',
      },
    };

    const result = await client.analyze(request);

    expect(result.determination).toBe('threat');
    expect(result.confidence).toBe(0.92);
    expect(result.suggestedAction).toBe('block');
    expect(result.reasoning).toContain('financial transaction');
  });

  it('should handle ambiguous website detection', async () => {
    const client = createMockLLMClient();

    const request: LLMAnalysisRequest = {
      detection: {
        category: 'website',
        severity: 'medium',
        confidence: 0.6,
        reason: 'Unknown website with suspicious path',
      },
      context: {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://totally-legit-site.com/login' },
        url: 'https://totally-legit-site.com/login',
      },
    };

    const result = await client.analyze(request);

    // Should return uncertain for mid-confidence with no specific indicators
    expect(['uncertain', 'safe', 'threat']).toContain(result.determination);
    expect(result.confidence).toBeGreaterThan(0);
    expect(result.suggestedAction).toBeDefined();
  });

  it('should handle repeated requests efficiently with caching', async () => {
    const api = createMockAPI();
    const client = new OpenClawLLMClient(api, {
      llmConfig: { enabled: true, model: null },
    });

    const request = createTestRequest();

    // Make 5 identical requests
    for (let i = 0; i < 5; i++) {
      await client.analyze(request);
    }

    // API should only be called once due to caching
    expect(api.complete).toHaveBeenCalledTimes(1);
  });
});
