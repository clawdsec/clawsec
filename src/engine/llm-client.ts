/**
 * LLM Client for analyzing ambiguous security detections
 *
 * This module provides an LLM client that analyzes ambiguous detections
 * to determine if they're true threats. Used when the HybridAnalyzer
 * sets requiresLLM = true for cases with ambiguous confidence (0.5-0.8).
 */

import type { CacheEntry } from './types.js';
import type { LLMConfig } from '../config/index.js';
import type { Detection, ToolCallContext } from './types.js';

// ============================================================================
// Types
// ============================================================================

/**
 * LLM analysis result
 */
export interface LLMAnalysisResult {
  /** Determination of the threat level */
  determination: 'threat' | 'safe' | 'uncertain';
  /** Confidence in the determination (0-1) */
  confidence: number;
  /** Reasoning behind the determination */
  reasoning: string;
  /** Suggested action based on analysis */
  suggestedAction: 'block' | 'confirm' | 'allow';
}

/**
 * Interface for LLM clients
 */
export interface LLMClient {
  /** Analyze a detection and determine if it's a real threat */
  analyze(request: LLMAnalysisRequest): Promise<LLMAnalysisResult>;
  /** Check if the LLM client is available and configured */
  isAvailable(): boolean;
}

/**
 * Conversation message for context
 */
export interface ConversationMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

/**
 * Request to analyze a detection with LLM
 */
export interface LLMAnalysisRequest {
  /** The detection to analyze */
  detection: Detection;
  /** Context of the tool call that triggered the detection */
  context: ToolCallContext;
  /** Optional conversation history for additional context */
  conversationHistory?: ConversationMessage[];
}

/**
 * Optional OpenClaw API interface (for real LLM integration)
 */
export interface OpenClawAPI {
  /** Send a prompt to the LLM and get a response */
  complete(prompt: string, options?: { model?: string | null; timeout?: number }): Promise<string>;
  /** Check if the API is available */
  isAvailable(): boolean;
}

// ============================================================================
// Constants
// ============================================================================

/** Default timeout for LLM requests (30 seconds) */
export const DEFAULT_LLM_TIMEOUT_MS = 30000;

/** Default TTL for LLM response cache (5 minutes - longer than detection cache) */
export const DEFAULT_LLM_CACHE_TTL_MS = 5 * 60 * 1000;

/** Maximum cache size for LLM responses */
export const MAX_LLM_CACHE_SIZE = 500;

// ============================================================================
// Cache for LLM Responses
// ============================================================================

/**
 * Generic in-memory cache for LLM responses
 */
export class LLMResponseCache {
  private cache: Map<string, CacheEntry<LLMAnalysisResult>>;
  private defaultTtl: number;

  constructor(defaultTtlMs: number = DEFAULT_LLM_CACHE_TTL_MS) {
    this.cache = new Map();
    this.defaultTtl = defaultTtlMs;
  }

  /**
   * Generate a cache key from the request
   */
  generateKey(request: LLMAnalysisRequest): string {
    const keyData = {
      category: request.detection.category,
      reason: request.detection.reason,
      toolName: request.context.toolName,
      toolInput: request.context.toolInput,
    };
    return JSON.stringify(keyData);
  }

  /**
   * Get a cached result
   */
  get(key: string): LLMAnalysisResult | undefined {
    const entry = this.cache.get(key);

    if (!entry) {
      return undefined;
    }

    if (this.isExpired(entry)) {
      this.cache.delete(key);
      return undefined;
    }

    return entry.value;
  }

  /**
   * Set a cached result
   */
  set(key: string, result: LLMAnalysisResult, ttl?: number): void {
    if (this.cache.size >= MAX_LLM_CACHE_SIZE) {
      this.evictExpired();

      if (this.cache.size >= MAX_LLM_CACHE_SIZE) {
        this.evictOldest(Math.floor(MAX_LLM_CACHE_SIZE * 0.1));
      }
    }

    const entry: CacheEntry<LLMAnalysisResult> = {
      value: result,
      createdAt: Date.now(),
      ttl: ttl ?? this.defaultTtl,
    };

    this.cache.set(key, entry);
  }

  /**
   * Check if a key exists and is not expired
   */
  has(key: string): boolean {
    const entry = this.cache.get(key);

    if (!entry) {
      return false;
    }

    if (this.isExpired(entry)) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache size
   */
  size(): number {
    return this.cache.size;
  }

  private isExpired(entry: CacheEntry<LLMAnalysisResult>): boolean {
    return Date.now() - entry.createdAt >= entry.ttl;
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache) {
      if (now - entry.createdAt >= entry.ttl) {
        this.cache.delete(key);
      }
    }
  }

  private evictOldest(count: number): void {
    const entries = Array.from(this.cache.entries()).sort(
      (a, b) => a[1].createdAt - b[1].createdAt
    );

    for (let i = 0; i < Math.min(count, entries.length); i++) {
      this.cache.delete(entries[i][0]);
    }
  }
}

// ============================================================================
// Prompt Generation
// ============================================================================

/**
 * Build a prompt for LLM analysis of a security detection
 */
export function buildAnalysisPrompt(request: LLMAnalysisRequest): string {
  const { detection, context } = request;

  const toolInputStr = JSON.stringify(context.toolInput, null, 2);

  let prompt = `You are a security analyst reviewing a potentially suspicious action by an AI agent.

## Detection Details
- **Category**: ${detection.category}
- **Severity**: ${detection.severity}
- **Confidence**: ${(detection.confidence * 100).toFixed(0)}%
- **Reason**: ${detection.reason}

## Tool Call Context
- **Tool Name**: ${context.toolName}
- **Tool Input**:
\`\`\`json
${toolInputStr}
\`\`\``;

  if (context.url) {
    prompt += `\n- **URL**: ${context.url}`;
  }

  if (context.toolOutput) {
    const truncatedOutput =
      context.toolOutput.length > 500
        ? context.toolOutput.substring(0, 500) + '...'
        : context.toolOutput;
    prompt += `\n- **Tool Output** (truncated):\n\`\`\`\n${truncatedOutput}\n\`\`\``;
  }

  if (detection.metadata) {
    prompt += `\n- **Additional Metadata**: ${JSON.stringify(detection.metadata)}`;
  }

  prompt += `

## Your Task
Analyze this detection and determine if this represents a real security threat or a false positive.

Consider:
1. Is the detected action genuinely dangerous or malicious?
2. Could this be a legitimate use case that triggered a false positive?
3. What is the potential impact if this action is allowed?
4. Are there any contextual clues that suggest benign intent?

## Response Format
Respond with a JSON object in the following format:
\`\`\`json
{
  "determination": "threat" | "safe" | "uncertain",
  "confidence": 0.0 to 1.0,
  "reasoning": "Brief explanation of your analysis",
  "suggestedAction": "block" | "confirm" | "allow"
}
\`\`\`

Guidelines for determination:
- "threat": Clear evidence of malicious or dangerous intent
- "safe": Clear evidence this is a legitimate, safe operation
- "uncertain": Cannot determine with confidence; err on the side of caution

Guidelines for suggestedAction:
- "block": For clear threats or high-risk uncertain cases
- "confirm": When user confirmation would be helpful
- "allow": Only for clearly safe operations`;

  return prompt;
}

/**
 * Parse LLM response to extract structured result
 */
export function parseAnalysisResponse(response: string): LLMAnalysisResult {
  // Try to extract JSON from the response
  const jsonMatch = response.match(/```json\s*([\s\S]*?)\s*```/);
  const jsonStr = jsonMatch ? jsonMatch[1] : response;

  try {
    const parsed = JSON.parse(jsonStr.trim());

    // Validate and normalize the response
    const determination = normalizeDetermination(parsed.determination);
    const confidence = normalizeConfidence(parsed.confidence);
    const reasoning = typeof parsed.reasoning === 'string' ? parsed.reasoning : 'No reasoning provided';
    const suggestedAction = normalizeSuggestedAction(parsed.suggestedAction, determination);

    return {
      determination,
      confidence,
      reasoning,
      suggestedAction,
    };
  } catch {
    // If parsing fails, return uncertain result
    return {
      determination: 'uncertain',
      confidence: 0.5,
      reasoning: 'Failed to parse LLM response',
      suggestedAction: 'confirm',
    };
  }
}

function normalizeDetermination(value: unknown): 'threat' | 'safe' | 'uncertain' {
  if (value === 'threat' || value === 'safe' || value === 'uncertain') {
    return value;
  }
  return 'uncertain';
}

function normalizeConfidence(value: unknown): number {
  if (typeof value === 'number' && value >= 0 && value <= 1) {
    return value;
  }
  return 0.5;
}

function normalizeSuggestedAction(
  value: unknown,
  determination: 'threat' | 'safe' | 'uncertain'
): 'block' | 'confirm' | 'allow' {
  if (value === 'block' || value === 'confirm' || value === 'allow') {
    return value;
  }

  // Default based on determination
  switch (determination) {
    case 'threat':
      return 'block';
    case 'safe':
      return 'allow';
    case 'uncertain':
      return 'confirm';
  }
}

// ============================================================================
// LLM Client Implementations
// ============================================================================

/**
 * Configuration for the LLM client
 */
export interface LLMClientConfig {
  /** LLM configuration from ClawsecConfig */
  llmConfig: LLMConfig;
  /** Optional timeout in milliseconds */
  timeoutMs?: number;
  /** Optional cache TTL in milliseconds */
  cacheTtlMs?: number;
  /** Whether to enable caching */
  enableCache?: boolean;
}

/**
 * Real LLM client that uses OpenClaw API
 */
export class OpenClawLLMClient implements LLMClient {
  private api: OpenClawAPI;
  private model: string | null;
  private timeoutMs: number;
  private cache: LLMResponseCache | null;
  private cacheTtlMs: number;

  constructor(api: OpenClawAPI, config: LLMClientConfig) {
    this.api = api;
    this.model = config.llmConfig.model;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_LLM_TIMEOUT_MS;
    this.cacheTtlMs = config.cacheTtlMs ?? DEFAULT_LLM_CACHE_TTL_MS;
    this.cache = config.enableCache !== false ? new LLMResponseCache(this.cacheTtlMs) : null;
  }

  isAvailable(): boolean {
    return this.api.isAvailable();
  }

  async analyze(request: LLMAnalysisRequest): Promise<LLMAnalysisResult> {
    // Check cache first
    if (this.cache) {
      const cacheKey = this.cache.generateKey(request);
      const cached = this.cache.get(cacheKey);
      if (cached) {
        return cached;
      }
    }

    try {
      const prompt = buildAnalysisPrompt(request);
      const response = await this.api.complete(prompt, {
        model: this.model,
        timeout: this.timeoutMs,
      });
      const result = parseAnalysisResponse(response);

      // Cache the result
      if (this.cache) {
        const cacheKey = this.cache.generateKey(request);
        this.cache.set(cacheKey, result);
      }

      return result;
    } catch (error) {
      // Return uncertain on error
      return {
        determination: 'uncertain',
        confidence: 0.5,
        reasoning: `LLM analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        suggestedAction: 'confirm',
      };
    }
  }

  /**
   * Clear the response cache
   */
  clearCache(): void {
    this.cache?.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; enabled: boolean } {
    return {
      size: this.cache?.size() ?? 0,
      enabled: this.cache !== null,
    };
  }
}

/**
 * Mock LLM client for testing
 * Provides deterministic responses based on detection characteristics
 */
export class MockLLMClient implements LLMClient {
  private available: boolean;
  private responseDelay: number;
  private cache: LLMResponseCache | null;
  private customResponses: Map<string, LLMAnalysisResult>;

  constructor(options?: {
    available?: boolean;
    responseDelay?: number;
    enableCache?: boolean;
    cacheTtlMs?: number;
  }) {
    this.available = options?.available ?? true;
    this.responseDelay = options?.responseDelay ?? 0;
    this.cache = options?.enableCache !== false ? new LLMResponseCache(options?.cacheTtlMs) : null;
    this.customResponses = new Map();
  }

  isAvailable(): boolean {
    return this.available;
  }

  /**
   * Set availability for testing
   */
  setAvailable(available: boolean): void {
    this.available = available;
  }

  /**
   * Set a custom response for a specific category
   */
  setCustomResponse(category: string, response: LLMAnalysisResult): void {
    this.customResponses.set(category, response);
  }

  async analyze(request: LLMAnalysisRequest): Promise<LLMAnalysisResult> {
    if (!this.available) {
      return {
        determination: 'uncertain',
        confidence: 0.5,
        reasoning: 'LLM client unavailable',
        suggestedAction: 'confirm',
      };
    }

    // Check cache first
    if (this.cache) {
      const cacheKey = this.cache.generateKey(request);
      const cached = this.cache.get(cacheKey);
      if (cached) {
        return cached;
      }
    }

    // Simulate processing time
    if (this.responseDelay > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.responseDelay));
    }

    // Check for custom response
    const customResponse = this.customResponses.get(request.detection.category);
    if (customResponse) {
      if (this.cache) {
        const cacheKey = this.cache.generateKey(request);
        this.cache.set(cacheKey, customResponse);
      }
      return customResponse;
    }

    // Generate deterministic response based on detection
    const result = this.generateMockResponse(request);

    // Cache the result
    if (this.cache) {
      const cacheKey = this.cache.generateKey(request);
      this.cache.set(cacheKey, result);
    }

    return result;
  }

  /**
   * Generate a mock response based on detection characteristics
   */
  private generateMockResponse(request: LLMAnalysisRequest): LLMAnalysisResult {
    const { detection, context } = request;

    // High confidence detections are treated as threats
    if (detection.confidence >= 0.75) {
      return {
        determination: 'threat',
        confidence: 0.85,
        reasoning: `High confidence ${detection.category} detection confirms threat`,
        suggestedAction: 'block',
      };
    }

    // Low confidence detections are treated as safe
    if (detection.confidence < 0.55) {
      return {
        determination: 'safe',
        confidence: 0.7,
        reasoning: `Low confidence ${detection.category} detection likely false positive`,
        suggestedAction: 'allow',
      };
    }

    // Category-specific logic for mid-range confidence
    switch (detection.category) {
      case 'purchase':
        // Purchase in known checkout flows is more likely a threat
        if (context.url?.includes('checkout') || context.url?.includes('pay')) {
          return {
            determination: 'threat',
            confidence: 0.8,
            reasoning: 'Checkout or payment URL indicates real purchase attempt',
            suggestedAction: 'block',
          };
        }
        break;

      case 'destructive':
        // Destructive commands in test directories might be safe
        if (JSON.stringify(context.toolInput).includes('test')) {
          return {
            determination: 'safe',
            confidence: 0.65,
            reasoning: 'Command appears to target test files/directories',
            suggestedAction: 'confirm',
          };
        }
        break;

      case 'secrets':
        // Secrets in env.example files are usually safe
        if (JSON.stringify(context.toolInput).includes('example')) {
          return {
            determination: 'safe',
            confidence: 0.75,
            reasoning: 'Secret appears to be in example/template file',
            suggestedAction: 'allow',
          };
        }
        break;

      case 'exfiltration':
        // Exfiltration to localhost is usually safe
        if (context.url?.includes('localhost') || context.url?.includes('127.0.0.1')) {
          return {
            determination: 'safe',
            confidence: 0.8,
            reasoning: 'Target is localhost, likely development/testing',
            suggestedAction: 'allow',
          };
        }
        break;
    }

    // Default uncertain response for ambiguous cases
    return {
      determination: 'uncertain',
      confidence: 0.6,
      reasoning: `Unable to definitively classify ${detection.category} detection`,
      suggestedAction: 'confirm',
    };
  }

  /**
   * Clear the response cache
   */
  clearCache(): void {
    this.cache?.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; enabled: boolean } {
    return {
      size: this.cache?.size() ?? 0,
      enabled: this.cache !== null,
    };
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create an LLM client
 *
 * @param config - LLM client configuration
 * @param api - Optional OpenClaw API instance (if available, creates real client)
 * @returns LLM client instance
 */
export function createLLMClient(config: LLMClientConfig, api?: OpenClawAPI): LLMClient {
  // If API is provided and available, use real client
  if (api && api.isAvailable()) {
    return new OpenClawLLMClient(api, config);
  }

  // Otherwise return mock client
  return new MockLLMClient({
    enableCache: config.enableCache,
    cacheTtlMs: config.cacheTtlMs,
  });
}

/**
 * Create a mock LLM client for testing
 */
export function createMockLLMClient(options?: {
  available?: boolean;
  responseDelay?: number;
  enableCache?: boolean;
  cacheTtlMs?: number;
}): MockLLMClient {
  return new MockLLMClient(options);
}

/**
 * Create an unavailable LLM client (always returns uncertain)
 */
export function createUnavailableLLMClient(): LLMClient {
  return new MockLLMClient({ available: false });
}
