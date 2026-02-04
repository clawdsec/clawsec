/**
 * Hybrid Detection Engine
 * Re-exports for clean imports
 */

// Types
export type {
  ThreatCategory,
  ToolCallContext,
  Detection,
  AnalysisResult,
  AnalysisAction,
  CacheEntry,
  DetectionCache,
  AnalyzerConfig,
  Analyzer,
} from './types.js';

export {
  SEVERITY_WEIGHTS,
  compareSeverity,
} from './types.js';

// Cache
export {
  DEFAULT_CACHE_TTL_MS,
  MAX_CACHE_SIZE,
  generateCacheKey,
  InMemoryCache,
  createCache,
  createNoOpCache,
} from './cache.js';

// Analyzer
export {
  HybridAnalyzer,
  createAnalyzer,
  createDefaultAnalyzer,
} from './analyzer.js';

// LLM Client
export type {
  ConversationMessage,
  LLMAnalysisRequest,
  LLMAnalysisResult,
  LLMClient,
  OpenClawAPI,
  LLMClientConfig,
} from './llm-client.js';

export {
  DEFAULT_LLM_TIMEOUT_MS,
  DEFAULT_LLM_CACHE_TTL_MS,
  MAX_LLM_CACHE_SIZE,
  LLMResponseCache,
  buildAnalysisPrompt,
  parseAnalysisResponse,
  OpenClawLLMClient,
  MockLLMClient,
  createLLMClient,
  createMockLLMClient,
  createUnavailableLLMClient,
} from './llm-client.js';
