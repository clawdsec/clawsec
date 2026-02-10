/**
 * Hybrid Detection Engine Types
 * Type definitions for the main detection engine that orchestrates all detectors
 */

import type { Severity, ClawsecConfig } from '../config/index.js';
import type { Logger } from '../utils/logger.js';

/**
 * Actions that can be returned by the analyzer
 * Note: This extends the config Action type with 'allow' for analysis results
 */
export type AnalysisAction = 'allow' | 'block' | 'confirm' | 'warn' | 'log';

/**
 * Threat categories that can be detected
 */
export type ThreatCategory =
  | 'purchase'
  | 'website'
  | 'destructive'
  | 'secrets'
  | 'exfiltration'
  | 'unknown';

/**
 * Detection context provided to the engine
 */
export interface ToolCallContext {
  /** Name of the tool being invoked */
  toolName: string;
  /** Input parameters to the tool */
  toolInput: Record<string, unknown>;
  /** URL being accessed (for browser/navigation tools) */
  url?: string;
  /** Output from the tool (for post-execution scanning like secrets) */
  toolOutput?: string;
}

/**
 * Individual detection result
 */
export interface Detection {
  /** Category of threat detected */
  category: ThreatCategory;
  /** Severity level */
  severity: Severity;
  /** Confidence score from 0 to 1 */
  confidence: number;
  /** Human-readable reason for the detection */
  reason: string;
  /** Additional metadata about the detection */
  metadata?: Record<string, unknown>;
}

/**
 * Result of the analysis
 */
export interface AnalysisResult {
  /** Recommended action to take */
  action: AnalysisAction;
  /** All detections found across all enabled detectors */
  detections: Detection[];
  /** Highest severity detection (if any) */
  primaryDetection?: Detection;
  /** True if the result needs LLM analysis for ambiguous cases */
  requiresLLM: boolean;
  /** True if the result was retrieved from cache */
  cached: boolean;
  /** Analysis duration in milliseconds */
  durationMs?: number;
}

/**
 * Cache entry for storing analysis results
 */
export interface CacheEntry<T> {
  /** The cached value */
  value: T;
  /** Timestamp when the entry was created */
  createdAt: number;
  /** Time-to-live in milliseconds */
  ttl: number;
}

/**
 * Cache interface for detection results
 */
export interface DetectionCache {
  /** Get a cached result by key */
  get(key: string): AnalysisResult | undefined;
  /** Set a cached result */
  set(key: string, result: AnalysisResult, ttl?: number): void;
  /** Check if a key exists and is not expired */
  has(key: string): boolean;
  /** Clear all entries */
  clear(): void;
  /** Delete a specific entry */
  delete(key: string): boolean;
  /** Get the number of entries */
  size(): number;
}

/**
 * Configuration for the analyzer
 */
export interface AnalyzerConfig {
  /** The Clawsec configuration */
  config: ClawsecConfig;
  /** Enable caching (default: true) */
  enableCache?: boolean;
  /** Cache TTL in milliseconds (default: 5 minutes) */
  cacheTtlMs?: number;
  /** Optional LLM client for analyzing ambiguous detections */
  llmClient?: LLMClient;
  /** Optional logger instance */
  logger?: Logger;
}

/**
 * LLM analysis result determination
 */
export type LLMDetermination = 'threat' | 'safe' | 'uncertain';

/**
 * LLM analysis suggested action
 */
export type LLMSuggestedAction = 'block' | 'confirm' | 'allow';

/**
 * Result of LLM analysis
 */
export interface LLMAnalysisResult {
  /** Determination of the threat level */
  determination: LLMDetermination;
  /** Confidence in the determination (0-1) */
  confidence: number;
  /** Reasoning behind the determination */
  reasoning: string;
  /** Suggested action based on analysis */
  suggestedAction: LLMSuggestedAction;
}

/**
 * Request to analyze a detection with LLM
 */
export interface LLMAnalysisRequest {
  /** The detection to analyze */
  detection: Detection;
  /** Context of the tool call that triggered the detection */
  context: ToolCallContext;
}

/**
 * Interface for LLM clients (minimal for avoiding circular deps)
 */
export interface LLMClient {
  /** Analyze a detection and determine if it's a real threat */
  analyze(request: LLMAnalysisRequest): Promise<LLMAnalysisResult>;
  /** Check if the LLM client is available and configured */
  isAvailable(): boolean;
}

/**
 * Main analyzer interface
 */
export interface Analyzer {
  /** Analyze a tool call and return the result */
  analyze(context: ToolCallContext): Promise<AnalysisResult>;
  /** Clear the detection cache */
  clearCache(): void;
  /** Get cache statistics */
  getCacheStats(): { size: number; enabled: boolean };
}

/**
 * Severity weights for sorting (higher = more severe)
 */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Compare two severities
 * @returns negative if a < b, 0 if equal, positive if a > b
 */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_WEIGHTS[a] - SEVERITY_WEIGHTS[b];
}
