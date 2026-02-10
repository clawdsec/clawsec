/**
 * Hybrid Detection Engine Analyzer
 * Main engine that orchestrates all 5 detectors and produces unified results
 *
 * Architecture:
 * Tool Call -> Pattern Matching (≤5ms) -> BLOCK/ALLOW
 *                                    |
 *              ambiguous -------------+
 *                   |
 *                   v
 *           LLM Analysis (~500ms) -> BLOCK/CONFIRM
 */

import type {
  Analyzer,
  AnalyzerConfig,
  AnalysisResult,
  AnalysisAction,
  Detection,
  ToolCallContext,
  ThreatCategory,
  DetectionCache,
  LLMClient,
  LLMAnalysisResult,
} from './types.js';
import { createLogger, type Logger } from '../utils/logger.js';
import { compareSeverity } from './types.js';
import { createCache, createNoOpCache, generateCacheKey, DEFAULT_CACHE_TTL_MS } from './cache.js';
import type { ClawsecConfig, Severity } from '../config/index.js';

// Import detector factories
import { createDefaultPurchaseDetector, createPurchaseDetector } from '../detectors/purchase/index.js';
import { createDefaultWebsiteDetector, createWebsiteDetector } from '../detectors/website/index.js';
import { createDefaultDestructiveDetector, createDestructiveDetector } from '../detectors/destructive/index.js';
import { createDefaultSecretsDetector, createSecretsDetector } from '../detectors/secrets/index.js';
import { createDefaultExfiltrationDetector, createExfiltrationDetector } from '../detectors/exfiltration/index.js';

// Import detector types
import type { PurchaseDetector, DetectionResult as PurchaseDetectionResult } from '../detectors/purchase/index.js';
import type { WebsiteDetector, WebsiteDetectionResult } from '../detectors/website/index.js';
import type { DestructiveDetector, DestructiveDetectionResult } from '../detectors/destructive/index.js';
import type { SecretsDetector, SecretsDetectionResult } from '../detectors/secrets/index.js';
import type { IExfiltrationDetector, ExfiltrationDetectionResult } from '../detectors/exfiltration/index.js';

/**
 * Union type of all detection results
 */
type AnyDetectionResult =
  | PurchaseDetectionResult
  | WebsiteDetectionResult
  | DestructiveDetectionResult
  | SecretsDetectionResult
  | ExfiltrationDetectionResult;

/**
 * Convert a detector-specific result to a unified Detection
 */
function toDetection(result: AnyDetectionResult): Detection | null {
  if (!result.detected) {
    return null;
  }

  return {
    category: result.category as ThreatCategory,
    severity: result.severity,
    confidence: result.confidence,
    reason: result.reason,
    metadata: result.metadata as Record<string, unknown> | undefined,
  };
}

/**
 * Determine the recommended action based on detections
 *
 * Action determination logic:
 * - critical + confidence > 0.8 -> block
 * - critical + confidence < 0.8 -> confirm (needs LLM)
 * - high + confidence > 0.7 -> confirm
 * - high + confidence < 0.7 -> warn (needs LLM consideration)
 * - medium -> warn
 * - low -> log (allow with warning)
 * - no detections -> allow
 */
function determineAction(
  detections: Detection[],
  config: ClawsecConfig
): { action: AnalysisAction; requiresLLM: boolean } {
  if (detections.length === 0) {
    return { action: 'allow', requiresLLM: false };
  }

  // Get primary detection (highest severity, highest confidence)
  const primary = detections[0];
  const { severity, confidence, category } = primary;

  // Check if LLM is enabled in config
  const llmEnabled = config.llm?.enabled ?? false;

  // FIRST: Check if config specifies an action for this category
  // Skip 'unknown' category as it's not a valid config key
  if (category !== 'unknown') {
    const categoryConfig = config.rules[category];
    if (categoryConfig?.action) {
      // User explicitly configured an action - RESPECT IT
      let configuredAction = categoryConfig.action;

      // Convert 'agent-confirm' to 'confirm' for internal use
      if (configuredAction === 'agent-confirm') {
        configuredAction = 'confirm';
      }

      // Determine if LLM should be involved (if confidence is ambiguous)
      const isAmbiguous = confidence >= 0.5 && confidence <= 0.8;
      const requiresLLM = llmEnabled && isAmbiguous;

      return {
        action: configuredAction as AnalysisAction,
        requiresLLM
      };
    }
  }

  // FALLBACK: If no config action specified, use confidence-based logic
  switch (severity) {
    case 'critical':
      if (confidence > 0.8) {
        // High confidence critical -> block immediately
        return { action: 'block', requiresLLM: false };
      } else {
        // Lower confidence critical -> confirm, may need LLM
        // Ambiguous range: 0.5-0.8
        const isAmbiguous = confidence >= 0.5 && confidence <= 0.8;
        return { action: 'confirm', requiresLLM: llmEnabled && isAmbiguous };
      }

    case 'high':
      if (confidence > 0.7) {
        // High confidence high severity -> confirm
        return { action: 'confirm', requiresLLM: false };
      } else {
        // Lower confidence high -> warn, may need LLM
        const isAmbiguous = confidence >= 0.5 && confidence <= 0.7;
        return { action: 'warn', requiresLLM: llmEnabled && isAmbiguous };
      }

    case 'medium':
      // Medium severity -> warn
      // May need LLM if confidence is ambiguous
      const isAmbiguousMedium = confidence >= 0.5 && confidence <= 0.8;
      return { action: 'warn', requiresLLM: llmEnabled && isAmbiguousMedium };

    case 'low':
      // Low severity -> allow with logging
      return { action: 'allow', requiresLLM: false };

    default:
      return { action: 'allow', requiresLLM: false };
  }
}

/**
 * Sort detections by severity (highest first), then by confidence (highest first)
 */
function sortDetections(detections: Detection[]): Detection[] {
  return [...detections].sort((a, b) => {
    // First compare by severity (descending)
    const severityDiff = compareSeverity(b.severity, a.severity);
    if (severityDiff !== 0) {
      return severityDiff;
    }
    // Then by confidence (descending)
    return b.confidence - a.confidence;
  });
}

/**
 * Main hybrid detection engine implementation
 */
export class HybridAnalyzer implements Analyzer {
  private config: ClawsecConfig;
  private cache: DetectionCache;
  private cacheEnabled: boolean;
  private cacheTtlMs: number;
  private llmClient?: LLMClient;
  private logger: Logger;

  // Detectors
  private purchaseDetector: PurchaseDetector;
  private websiteDetector: WebsiteDetector;
  private destructiveDetector: DestructiveDetector;
  private secretsDetector: SecretsDetector;
  private exfiltrationDetector: IExfiltrationDetector;

  constructor(analyzerConfig: AnalyzerConfig) {
    this.config = analyzerConfig.config;
    this.cacheEnabled = analyzerConfig.enableCache ?? true;
    this.cacheTtlMs = analyzerConfig.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.llmClient = analyzerConfig.llmClient;
    this.logger = analyzerConfig.logger ?? createLogger(null, null);
    
    // Initialize cache
    this.cache = this.cacheEnabled
      ? createCache(this.cacheTtlMs)
      : createNoOpCache();

    // Initialize detectors from config
    this.purchaseDetector = this.config.rules.purchase
      ? createPurchaseDetector(this.config.rules.purchase, undefined, this.logger)
      : createDefaultPurchaseDetector();

    this.websiteDetector = this.config.rules.website
      ? createWebsiteDetector(this.config.rules.website, this.logger)
      : createDefaultWebsiteDetector();

    this.destructiveDetector = this.config.rules.destructive
      ? createDestructiveDetector(this.config.rules.destructive, this.logger)
      : createDefaultDestructiveDetector();

    this.secretsDetector = this.config.rules.secrets
      ? createSecretsDetector(this.config.rules.secrets, this.logger)
      : createDefaultSecretsDetector();

    this.exfiltrationDetector = this.config.rules.exfiltration
      ? createExfiltrationDetector(this.config.rules.exfiltration, this.logger)
      : createDefaultExfiltrationDetector();
  }

  /**
   * Analyze a tool call and return the result
   */
  async analyze(context: ToolCallContext): Promise<AnalysisResult> {
    const startTime = Date.now();
    const toolName = context.toolName;
    const url = context.url || 'none';

    this.logger.debug(`[Analyzer] Starting analysis: tool=${toolName}, url=${url}`);

    // Check if globally disabled
    if (!this.config.global?.enabled) {
      return {
        action: 'allow',
        detections: [],
        requiresLLM: false,
        cached: false,
        durationMs: Date.now() - startTime,
      };
    }

    // Generate cache key
    const cacheKey = generateCacheKey(context.toolName, context.toolInput);

    // Check cache first
    if (this.cacheEnabled) {
      const cachedResult = this.cache.get(cacheKey);
      if (cachedResult) {
        this.logger.debug(`[Analyzer] Cache hit: key=${cacheKey}`);
        return {
          ...cachedResult,
          durationMs: Date.now() - startTime,
        };
      }
      this.logger.debug(`[Analyzer] Cache miss: key=${cacheKey}`);
    }

    // Run all detectors in parallel
    this.logger.debug(`[Analyzer] Running 5 detectors`);
    const detectionResults = await Promise.all([
      this.runPurchaseDetector(context),
      this.runWebsiteDetector(context),
      this.runDestructiveDetector(context),
      this.runSecretsDetector(context),
      this.runExfiltrationDetector(context),
    ]);

    // Log detection results
    for (const result of detectionResults) {
      if (result.detected) {
        this.logger.info(`[Analyzer] Detection: detector=${result.category}, severity=${result.severity}, confidence=${result.confidence}, reason="${result.reason}"`);
      } else {
        this.logger.debug(`[Analyzer] No detection: detector=${result.category}`);
      }
    }

    // Convert to unified detections and filter out non-detections
    const detections = detectionResults
      .map(toDetection)
      .filter((d): d is Detection => d !== null);

    // Sort by severity (critical > high > medium > low) and confidence
    const sortedDetections = sortDetections(detections);
    this.logger.debug(`[Analyzer] Found ${sortedDetections.length} detections, sorted by severity and confidence`);

    // Determine action based on highest severity detection
    let { action, requiresLLM } = determineAction(sortedDetections, this.config);
    this.logger.info(`[Analyzer] Action determined: ${action}, detections=${sortedDetections.length}, requiresLLM=${requiresLLM}`);

    // If LLM analysis is needed and we have an LLM client, perform analysis
    let llmResult: LLMAnalysisResult | undefined;
    if (requiresLLM && this.llmClient && this.llmClient.isAvailable() && sortedDetections[0]) {
      this.logger.info(`[Analyzer] LLM analysis required: confidence in ambiguous range`);
      this.logger.debug(`[Analyzer] Invoking LLM analysis`);
      
      llmResult = await this.performLLMAnalysis(sortedDetections[0], context);
      this.logger.info(`[Analyzer] LLM response: determination=${llmResult.determination}, confidence=${llmResult.confidence}, suggested_action=${llmResult.suggestedAction}`);
      
      // Adjust action based on LLM result
      const previousAction = action;
      const adjustedAction = this.adjustActionFromLLM(action, llmResult);
      action = adjustedAction;
      
      if (previousAction !== action) {
        this.logger.info(`[Analyzer] LLM override: changed action from ${previousAction} to ${action}`);
      }
      
      // LLM has made its determination, no longer needs LLM
      requiresLLM = false;
    } else if (requiresLLM && (!this.llmClient || !this.llmClient.isAvailable())) {
      this.logger.debug(`[Analyzer] LLM not configured or unavailable, using pattern-based action`);
    }

    // Build result
    const result: AnalysisResult = {
      action,
      detections: sortedDetections,
      primaryDetection: sortedDetections[0],
      requiresLLM,
      cached: false,
      durationMs: Date.now() - startTime,
    };

    // Cache the result (unless it still requires LLM - those shouldn't be cached)
    if (this.cacheEnabled && !requiresLLM) {
      this.cache.set(cacheKey, result);
      this.logger.debug(`[Analyzer] Cached result: ttl=${this.cacheTtlMs}ms`);
    }

    this.logger.debug(`[Analyzer] Analysis complete: tool=${toolName}, action=${action}, duration=${Date.now() - startTime}ms`);
    return result;
  }

  /**
   * Clear the detection cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; enabled: boolean } {
    return {
      size: this.cache.size(),
      enabled: this.cacheEnabled,
    };
  }

  /**
   * Run purchase detector if enabled
   */
  private async runPurchaseDetector(context: ToolCallContext): Promise<AnyDetectionResult> {
    if (!this.config.rules.purchase?.enabled) {
      return this.createNoDetection('purchase');
    }
    return this.purchaseDetector.detect({
      toolName: context.toolName,
      toolInput: context.toolInput,
      url: context.url,
    });
  }

  /**
   * Run website detector if enabled
   */
  private async runWebsiteDetector(context: ToolCallContext): Promise<AnyDetectionResult> {
    if (!this.config.rules.website?.enabled) {
      return this.createNoDetection('website');
    }
    return this.websiteDetector.detect({
      toolName: context.toolName,
      toolInput: context.toolInput,
      url: context.url,
    });
  }

  /**
   * Run destructive detector if enabled
   */
  private async runDestructiveDetector(context: ToolCallContext): Promise<AnyDetectionResult> {
    if (!this.config.rules.destructive?.enabled) {
      return this.createNoDetection('destructive');
    }
    return this.destructiveDetector.detect({
      toolName: context.toolName,
      toolInput: context.toolInput,
      url: context.url,
    });
  }

  /**
   * Run secrets detector if enabled
   */
  private async runSecretsDetector(context: ToolCallContext): Promise<AnyDetectionResult> {
    if (!this.config.rules.secrets?.enabled) {
      return this.createNoDetection('secrets');
    }
    return this.secretsDetector.detect({
      toolName: context.toolName,
      toolInput: context.toolInput,
      toolOutput: context.toolOutput,
    });
  }

  /**
   * Run exfiltration detector if enabled
   */
  private async runExfiltrationDetector(context: ToolCallContext): Promise<AnyDetectionResult> {
    if (!this.config.rules.exfiltration?.enabled) {
      return this.createNoDetection('exfiltration');
    }
    return this.exfiltrationDetector.detect({
      toolName: context.toolName,
      toolInput: context.toolInput,
      url: context.url,
    });
  }

  /**
   * Create a no-detection result for disabled detectors
   */
  private createNoDetection(category: ThreatCategory): AnyDetectionResult {
    return {
      detected: false,
      category,
      severity: 'low' as Severity,
      confidence: 0,
      reason: `${category} detection disabled`,
    } as AnyDetectionResult;
  }

  /**
   * Perform LLM analysis on an ambiguous detection
   */
  private async performLLMAnalysis(
    detection: Detection,
    context: ToolCallContext
  ): Promise<LLMAnalysisResult> {
    try {
      return await this.llmClient!.analyze({
        detection,
        context,
      });
    } catch (error) {
      // Return uncertain on error - don't block the flow
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.warn(`[Analyzer] LLM analysis failed: ${errorMessage}, using pattern-based action`);
      return {
        determination: 'uncertain',
        confidence: 0.5,
        reasoning: 'LLM analysis failed',
        suggestedAction: 'confirm',
      };
    }
  }

  /**
   * Adjust the action based on LLM analysis result
   */
  private adjustActionFromLLM(
    currentAction: AnalysisAction,
    llmResult: LLMAnalysisResult
  ): AnalysisAction {
    // Map LLM suggested action to AnalysisAction
    switch (llmResult.suggestedAction) {
      case 'block':
        return 'block';
      case 'allow':
        // Only allow if LLM is confident it's safe
        return llmResult.confidence >= 0.7 ? 'allow' : 'warn';
      case 'confirm':
        return 'confirm';
      default:
        // Fall back to original action if LLM result is unexpected
        return currentAction;
    }
  }
}

/**
 * Create an analyzer from configuration
 */
export function createAnalyzer(config: ClawsecConfig, options?: Partial<AnalyzerConfig>, logger?: Logger): Analyzer {
  return new HybridAnalyzer({
    config,
    enableCache: options?.enableCache,
    cacheTtlMs: options?.cacheTtlMs,
    llmClient: options?.llmClient,
    logger,
  });
}

/**
 * Create an analyzer with default configuration
 */
export function createDefaultAnalyzer(): Analyzer {
  const defaultConfig: ClawsecConfig = {
    version: '1.0',
    global: {
      enabled: true,
      logLevel: 'info',
    },
    llm: {
      enabled: true,
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
      sanitization: {
        enabled: true,
        severity: 'high',
        action: 'block',
        minConfidence: 0.5,
        redactMatches: false,
        categories: {
          instructionOverride: true,
          systemLeak: true,
          jailbreak: true,
          encodedPayload: true,
        },
      },
    },
    approval: {
      native: { enabled: true, timeout: 300 },
      agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
      webhook: { enabled: false, url: undefined, timeout: 30, headers: {} },
    },
  };

  return new HybridAnalyzer({ config: defaultConfig });
}

// Re-export types
export type { Analyzer, AnalyzerConfig, AnalysisResult, Detection, ToolCallContext, ThreatCategory };
