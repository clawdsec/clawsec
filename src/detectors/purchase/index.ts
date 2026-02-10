/**
 * Purchase Detector
 * Main detector that combines domain, URL, and form field detection
 */

import type {
  DetectionContext,
  DetectionResult,
  PurchaseDetector as IPurchaseDetector,
  PurchaseDetectorConfig,
} from './types.js';
import { createLogger, type Logger } from '../../utils/logger.js';
import { DomainDetector, createDomainDetector } from './domain-detector.js';
import { UrlDetector, createUrlDetector } from './url-detector.js';
import { FormDetector, createFormDetector } from './form-detector.js';
import {
  SpendTracker,
  getGlobalSpendTracker,
  extractAmountFromInput,
} from './spend-tracker.js';
import type { PurchaseRule, Severity, SpendLimits } from '../../config/index.js';

// Re-export types
export * from './types.js';

// Re-export sub-detectors
export { DomainDetector, createDomainDetector } from './domain-detector.js';
export { UrlDetector, createUrlDetector } from './url-detector.js';
export { FormDetector, createFormDetector } from './form-detector.js';
export {
  extractDomain,
  matchDomain,
  globToRegex,
  matchesGlobPattern,
  hasPaymentKeyword,
} from './domain-detector.js';
export { extractPath, matchUrlPath } from './url-detector.js';
export { matchFormFields, containsPaymentValues } from './form-detector.js';

// Re-export spend tracker
export {
  SpendTracker,
  createSpendTracker,
  getGlobalSpendTracker,
  resetGlobalSpendTracker,
  extractAmountFromInput,
  extractAmount,
  type SpendRecord,
  type SpendLimitResult,
  type ISpendTracker,
} from './spend-tracker.js';

/**
 * No detection result (used when disabled or no match)
 */
function noDetection(severity: Severity): DetectionResult {
  return {
    detected: false,
    category: 'purchase',
    severity,
    confidence: 0,
    reason: 'No purchase activity detected',
  };
}

/**
 * Combine multiple detection results, taking the highest confidence
 */
function combineResults(results: (DetectionResult | null)[], severity: Severity): DetectionResult {
  const validResults = results.filter((r): r is DetectionResult => r !== null && r.detected);
  
  if (validResults.length === 0) {
    return noDetection(severity);
  }
  
  // Sort by confidence (highest first)
  validResults.sort((a, b) => b.confidence - a.confidence);
  
  // Take the highest confidence result as primary
  const primary = validResults[0];
  
  // Merge metadata from all results
  const mergedMetadata: DetectionResult['metadata'] = {
    ...primary.metadata,
  };
  
  // Collect all form fields
  const allFormFields: string[] = [];
  for (const result of validResults) {
    if (result.metadata?.formFields) {
      allFormFields.push(...result.metadata.formFields);
    }
  }
  if (allFormFields.length > 0) {
    mergedMetadata.formFields = [...new Set(allFormFields)];
  }
  
  // Build combined reason
  let reason = primary.reason;
  if (validResults.length > 1) {
    const additionalReasons = validResults.slice(1).map(r => r.reason);
    reason = `${primary.reason}. Additional signals: ${additionalReasons.join('; ')}`;
  }
  
  // Boost confidence if multiple detectors triggered
  let confidence = primary.confidence;
  if (validResults.length >= 2) {
    // Boost confidence but cap at 0.99
    confidence = Math.min(0.99, confidence + 0.05 * (validResults.length - 1));
  }
  
  return {
    detected: true,
    category: 'purchase',
    severity,
    confidence,
    reason,
    metadata: mergedMetadata,
  };
}

/**
 * Main purchase detector implementation
 */
export class PurchaseDetectorImpl implements IPurchaseDetector {
  private config: PurchaseDetectorConfig;
  private domainDetector: DomainDetector;
  private urlDetector: UrlDetector;
  private formDetector: FormDetector;
  private spendTracker: SpendTracker;
  private logger: Logger;

  constructor(config: PurchaseDetectorConfig, spendTracker?: SpendTracker, logger?: Logger) {
    this.config = config;
    this.logger = logger ?? createLogger(null, null);

    const customBlocklist = config.domains?.mode === 'blocklist'
      ? (config.domains.blocklist || [])
      : [];

    this.domainDetector = createDomainDetector(config.severity, customBlocklist);
    this.urlDetector = createUrlDetector(config.severity, this.logger);
    this.formDetector = createFormDetector(config.severity, this.logger);
    this.spendTracker = spendTracker || getGlobalSpendTracker();
  }

  async detect(context: DetectionContext): Promise<DetectionResult> {
    this.logger.debug(`[PurchaseDetector] Starting detection: tool=${context.toolName}`);

    // Check if detector is enabled
    if (!this.config.enabled) {
      this.logger.debug(`[PurchaseDetector] Detector disabled`);
      return noDetection(this.config.severity);
    }

    // Run all sub-detectors
    this.logger.debug(`[PurchaseDetector] Running domain detector`);
    const domainResult = this.domainDetector.detect(context);
    if (domainResult && domainResult.detected) {
      this.logger.info(`[PurchaseDetector] Domain detection: domain=${domainResult.metadata?.domain || 'unknown'}, confidence=${domainResult.confidence}`);
    }

    this.logger.debug(`[PurchaseDetector] Running URL detector`);
    const urlResult = this.urlDetector.detect(context);
    if (urlResult && urlResult.detected) {
      this.logger.info(`[PurchaseDetector] URL detection: url=${urlResult.metadata?.url || 'unknown'}, confidence=${urlResult.confidence}`);
    }

    this.logger.debug(`[PurchaseDetector] Running form detector`);
    const formResult = this.formDetector.detect(context);
    if (formResult && formResult.detected) {
      this.logger.info(`[PurchaseDetector] Form detection: fields=${formResult.metadata?.formFields?.join(',') || 'unknown'}, confidence=${formResult.confidence}`);
    }

    // Combine results
    const validDetections = [domainResult, urlResult, formResult].filter((r): r is DetectionResult => r !== null && r.detected);
    if (validDetections.length === 0) {
      this.logger.debug(`[PurchaseDetector] No detections found`);
    } else {
      this.logger.debug(`[PurchaseDetector] Combining ${validDetections.length} detections`);
      if (validDetections.length > 1) {
        this.logger.info(`[PurchaseDetector] Confidence boost: multiple sub-detectors triggered (${validDetections.length})`);
      }
    }

    let result = combineResults([domainResult, urlResult, formResult], this.config.severity);

    // If purchase detected and spend limits configured, check limits
    if (result.detected && this.config.spendLimits) {
      this.logger.debug(`[PurchaseDetector] Checking spend limits`);
      result = this.checkSpendLimits(result, context);
    }

    this.logger.debug(`[PurchaseDetector] Detection complete: detected=${result.detected}, confidence=${result.confidence}`);
    return result;
  }

  /**
   * Check spend limits and enhance detection result
   */
  private checkSpendLimits(result: DetectionResult, context: DetectionContext): DetectionResult {
    const limits = this.config.spendLimits;
    if (!limits) {
      return result;
    }

    // Try to extract amount from the tool input
    const amount = extractAmountFromInput(context.toolInput, this.logger);

    // If no amount found, use per-transaction limit as the assumed amount
    // This is a security-first approach - assume worst case if unknown
    const effectiveAmount = amount ?? limits.perTransaction;

    // Check limits
    const limitResult = this.spendTracker.checkLimits(effectiveAmount, limits);

    // Enhance metadata with amount info
    const enhancedMetadata = {
      ...result.metadata,
      amount: amount ?? undefined,
      currentDailyTotal: limitResult.currentDailyTotal,
    };

    // If limits exceeded, add to reason
    if (!limitResult.allowed) {
      enhancedMetadata.exceededLimit = limitResult.exceededLimit;
      
      const limitReason = limitResult.message || 
        `Spend limit exceeded: ${limitResult.exceededLimit}`;
      
      return {
        ...result,
        reason: `${result.reason}. ${limitReason}`,
        metadata: enhancedMetadata,
      };
    }

    // Limits not exceeded but amount detected - add to metadata
    return {
      ...result,
      metadata: enhancedMetadata,
    };
  }

  /**
   * Record a transaction after it has been approved
   * Call this when a purchase is allowed to proceed
   */
  recordTransaction(amount: number, metadata?: { transactionId?: string; domain?: string }): void {
    this.spendTracker.record(amount, metadata);
  }

  /**
   * Get the spend tracker instance
   */
  getSpendTracker(): SpendTracker {
    return this.spendTracker;
  }

  /**
   * Get the configured action for detected purchases
   */
  getAction() {
    return this.config.action;
  }

  /**
   * Check if the detector is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }

  /**
   * Get the configured spend limits
   */
  getSpendLimits(): SpendLimits | undefined {
    return this.config.spendLimits;
  }
}

/**
 * Create a purchase detector from PurchaseRule configuration
 */
export function createPurchaseDetector(rule: PurchaseRule, spendTracker?: SpendTracker, logger?: Logger): PurchaseDetectorImpl {
  const config: PurchaseDetectorConfig = {
    enabled: rule.enabled,
    severity: rule.severity,
    action: rule.action,
    domains: rule.domains ? {
      mode: rule.domains.mode,
      blocklist: rule.domains.blocklist,
    } : undefined,
    spendLimits: rule.spendLimits ? {
      perTransaction: rule.spendLimits.perTransaction,
      daily: rule.spendLimits.daily,
    } : undefined,
  };
  
  return new PurchaseDetectorImpl(config, spendTracker, logger);
}

/**
 * Create a purchase detector with default configuration
 */
export function createDefaultPurchaseDetector(): PurchaseDetectorImpl {
  return new PurchaseDetectorImpl({
    enabled: true,
    severity: 'critical',
    action: 'block',
  });
}

// Default export
export default PurchaseDetectorImpl;
