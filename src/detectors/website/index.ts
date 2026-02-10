/**
 * Website Detector
 * Main detector that controls which websites an AI agent can navigate to
 * 
 * Supports two modes:
 * - Allowlist mode: Only pre-approved domains are accessible
 * - Blocklist mode: Everything except blocked domains is accessible
 * 
 * Additionally performs category-based detection for malware, phishing, etc.
 */

import type {
  DetectionContext,
  WebsiteDetectionResult,
  WebsiteDetector as IWebsiteDetector,
  WebsiteDetectorConfig,
} from './types.js';
import { createLogger, type Logger } from '../../utils/logger.js';

import { 
  extractDomain, 
  extractUrlFromContext, 
  matchesAnyPattern,
} from './pattern-matcher.js';
import { 
  detectCategory, 
  isDangerousCategory, 
  getCategorySeverityDescription,
} from './category-detector.js';
import type { WebsiteRule, Severity, FilterMode } from '../../config/index.js';

// Re-export types
export * from './types.js';

// Re-export pattern matcher functions
export { 
  extractDomain, 
  extractUrlFromContext, 
  matchesAnyPattern,
  matchesGlobPattern,
  globToRegex,
} from './pattern-matcher.js';

// Re-export category detector functions
export { 
  detectCategory, 
  isDangerousCategory, 
  isWarningCategory,
  getCategorySeverityDescription,
} from './category-detector.js';

/**
 * No detection result (used when disabled or allowed)
 */
function noDetection(severity: Severity, mode: FilterMode): WebsiteDetectionResult {
  return {
    detected: false,
    category: 'website',
    severity,
    confidence: 0,
    reason: 'Website access is allowed',
    metadata: {
      mode,
    },
  };
}

/**
 * Main website detector implementation
 */
export class WebsiteDetectorImpl implements IWebsiteDetector {
  private config: WebsiteDetectorConfig;
  private logger: Logger;

  constructor(config: WebsiteDetectorConfig, logger?: Logger) {
    this.config = config;
    this.logger = logger ?? createLogger(null, null);
  }

  async detect(context: DetectionContext): Promise<WebsiteDetectionResult> {
    this.logger.debug(`[WebsiteDetector] Starting detection: tool=${context.toolName}`);

    // Check if detector is enabled
    if (!this.config.enabled) {
      this.logger.debug(`[WebsiteDetector] Detector disabled`);
      return noDetection(this.config.severity, this.config.mode);
    }

    // Extract URL from context
    const url = extractUrlFromContext(context);
    if (!url) {
      this.logger.debug(`[WebsiteDetector] No URL found in context`);
      return noDetection(this.config.severity, this.config.mode);
    }

    // Extract domain from URL
    const domain = extractDomain(url);
    if (!domain) {
      this.logger.debug(`[WebsiteDetector] Could not extract domain from URL: ${url}`);
      return noDetection(this.config.severity, this.config.mode);
    }

    this.logger.debug(`[WebsiteDetector] Checking domain: ${domain} (mode: ${this.config.mode})`);

    // First, check for dangerous categories (malware, phishing) regardless of mode
    const categoryResult = detectCategory(domain);
    if (categoryResult.detected && categoryResult.category && isDangerousCategory(categoryResult.category)) {
      this.logger.info(`[WebsiteDetector] Dangerous category detected: ${categoryResult.category}, confidence=${categoryResult.confidence}`);
      return {
        detected: true,
        category: 'website',
        severity: 'critical', // Always critical for dangerous categories
        confidence: categoryResult.confidence,
        reason: `Blocked: ${getCategorySeverityDescription(categoryResult.category)} detected`,
        metadata: {
          url,
          domain,
          matchedPattern: categoryResult.matchedPattern,
          mode: this.config.mode,
          websiteCategory: categoryResult.category,
        },
      };
    }

    // Apply mode-based filtering
    this.logger.debug(`[WebsiteDetector] Applying ${this.config.mode} mode filtering`);
    const result = this.config.mode === 'allowlist'
      ? this.checkAllowlistMode(url, domain, categoryResult)
      : this.checkBlocklistMode(url, domain, categoryResult);

    if (result.detected) {
      this.logger.info(`[WebsiteDetector] Detection: domain=${domain}, confidence=${result.confidence}, reason="${result.reason}"`);
    } else {
      this.logger.debug(`[WebsiteDetector] No detection: domain=${domain} is allowed`);
    }

    this.logger.debug(`[WebsiteDetector] Detection complete: detected=${result.detected}`);
    return result;
  }

  /**
   * Allowlist mode: Block if NOT in allowlist
   */
  private checkAllowlistMode(
    url: string, 
    domain: string,
    categoryResult: ReturnType<typeof detectCategory>
  ): WebsiteDetectionResult {
    const allowlist = this.config.allowlist;
    
    // If allowlist is empty, block everything
    if (allowlist.length === 0) {
      return {
        detected: true,
        category: 'website',
        severity: this.config.severity,
        confidence: 0.99,
        reason: 'Blocked: No websites are allowed (empty allowlist)',
        metadata: {
          url,
          domain,
          mode: 'allowlist',
          websiteCategory: categoryResult.category,
        },
      };
    }

    // Check if domain is in allowlist
    const allowlistMatch = matchesAnyPattern(domain, allowlist);
    
    if (allowlistMatch.matched) {
      // Domain is allowed
      return {
        detected: false,
        category: 'website',
        severity: this.config.severity,
        confidence: 0,
        reason: `Website is allowed: ${domain} matched allowlist pattern "${allowlistMatch.pattern}"`,
        metadata: {
          url,
          domain,
          matchedPattern: allowlistMatch.pattern,
          mode: 'allowlist',
        },
      };
    }

    // Domain is NOT in allowlist - block it
    let reason = `Blocked: ${domain} is not in the allowlist`;
    if (categoryResult.detected && categoryResult.category) {
      reason += ` (detected as ${getCategorySeverityDescription(categoryResult.category)})`;
    }

    return {
      detected: true,
      category: 'website',
      severity: this.config.severity,
      confidence: 0.95,
      reason,
      metadata: {
        url,
        domain,
        mode: 'allowlist',
        websiteCategory: categoryResult.category,
      },
    };
  }

  /**
   * Blocklist mode: Block if IN blocklist
   */
  private checkBlocklistMode(
    url: string, 
    domain: string,
    categoryResult: ReturnType<typeof detectCategory>
  ): WebsiteDetectionResult {
    const blocklist = this.config.blocklist;

    // Check if domain is in blocklist
    const blocklistMatch = matchesAnyPattern(domain, blocklist);
    
    if (blocklistMatch.matched) {
      return {
        detected: true,
        category: 'website',
        severity: this.config.severity,
        confidence: blocklistMatch.confidence,
        reason: `Blocked: ${domain} matched blocklist pattern "${blocklistMatch.pattern}"`,
        metadata: {
          url,
          domain,
          matchedPattern: blocklistMatch.pattern,
          mode: 'blocklist',
          websiteCategory: categoryResult.category,
        },
      };
    }

    // Check for warning categories (gambling, adult) - detected but with warning
    if (categoryResult.detected && categoryResult.category) {
      return {
        detected: true,
        category: 'website',
        severity: 'medium', // Lower severity for warning categories
        confidence: categoryResult.confidence,
        reason: `Warning: ${getCategorySeverityDescription(categoryResult.category)} detected`,
        metadata: {
          url,
          domain,
          matchedPattern: categoryResult.matchedPattern,
          mode: 'blocklist',
          websiteCategory: categoryResult.category,
        },
      };
    }

    // Domain is allowed (not in blocklist and no category detected)
    return noDetection(this.config.severity, this.config.mode);
  }

  /**
   * Get the configured action for detected websites
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
   * Get the filter mode
   */
  getMode(): FilterMode {
    return this.config.mode;
  }
}

/**
 * Create a website detector from WebsiteRule configuration
 */
export function createWebsiteDetector(rule: WebsiteRule, logger?: Logger): WebsiteDetectorImpl {
  const config: WebsiteDetectorConfig = {
    enabled: rule.enabled,
    mode: rule.mode,
    severity: rule.severity,
    action: rule.action,
    blocklist: rule.blocklist,
    allowlist: rule.allowlist,
  };
  
  return new WebsiteDetectorImpl(config, logger);
}

/**
 * Create a website detector with default configuration
 */
export function createDefaultWebsiteDetector(): WebsiteDetectorImpl {
  return new WebsiteDetectorImpl({
    enabled: true,
    mode: 'blocklist',
    severity: 'high',
    action: 'block',
    blocklist: [],
    allowlist: [],
  });
}

// Default export
export default WebsiteDetectorImpl;
