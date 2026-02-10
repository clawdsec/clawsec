/**
 * Secrets Detector
 * Main detector that combines API key, token, credential, and PII detection
 */

import type {
  SecretsDetectionContext,
  SecretsDetectionResult,
  SecretsDetector as ISecretsDetector,
  SecretsDetectorConfig,
} from './types.js';
import { createLogger, type Logger } from '../../utils/logger.js';
import { ApiKeyDetector, createApiKeyDetector } from './api-key-detector.js';
import { TokenDetector, createTokenDetector } from './token-detector.js';
import { PiiDetector, createPiiDetector } from './pii-detector.js';
import type { SecretsRule, Severity } from '../../config/index.js';

// Re-export types
export * from './types.js';

// Re-export sub-detectors
export { ApiKeyDetector, createApiKeyDetector, matchApiKeys, redactValue } from './api-key-detector.js';
export {
  TokenDetector,
  createTokenDetector,
  matchTokens,
  matchJwt,
  matchBearerToken,
  matchSessionToken,
  matchRefreshToken,
  matchAccessToken,
  isValidJwtStructure,
} from './token-detector.js';
export {
  PiiDetector,
  createPiiDetector,
  matchPii,
  matchSsn,
  matchCreditCard,
  matchEmail,
  luhnCheck,
  isValidSsn,
  redactPii,
} from './pii-detector.js';

/**
 * Credential patterns for password/secret detection
 */
const CREDENTIAL_PATTERNS = [
  // password=, passwd=, pwd=
  {
    pattern: /\b(?:password|passwd|pwd)\s*[=:]\s*["']?([^\s"']{4,})["']?/gi,
    type: 'password',
  },
  // secret=, api_key=, apikey=
  {
    pattern: /\b(?:secret|api_key|apikey|api-key)\s*[=:]\s*["']?([^\s"']{8,})["']?/gi,
    type: 'secret',
  },
  // auth_token=, auth-token=
  {
    pattern: /\b(?:auth_token|auth-token|authtoken)\s*[=:]\s*["']?([^\s"']{8,})["']?/gi,
    type: 'auth_token',
  },
  // database connection strings with password
  {
    pattern: /(?:mysql|postgres|postgresql|mongodb|redis):\/\/[^:]+:([^@]+)@/gi,
    type: 'connection_string',
  },
];

/**
 * No detection result (used when disabled or no match)
 */
function noDetection(severity: Severity): SecretsDetectionResult {
  return {
    detected: false,
    category: 'secrets',
    severity,
    confidence: 0,
    reason: 'No secrets detected',
  };
}

/**
 * Combine multiple detection results, taking the highest severity/confidence
 */
function combineResults(
  results: SecretsDetectionResult[],
  severity: Severity
): SecretsDetectionResult {
  const detections = results.filter((r) => r.detected);

  if (detections.length === 0) {
    return noDetection(severity);
  }

  // Sort by confidence (highest first)
  detections.sort((a, b) => b.confidence - a.confidence);

  // Take the highest confidence result as primary
  const primary = detections[0];

  // Build combined reason if multiple detections
  let reason = primary.reason;
  if (detections.length > 1) {
    reason = `${primary.reason} (+${detections.length - 1} more)`;
  }

  return {
    detected: true,
    category: 'secrets',
    severity,
    confidence: primary.confidence,
    reason,
    metadata: primary.metadata,
  };
}

/**
 * Extract text content from tool input/output for scanning
 */
function extractTextContent(obj: Record<string, unknown> | undefined): Map<string, string> {
  const content = new Map<string, string>();

  // Guard against undefined/null input
  if (!obj || typeof obj !== 'object') {
    return content;
  }

  const textFields = [
    'command', 'script', 'code', 'content', 'body', 'text',
    'message', 'response', 'output', 'result', 'data',
    'query', 'sql', 'value', 'payload', 'json',
    'stdout', 'stderr', 'log', 'logs',
    'env', 'environment', 'config', 'configuration',
    'headers', 'header', 'authorization',
  ];

  function processValue(key: string, value: unknown): void {
    if (typeof value === 'string' && value.length > 0) {
      content.set(key, value);
    } else if (typeof value === 'object' && value !== null) {
      if (Array.isArray(value)) {
        value.forEach((item, idx) => {
          processValue(`${key}[${idx}]`, item);
        });
      } else {
        Object.entries(value as Record<string, unknown>).forEach(([k, v]) => {
          processValue(`${key}.${k}`, v);
        });
      }
    }
  }

  // Process known text fields first
  for (const field of textFields) {
    if (field in obj) {
      processValue(field, obj[field]);
    }
  }

  // Process all remaining fields
  for (const [key, value] of Object.entries(obj)) {
    if (!textFields.includes(key)) {
      processValue(key, value);
    }
  }

  return content;
}

/**
 * Scan for credential patterns
 */
function scanCredentials(
  text: string,
  location: string,
  severity: Severity
): SecretsDetectionResult[] {
  const results: SecretsDetectionResult[] = [];

  for (const credPattern of CREDENTIAL_PATTERNS) {
    const regex = new RegExp(credPattern.pattern.source, credPattern.pattern.flags);
    let match;

    while ((match = regex.exec(text)) !== null) {
      const value = match[1] || match[0];
      
      // Skip short or placeholder values
      if (value.length < 4) continue;
      if (/^[*x]+$/i.test(value)) continue; // Skip masked values
      if (/^<.+>$/.test(value)) continue; // Skip placeholders like <password>
      if (/^{.+}$/.test(value)) continue; // Skip template vars like {password}
      if (/^\$\{.+\}$/.test(value)) continue; // Skip env vars like ${PASSWORD}

      const redactedValue = value.length <= 8 
        ? value.slice(0, 2) + '***'
        : value.slice(0, 4) + '***' + value.slice(-2);

      results.push({
        detected: true,
        category: 'secrets',
        severity,
        confidence: 0.80,
        reason: `Detected ${credPattern.type} credential`,
        metadata: {
          type: 'credential',
          subtype: credPattern.type,
          redactedValue,
          location,
        },
      });
    }
  }

  return results;
}

/**
 * Main secrets detector implementation
 */
export class SecretsDetectorImpl implements ISecretsDetector {
  private config: SecretsDetectorConfig;
  private apiKeyDetector: ApiKeyDetector;
  private tokenDetector: TokenDetector;
  private piiDetector: PiiDetector;
  private logger: Logger;

  constructor(config: SecretsDetectorConfig, logger?: Logger) {
    this.config = config;
    this.logger = logger ?? createLogger(null, null);
    this.apiKeyDetector = createApiKeyDetector(config.severity, config.patterns, this.logger);
    this.tokenDetector = createTokenDetector(config.severity, this.logger);
    this.piiDetector = createPiiDetector(config.severity, false, this.logger); // Don't include email by default
  }

  async detect(context: SecretsDetectionContext): Promise<SecretsDetectionResult> {
    this.logger.debug(`[SecretsDetector] Starting detection: tool=${context.toolName}`);

    // Check if detector is enabled
    if (!this.config.enabled) {
      this.logger.debug(`[SecretsDetector] Detector disabled`);
      return noDetection(this.config.severity);
    }

    const allResults: SecretsDetectionResult[] = [];

    // Extract text content from tool input
    const inputContent = extractTextContent(context.toolInput);
    this.logger.debug(`[SecretsDetector] Scanning ${inputContent.size} text fields in tool input`);

    for (const [location, text] of inputContent) {
      this.logger.debug(`[SecretsDetector] Running API key detector on ${location}`);
      const apiKeyResults = this.apiKeyDetector.scan(text, `input.${location}`);
      if (apiKeyResults.length > 0) {
        this.logger.info(`[SecretsDetector] API key detection: count=${apiKeyResults.length}, location=${location}`);
      }
      allResults.push(...apiKeyResults);

      this.logger.debug(`[SecretsDetector] Running token detector on ${location}`);
      const tokenResults = this.tokenDetector.scan(text, `input.${location}`);
      if (tokenResults.length > 0) {
        this.logger.info(`[SecretsDetector] Token detection: count=${tokenResults.length}, location=${location}`);
      }
      allResults.push(...tokenResults);

      this.logger.debug(`[SecretsDetector] Running PII detector on ${location}`);
      const piiResults = this.piiDetector.scan(text, `input.${location}`);
      if (piiResults.length > 0) {
        this.logger.info(`[SecretsDetector] PII detection: count=${piiResults.length}, location=${location}`);
      }
      allResults.push(...piiResults);

      this.logger.debug(`[SecretsDetector] Running credential scanner on ${location}`);
      const credResults = scanCredentials(text, `input.${location}`, this.config.severity);
      if (credResults.length > 0) {
        this.logger.info(`[SecretsDetector] Credential detection: count=${credResults.length}, location=${location}`);
      }
      allResults.push(...credResults);
    }

    // Also scan tool output if provided
    if (context.toolOutput) {
      this.logger.debug(`[SecretsDetector] Scanning tool output`);
      allResults.push(...this.apiKeyDetector.scan(context.toolOutput, 'output'));
      allResults.push(...this.tokenDetector.scan(context.toolOutput, 'output'));
      allResults.push(...this.piiDetector.scan(context.toolOutput, 'output'));
      allResults.push(...scanCredentials(context.toolOutput, 'output', this.config.severity));
    }

    const detections = allResults.filter((r) => r.detected);
    if (detections.length === 0) {
      this.logger.debug(`[SecretsDetector] No secrets detected`);
    } else {
      this.logger.debug(`[SecretsDetector] Combining ${detections.length} secret detections`);
    }

    // Combine and return results
    const combined = combineResults(allResults, this.config.severity);
    this.logger.debug(`[SecretsDetector] Detection complete: detected=${combined.detected}, confidence=${combined.confidence}`);
    
    return combined;
  }

  /**
   * Get all individual detection results (for detailed reporting)
   */
  async detectAll(context: SecretsDetectionContext): Promise<SecretsDetectionResult[]> {
    if (!this.config.enabled) {
      return [];
    }

    const allResults: SecretsDetectionResult[] = [];

    // Extract text content from tool input
    const inputContent = extractTextContent(context.toolInput);
    for (const [location, text] of inputContent) {
      allResults.push(...this.apiKeyDetector.scan(text, `input.${location}`));
      allResults.push(...this.tokenDetector.scan(text, `input.${location}`));
      allResults.push(...this.piiDetector.scan(text, `input.${location}`));
      allResults.push(...scanCredentials(text, `input.${location}`, this.config.severity));
    }

    // Also scan tool output if provided
    if (context.toolOutput) {
      allResults.push(...this.apiKeyDetector.scan(context.toolOutput, 'output'));
      allResults.push(...this.tokenDetector.scan(context.toolOutput, 'output'));
      allResults.push(...this.piiDetector.scan(context.toolOutput, 'output'));
      allResults.push(...scanCredentials(context.toolOutput, 'output', this.config.severity));
    }

    return allResults.filter((r) => r.detected);
  }

  /**
   * Get the configured action for detected secrets
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
}

/**
 * Create a secrets detector from SecretsRule configuration
 */
export function createSecretsDetector(rule: SecretsRule, logger?: Logger): SecretsDetectorImpl {
  const config: SecretsDetectorConfig = {
    enabled: rule.enabled,
    severity: rule.severity,
    action: rule.action,
    patterns: rule.patterns,
  };

  return new SecretsDetectorImpl(config, logger);
}

/**
 * Create a secrets detector with default configuration
 */
export function createDefaultSecretsDetector(): SecretsDetectorImpl {
  return new SecretsDetectorImpl({
    enabled: true,
    severity: 'critical',
    action: 'block',
  });
}

// Default export
export default SecretsDetectorImpl;
