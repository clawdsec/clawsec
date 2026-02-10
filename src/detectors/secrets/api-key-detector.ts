/**
 * API Key Detector
 * Detects API keys from various providers
 */

import type {
  SecretsDetectionResult,
  SecretSubDetector,
  ApiKeyMatch,
  ApiKeyProvider,
} from './types.js';
import type { Severity } from '../../config/index.js';
import { createLogger, type Logger } from '../../utils/logger.js';

/**
 * API key pattern definitions
 */
interface ApiKeyPattern {
  provider: ApiKeyProvider;
  pattern: RegExp;
  minLength?: number;
  maxLength?: number;
  confidence: number;
  description: string;
}

/**
 * API key patterns for various providers
 */
const API_KEY_PATTERNS: ApiKeyPattern[] = [
  // OpenAI - sk-... format (51+ chars)
  {
    provider: 'openai',
    pattern: /\bsk-[A-Za-z0-9]{48,}\b/g,
    minLength: 51,
    confidence: 0.95,
    description: 'OpenAI API key',
  },
  // Anthropic - sk-ant-... format
  {
    provider: 'anthropic',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g,
    confidence: 0.95,
    description: 'Anthropic API key',
  },
  // AWS Access Key ID - AKIA... (20 chars)
  {
    provider: 'aws',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    minLength: 20,
    maxLength: 20,
    confidence: 0.95,
    description: 'AWS Access Key ID',
  },
  // AWS Secret Access Key (40 chars base64-like)
  {
    provider: 'aws',
    pattern: /\b[A-Za-z0-9/+=]{40}\b/g,
    minLength: 40,
    maxLength: 40,
    confidence: 0.5, // Lower confidence without context
    description: 'Potential AWS Secret Access Key',
  },
  // GitHub tokens - ghp_, gho_, ghs_, ghr_ prefixes
  {
    provider: 'github',
    pattern: /\bghp_[A-Za-z0-9]{36,}\b/g,
    confidence: 0.95,
    description: 'GitHub Personal Access Token',
  },
  {
    provider: 'github',
    pattern: /\bgho_[A-Za-z0-9]{36,}\b/g,
    confidence: 0.95,
    description: 'GitHub OAuth Token',
  },
  {
    provider: 'github',
    pattern: /\bghs_[A-Za-z0-9]{36,}\b/g,
    confidence: 0.95,
    description: 'GitHub App Installation Token',
  },
  {
    provider: 'github',
    pattern: /\bghr_[A-Za-z0-9]{36,}\b/g,
    confidence: 0.95,
    description: 'GitHub Refresh Token',
  },
  // Stripe keys - sk_live_, sk_test_, pk_live_, pk_test_
  {
    provider: 'stripe',
    pattern: /\bsk_live_[A-Za-z0-9]{24,}\b/g,
    confidence: 0.95,
    description: 'Stripe Live Secret Key',
  },
  {
    provider: 'stripe',
    pattern: /\bsk_test_[A-Za-z0-9]{24,}\b/g,
    confidence: 0.90,
    description: 'Stripe Test Secret Key',
  },
  {
    provider: 'stripe',
    pattern: /\bpk_live_[A-Za-z0-9]{24,}\b/g,
    confidence: 0.90,
    description: 'Stripe Live Publishable Key',
  },
  {
    provider: 'stripe',
    pattern: /\bpk_test_[A-Za-z0-9]{24,}\b/g,
    confidence: 0.85,
    description: 'Stripe Test Publishable Key',
  },
  // Slack tokens - xoxb-, xoxp-, xoxa-, xoxr-, xoxs-
  {
    provider: 'slack',
    pattern: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b/g,
    confidence: 0.95,
    description: 'Slack Bot Token',
  },
  {
    provider: 'slack',
    pattern: /\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}\b/g,
    confidence: 0.95,
    description: 'Slack User Token',
  },
  {
    provider: 'slack',
    pattern: /\bxoxa-[0-9]+-[A-Za-z0-9]{24,}\b/g,
    confidence: 0.95,
    description: 'Slack App Token',
  },
  {
    provider: 'slack',
    pattern: /\bxoxr-[0-9]+-[A-Za-z0-9]{24,}\b/g,
    confidence: 0.95,
    description: 'Slack Refresh Token',
  },
  {
    provider: 'slack',
    pattern: /\bxoxs-[0-9]+-[A-Za-z0-9]{24,}\b/g,
    confidence: 0.95,
    description: 'Slack Session Token',
  },
  // Google API key - AIza... (39 total chars)
  {
    provider: 'google',
    pattern: /\bAIza[A-Za-z0-9_-]{35,}\b/g,
    confidence: 0.90,
    description: 'Google API Key',
  },
  // Generic patterns (lower confidence)
  {
    provider: 'generic',
    pattern: /\bapi[_-]?key[_-]?[=:]["']?([A-Za-z0-9_-]{20,})["']?/gi,
    confidence: 0.70,
    description: 'Generic API Key pattern',
  },
];

/**
 * Cloud credential patterns (environment variables)
 */
const CLOUD_CREDENTIAL_PATTERNS: ApiKeyPattern[] = [
  {
    provider: 'aws',
    pattern: /AWS_SECRET_ACCESS_KEY\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/g,
    confidence: 0.95,
    description: 'AWS Secret Access Key in env var',
  },
  {
    provider: 'aws',
    pattern: /AWS_ACCESS_KEY_ID\s*[=:]\s*["']?(AKIA[0-9A-Z]{16})["']?/g,
    confidence: 0.95,
    description: 'AWS Access Key ID in env var',
  },
  {
    provider: 'google',
    pattern: /GOOGLE_APPLICATION_CREDENTIALS\s*[=:]\s*["']?([^"'\s]+)["']?/g,
    confidence: 0.85,
    description: 'Google Application Credentials path',
  },
];

/**
 * Private key patterns
 */
const PRIVATE_KEY_PATTERNS: ApiKeyPattern[] = [
  {
    provider: 'generic',
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
    confidence: 0.99,
    description: 'Private key (RSA)',
  },
  {
    provider: 'generic',
    pattern: /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----/g,
    confidence: 0.99,
    description: 'Private key (EC)',
  },
  {
    provider: 'generic',
    pattern: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/g,
    confidence: 0.99,
    description: 'Private key (OpenSSH)',
  },
  {
    provider: 'generic',
    pattern: /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/g,
    confidence: 0.99,
    description: 'Private key (PGP)',
  },
];

/**
 * Redact a value showing first and last few characters
 */
export function redactValue(value: string, showStart = 4, showEnd = 4): string {
  if (value.length <= showStart + showEnd + 3) {
    // Too short to redact meaningfully
    return value.slice(0, showStart) + '***';
  }
  return value.slice(0, showStart) + '***' + value.slice(-showEnd);
}

/**
 * Match API keys in text
 */
export function matchApiKeys(text: string): ApiKeyMatch[] {
  const matches: ApiKeyMatch[] = [];
  const seen = new Set<string>();

  // Check standard API key patterns
  for (const pattern of API_KEY_PATTERNS) {
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[1] || match[0];
      
      // Skip if we've already seen this value
      if (seen.has(value)) continue;
      seen.add(value);

      // Validate length if specified
      if (pattern.minLength && value.length < pattern.minLength) continue;
      if (pattern.maxLength && value.length > pattern.maxLength) continue;

      matches.push({
        matched: true,
        provider: pattern.provider,
        value,
        redactedValue: redactValue(value),
        confidence: pattern.confidence,
      });
    }
  }

  // Check cloud credential patterns
  for (const pattern of CLOUD_CREDENTIAL_PATTERNS) {
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[1] || match[0];
      
      if (seen.has(value)) continue;
      seen.add(value);

      matches.push({
        matched: true,
        provider: pattern.provider,
        value,
        redactedValue: redactValue(value),
        confidence: pattern.confidence,
      });
    }
  }

  // Check private key patterns
  for (const pattern of PRIVATE_KEY_PATTERNS) {
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
    if (regex.test(text)) {
      matches.push({
        matched: true,
        provider: pattern.provider,
        value: pattern.description,
        redactedValue: '[PRIVATE KEY]',
        confidence: pattern.confidence,
      });
    }
  }

  return matches;
}

/**
 * API Key Detector class
 */
export class ApiKeyDetector implements SecretSubDetector {
  private severity: Severity;
  private customPatterns: string[];
  private logger: Logger;

  constructor(severity: Severity, customPatterns?: string[], logger?: Logger) {
    this.severity = severity;
    this.customPatterns = customPatterns || [];
    this.logger = logger ?? createLogger(null, null);
  }

  scan(text: string, location: string): SecretsDetectionResult[] {
    const matches = matchApiKeys(text);

    // Add custom pattern matches
    if (this.customPatterns.length > 0) {
      this.logger.debug(`[ApiKeyDetector] Checking ${this.customPatterns.length} custom patterns`);

      for (const pattern of this.customPatterns) {
        try {
          const regex = new RegExp(pattern, 'gi');
          let match;
          while ((match = regex.exec(text)) !== null) {
            this.logger.info(`[ApiKeyDetector] Custom pattern matched: ${pattern}`);
            matches.push({
              matched: true,
              value: match[0],
              provider: 'custom',
              redactedValue: '[REDACTED:custom]',
              confidence: 0.85,
            });
          }
        } catch (error) {
          this.logger.warn(`[ApiKeyDetector] Invalid regex pattern skipped: "${pattern}" - ${error instanceof Error ? error.message : String(error)}`);
          continue;
        }
      }
    }
    
    return matches.map((match) => ({
      detected: true,
      category: 'secrets' as const,
      severity: this.severity,
      confidence: match.confidence,
      reason: `Detected ${match.provider} API key/credential`,
      metadata: {
        type: 'api-key' as const,
        provider: match.provider,
        redactedValue: match.redactedValue,
        location,
      },
    }));
  }
}

/**
 * Create an API key detector with custom patterns
 */
export function createApiKeyDetector(severity: Severity, customPatterns?: string[], logger?: Logger): ApiKeyDetector {
  return new ApiKeyDetector(severity, customPatterns, logger);
}
