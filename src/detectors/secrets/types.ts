/**
 * Secrets Detector Types
 * Type definitions for detecting secrets, tokens, and PII
 */

import type { Severity, Action } from '../../config/index.js';

/**
 * Detection context passed to detectors
 */
export interface SecretsDetectionContext {
  /** Name of the tool being invoked */
  toolName: string;
  /** Input parameters to the tool (may be undefined for certain tools) */
  toolInput: Record<string, unknown> | undefined;
  /** Output from the tool (if scanning output) */
  toolOutput?: string;
}

/**
 * Type of secret detected
 */
export type SecretType = 'api-key' | 'token' | 'credential' | 'pii';

/**
 * Provider of the detected API key
 */
export type ApiKeyProvider =
  | 'openai'
  | 'aws'
  | 'github'
  | 'stripe'
  | 'slack'
  | 'google'
  | 'anthropic'
  | 'generic'
  | 'custom';

/**
 * Type of token detected
 */
export type TokenType = 'jwt' | 'bearer' | 'session' | 'refresh';

/**
 * Type of PII detected
 */
export type PiiType = 'ssn' | 'credit-card' | 'email';

/**
 * Result of a secrets detection
 */
export interface SecretsDetectionResult {
  /** Whether a secret was detected */
  detected: boolean;
  /** Category of the detection */
  category: 'secrets';
  /** Severity level of the detection */
  severity: Severity;
  /** Confidence score from 0 to 1 */
  confidence: number;
  /** Human-readable reason for the detection */
  reason: string;
  /** Additional metadata about the detection */
  metadata?: {
    /** Type of secret detected */
    type: SecretType;
    /** Provider for API keys */
    provider?: string;
    /** Redacted value showing first/last few chars with *** */
    redactedValue?: string;
    /** Where the secret was found (input/output, field name) */
    location?: string;
    /** Specific subtype (jwt, ssn, etc.) */
    subtype?: string;
  };
}

/**
 * Configuration for the secrets detector
 */
export interface SecretsDetectorConfig {
  /** Whether the detector is enabled */
  enabled: boolean;
  /** Severity level to assign to detections */
  severity: Severity;
  /** Action to take when secret is detected */
  action: Action;
  /** Custom regex patterns for secrets detection */
  patterns?: string[];
}

/**
 * Interface for the main secrets detector
 */
export interface SecretsDetector {
  /**
   * Detect secrets in the given context
   * @param context Detection context with tool information
   * @returns Detection result (may contain multiple matches)
   */
  detect(context: SecretsDetectionContext): Promise<SecretsDetectionResult>;
}

/**
 * Interface for sub-detectors (api-key, token, pii)
 */
export interface SecretSubDetector {
  /**
   * Scan text for secrets
   * @param text Text to scan
   * @param location Description of where the text came from
   * @returns Array of detection results
   */
  scan(text: string, location: string): SecretsDetectionResult[];
}

/**
 * API key match result
 */
export interface ApiKeyMatch {
  /** Whether a match was found */
  matched: boolean;
  /** The provider of the API key */
  provider: ApiKeyProvider;
  /** The original matched value */
  value: string;
  /** Redacted value for safe display */
  redactedValue: string;
  /** Confidence score */
  confidence: number;
}

/**
 * Token match result
 */
export interface TokenMatch {
  /** Whether a match was found */
  matched: boolean;
  /** Type of token */
  tokenType: TokenType;
  /** The original matched value */
  value: string;
  /** Redacted value for safe display */
  redactedValue: string;
  /** Confidence score */
  confidence: number;
}

/**
 * PII match result
 */
export interface PiiMatch {
  /** Whether a match was found */
  matched: boolean;
  /** Type of PII */
  piiType: PiiType;
  /** The original matched value */
  value: string;
  /** Redacted value for safe display */
  redactedValue: string;
  /** Confidence score */
  confidence: number;
  /** Whether Luhn validation passed (for credit cards) */
  luhnValid?: boolean;
}

/**
 * Credential match result
 */
export interface CredentialMatch {
  /** Whether a match was found */
  matched: boolean;
  /** Type of credential pattern */
  credentialType: string;
  /** The matched value (usually key=value) */
  value: string;
  /** Redacted value */
  redactedValue: string;
  /** Confidence score */
  confidence: number;
}
