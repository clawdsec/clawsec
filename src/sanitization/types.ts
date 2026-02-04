/**
 * Type definitions for prompt injection scanner
 */

/**
 * Categories of prompt injection attacks
 */
export type InjectionCategory =
  | 'instruction-override'
  | 'system-leak'
  | 'jailbreak'
  | 'encoded-payload';

/**
 * Represents a matched injection pattern
 */
export interface InjectionMatch {
  /** Category of the detected injection */
  category: InjectionCategory;
  /** The pattern that matched */
  pattern: string;
  /** The actual matched content */
  match: string;
  /** Position of the match in the content */
  position: { start: number; end: number };
  /** Confidence score (0.0 - 1.0) */
  confidence: number;
}

/**
 * Result of scanning content for prompt injections
 */
export interface ScanResult {
  /** Whether any injection was detected */
  hasInjection: boolean;
  /** All detected injection matches */
  matches: InjectionMatch[];
  /** Highest confidence score among all matches */
  highestConfidence: number;
  /** Content with matches redacted (if redaction enabled) */
  sanitizedOutput?: string;
}

/**
 * Configuration for the scanner
 */
export interface ScannerConfig {
  /** Whether scanning is enabled */
  enabled: boolean;
  /** Which categories to scan for */
  categories: {
    instructionOverride: boolean;
    systemLeak: boolean;
    jailbreak: boolean;
    encodedPayload: boolean;
  };
  /** Minimum confidence threshold to report a match */
  minConfidence: number;
  /** Whether to redact matches in sanitizedOutput */
  redactMatches: boolean;
}
