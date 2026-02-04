/**
 * Output scanner for prompt injection detection
 *
 * @module sanitization
 */

// Type exports
export type {
  InjectionCategory,
  InjectionMatch,
  ScanResult,
  ScannerConfig,
} from './types.js';

// Pattern exports
export type { PatternDef } from './patterns.js';
export {
  INSTRUCTION_OVERRIDE_PATTERNS,
  SYSTEM_LEAK_PATTERNS,
  JAILBREAK_PATTERNS,
  ENCODED_PAYLOAD_PATTERNS,
  PATTERNS_BY_CATEGORY,
  getEnabledPatterns,
} from './patterns.js';

// Scanner exports
export {
  scan,
  sanitize,
  createScanner,
  DEFAULT_SCANNER_CONFIG,
} from './scanner.js';
