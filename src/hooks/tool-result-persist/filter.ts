/**
 * Output Filtering Logic for Tool Result Persist Hook
 *
 * Scans tool outputs for secrets/PII and redacts sensitive data
 * before it's persisted.
 */

import type { SecretsDetectionResult } from '../../detectors/secrets/types.js';

/**
 * Represents a single redaction made to the output
 */
export interface Redaction {
  /** Type of secret that was redacted (e.g., 'openai-api-key', 'ssn', 'jwt') */
  type: string;
  /** Human-readable description of what was redacted */
  description: string;
}

/**
 * Result of filtering an output
 */
export interface FilterResult {
  /** The filtered output with secrets redacted */
  filteredOutput: unknown;
  /** List of redactions made */
  redactions: Redaction[];
  /** Whether any redactions were made */
  wasRedacted: boolean;
}

/**
 * Pattern for matching secrets in text
 * Maps pattern type to regex and replacement format
 */
interface SecretPattern {
  /** Regular expression to match the secret */
  pattern: RegExp;
  /** Type identifier for the redaction (used in [REDACTED:type]) */
  type: string;
  /** Human-readable description */
  description: string;
}

/**
 * Common secret patterns for direct text scanning
 * These are simplified patterns - the main detection is done by the secrets detector
 */
const SECRET_PATTERNS: SecretPattern[] = [
  // OpenAI API keys
  {
    pattern: /sk-[a-zA-Z0-9]{20,}/g,
    type: 'openai-api-key',
    description: 'OpenAI API key',
  },
  // Anthropic API keys
  {
    pattern: /sk-ant-[a-zA-Z0-9-]{20,}/g,
    type: 'anthropic-api-key',
    description: 'Anthropic API key',
  },
  // AWS Access Key ID
  {
    pattern: /AKIA[0-9A-Z]{16}/g,
    type: 'aws-access-key',
    description: 'AWS access key ID',
  },
  // AWS Secret Access Key (context-based)
  {
    pattern: /(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    type: 'aws-secret-key',
    description: 'AWS secret access key',
  },
  // GitHub tokens
  {
    pattern: /gh[pous]_[a-zA-Z0-9]{36,}/g,
    type: 'github-token',
    description: 'GitHub token',
  },
  // GitHub classic tokens
  {
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    type: 'github-pat',
    description: 'GitHub personal access token',
  },
  // Stripe API keys
  {
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    type: 'stripe-api-key',
    description: 'Stripe live API key',
  },
  {
    pattern: /sk_test_[a-zA-Z0-9]{24,}/g,
    type: 'stripe-test-key',
    description: 'Stripe test API key',
  },
  // Slack tokens
  {
    pattern: /xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}/g,
    type: 'slack-token',
    description: 'Slack token',
  },
  // Google API keys
  {
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    type: 'google-api-key',
    description: 'Google API key',
  },
  // JWT tokens
  {
    pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    type: 'jwt',
    description: 'JWT token',
  },
  // Bearer tokens
  {
    pattern: /Bearer\s+[a-zA-Z0-9_-]{20,}/gi,
    type: 'bearer-token',
    description: 'Bearer token',
  },
  // SSN (Social Security Number)
  {
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    type: 'ssn',
    description: 'Social Security Number',
  },
  // Credit card numbers (basic patterns)
  {
    pattern: /\b4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b/g,
    type: 'credit-card',
    description: 'Credit card number (Visa)',
  },
  {
    pattern: /\b5[1-5][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b/g,
    type: 'credit-card',
    description: 'Credit card number (Mastercard)',
  },
  {
    pattern: /\b3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}\b/g,
    type: 'credit-card',
    description: 'Credit card number (Amex)',
  },
  // Private keys
  {
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    type: 'private-key',
    description: 'Private key',
  },
  // Generic API key patterns
  {
    pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?/gi,
    type: 'generic-api-key',
    description: 'Generic API key',
  },
  // Generic secret/password patterns
  {
    pattern: /(?:password|passwd|pwd|secret)\s*[:=]\s*['"]?([^\s'"]{8,})['"]?/gi,
    type: 'password',
    description: 'Password or secret',
  },
];

/**
 * Redact a single string value using pattern matching
 *
 * @param text - The text to scan and redact
 * @returns FilterResult with redacted text and list of redactions
 */
export function redactString(text: string): FilterResult {
  const redactions: Redaction[] = [];
  let filteredText = text;

  // Track which redactions we've already recorded to avoid duplicates
  const recordedTypes = new Set<string>();

  for (const secretPattern of SECRET_PATTERNS) {
    // Reset the pattern's lastIndex in case it was used before
    secretPattern.pattern.lastIndex = 0;

    // Check if pattern matches
    const matches = filteredText.match(secretPattern.pattern);
    if (matches && matches.length > 0) {
      // Replace all matches
      filteredText = filteredText.replace(
        secretPattern.pattern,
        `[REDACTED:${secretPattern.type}]`
      );

      // Record the redaction (only once per type)
      if (!recordedTypes.has(secretPattern.type)) {
        redactions.push({
          type: secretPattern.type,
          description: secretPattern.description,
        });
        recordedTypes.add(secretPattern.type);
      }
    }
  }

  return {
    filteredOutput: filteredText,
    redactions,
    wasRedacted: redactions.length > 0,
  };
}

/**
 * Recursively filter an object, redacting secrets in string values
 *
 * @param obj - The object to filter
 * @returns FilterResult with filtered object and aggregated redactions
 */
export function redactObject(obj: Record<string, unknown>): FilterResult {
  const redactions: Redaction[] = [];
  const recordedTypes = new Set<string>();
  const filtered: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    const result = filterValue(value);
    filtered[key] = result.filteredOutput;

    // Aggregate redactions (avoiding duplicates)
    for (const redaction of result.redactions) {
      if (!recordedTypes.has(redaction.type)) {
        redactions.push(redaction);
        recordedTypes.add(redaction.type);
      }
    }
  }

  return {
    filteredOutput: filtered,
    redactions,
    wasRedacted: redactions.length > 0,
  };
}

/**
 * Recursively filter an array, redacting secrets in string values
 *
 * @param arr - The array to filter
 * @returns FilterResult with filtered array and aggregated redactions
 */
export function redactArray(arr: unknown[]): FilterResult {
  const redactions: Redaction[] = [];
  const recordedTypes = new Set<string>();
  const filtered: unknown[] = [];

  for (const item of arr) {
    const result = filterValue(item);
    filtered.push(result.filteredOutput);

    // Aggregate redactions (avoiding duplicates)
    for (const redaction of result.redactions) {
      if (!recordedTypes.has(redaction.type)) {
        redactions.push(redaction);
        recordedTypes.add(redaction.type);
      }
    }
  }

  return {
    filteredOutput: filtered,
    redactions,
    wasRedacted: redactions.length > 0,
  };
}

/**
 * Filter any value, dispatching to the appropriate handler based on type
 *
 * @param value - The value to filter (can be any type)
 * @returns FilterResult with filtered value and redactions
 */
export function filterValue(value: unknown): FilterResult {
  // Handle null/undefined
  if (value === null || value === undefined) {
    return {
      filteredOutput: value,
      redactions: [],
      wasRedacted: false,
    };
  }

  // Handle strings
  if (typeof value === 'string') {
    return redactString(value);
  }

  // Handle arrays
  if (Array.isArray(value)) {
    return redactArray(value);
  }

  // Handle objects
  if (typeof value === 'object') {
    return redactObject(value as Record<string, unknown>);
  }

  // Pass through primitives (numbers, booleans, etc.)
  return {
    filteredOutput: value,
    redactions: [],
    wasRedacted: false,
  };
}

/**
 * Convert secrets detection results to redactions
 *
 * @param detections - Array of detection results from the secrets detector
 * @returns Array of redactions based on the detections
 */
export function detectionsToRedactions(
  detections: SecretsDetectionResult[]
): Redaction[] {
  const redactions: Redaction[] = [];
  const recordedTypes = new Set<string>();

  for (const detection of detections) {
    if (!detection.detected || !detection.metadata) {
      continue;
    }

    // Build type string from metadata
    let type: string = detection.metadata.type;
    if (detection.metadata.provider) {
      type = `${detection.metadata.provider}-${type}`;
    } else if (detection.metadata.subtype) {
      type = detection.metadata.subtype;
    }

    // Avoid duplicate redaction entries
    if (!recordedTypes.has(type)) {
      redactions.push({
        type,
        description: detection.reason,
      });
      recordedTypes.add(type);
    }
  }

  return redactions;
}

/**
 * Main filter function that combines pattern-based filtering
 * with detection-based redaction info
 *
 * @param output - The tool output to filter
 * @param detections - Optional array of detection results for more accurate redaction types
 * @returns FilterResult with filtered output and redactions
 */
export function filterOutput(
  output: unknown,
  detections?: SecretsDetectionResult[]
): FilterResult {
  // Filter the output using pattern matching
  const filterResult = filterValue(output);

  // If we have detections, enhance redaction list with more specific types
  if (detections && detections.length > 0) {
    const detectionRedactions = detectionsToRedactions(detections);

    // Merge detection-based redactions with pattern-based redactions
    // Detection-based are more authoritative
    const recordedTypes = new Set(filterResult.redactions.map((r) => r.type));
    for (const redaction of detectionRedactions) {
      if (!recordedTypes.has(redaction.type)) {
        filterResult.redactions.push(redaction);
        recordedTypes.add(redaction.type);
      }
    }
  }

  return filterResult;
}
