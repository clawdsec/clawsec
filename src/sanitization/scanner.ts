/**
 * Main scanner implementation for prompt injection detection
 */

import type { InjectionMatch, ScanResult, ScannerConfig } from './types.js';
import { getEnabledPatterns, PATTERNS_BY_CATEGORY } from './patterns.js';

/**
 * Default scanner configuration
 */
export const DEFAULT_SCANNER_CONFIG: ScannerConfig = {
  enabled: true,
  categories: {
    instructionOverride: true,
    systemLeak: true,
    jailbreak: true,
    encodedPayload: true,
  },
  minConfidence: 0.5,
  redactMatches: false,
};

/**
 * Redaction placeholder
 */
const REDACTED = '[REDACTED]';

/**
 * Maximum recursion depth for encoded payload scanning
 */
const MAX_DECODE_DEPTH = 3;

/**
 * Check if a string is valid base64
 * @param str - String to check
 * @returns Whether the string is valid base64
 */
function isValidBase64(str: string): boolean {
  if (str.length < 20) return false;
  if (str.length % 4 !== 0 && !str.endsWith('=')) return false;
  try {
    const decoded = atob(str);
    // Check if decoded content is printable
    return /^[\x20-\x7E\s]+$/.test(decoded);
  } catch {
    return false;
  }
}

/**
 * Decode base64 string safely
 * @param str - Base64 string to decode
 * @returns Decoded string or null if invalid
 */
function decodeBase64(str: string): string | null {
  try {
    // Normalize padding
    let normalized = str;
    while (normalized.length % 4 !== 0) {
      normalized += '=';
    }
    const decoded = atob(normalized);
    // Only return if it's printable text
    if (/^[\x20-\x7E\s]+$/.test(decoded)) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Decode hex escape sequences
 * @param str - String containing hex escapes
 * @returns Decoded string or null if invalid
 */
function decodeHexEscapes(str: string): string | null {
  try {
    const decoded = str.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
    if (/^[\x20-\x7E\s]+$/.test(decoded)) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Decode unicode escape sequences
 * @param str - String containing unicode escapes
 * @returns Decoded string or null if invalid
 */
function decodeUnicodeEscapes(str: string): string | null {
  try {
    const decoded = str.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
    if (/^[\x20-\x7E\s]+$/.test(decoded)) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Decode URL encoded sequences
 * @param str - URL encoded string
 * @returns Decoded string or null if invalid
 */
function decodeUrlEncoding(str: string): string | null {
  try {
    const decoded = decodeURIComponent(str);
    if (/^[\x20-\x7E\s]+$/.test(decoded)) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Extract and decode base64 content from a string
 * @param content - Content to search for base64
 * @returns Array of decoded base64 strings
 */
function extractBase64Content(content: string): string[] {
  const results: string[] = [];
  // Match base64 strings (at least 20 chars)
  const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
  let match;
  while ((match = base64Pattern.exec(content)) !== null) {
    const decoded = decodeBase64(match[0]);
    if (decoded) {
      results.push(decoded);
    }
  }
  return results;
}

/**
 * Scan content for injection patterns
 * @param content - Content to scan
 * @param config - Scanner configuration
 * @returns Scan result
 */
export function scan(
  content: string,
  config?: Partial<ScannerConfig>
): ScanResult {
  const mergedConfig: ScannerConfig = {
    ...DEFAULT_SCANNER_CONFIG,
    ...config,
    categories: {
      ...DEFAULT_SCANNER_CONFIG.categories,
      ...config?.categories,
    },
  };

  // Return early if disabled
  if (!mergedConfig.enabled) {
    return {
      hasInjection: false,
      matches: [],
      highestConfidence: 0,
    };
  }

  const matches: InjectionMatch[] = [];

  // Get enabled patterns
  const enabledPatterns = getEnabledPatterns(mergedConfig.categories);

  // Scan main content
  for (const [category, patternDef] of enabledPatterns) {
    const regex = new RegExp(patternDef.pattern.source, 'gi');
    let match;
    while ((match = regex.exec(content)) !== null) {
      if (patternDef.confidence >= mergedConfig.minConfidence) {
        matches.push({
          category,
          pattern: patternDef.pattern.source,
          match: match[0],
          position: {
            start: match.index,
            end: match.index + match[0].length,
          },
          confidence: patternDef.confidence,
        });
      }
    }
  }

  // Recursively scan decoded content if encoded payload detection is enabled
  if (mergedConfig.categories.encodedPayload) {
    scanEncodedContent(content, matches, mergedConfig, 0);
  }

  // Sort matches by position
  matches.sort((a, b) => a.position.start - b.position.start);

  // Remove duplicates (same position)
  const uniqueMatches = matches.filter(
    (match, index, arr) =>
      index === 0 ||
      match.position.start !== arr[index - 1].position.start ||
      match.position.end !== arr[index - 1].position.end
  );

  const highestConfidence =
    uniqueMatches.length > 0
      ? Math.max(...uniqueMatches.map((m) => m.confidence))
      : 0;

  const result: ScanResult = {
    hasInjection: uniqueMatches.length > 0,
    matches: uniqueMatches,
    highestConfidence,
  };

  // Add sanitized output if redaction is enabled
  if (mergedConfig.redactMatches && uniqueMatches.length > 0) {
    result.sanitizedOutput = sanitize(content, uniqueMatches);
  }

  return result;
}

/**
 * Scan encoded content recursively
 * @param content - Content to scan
 * @param matches - Accumulated matches
 * @param config - Scanner configuration
 * @param depth - Current recursion depth
 */
function scanEncodedContent(
  content: string,
  matches: InjectionMatch[],
  config: ScannerConfig,
  depth: number
): void {
  if (depth >= MAX_DECODE_DEPTH) return;

  // Extract and decode base64 content
  const base64Contents = extractBase64Content(content);
  for (const decoded of base64Contents) {
    // Scan decoded content for all patterns (not just encoded)
    const allPatterns = [
      ...PATTERNS_BY_CATEGORY['instruction-override'],
      ...PATTERNS_BY_CATEGORY['system-leak'],
      ...PATTERNS_BY_CATEGORY.jailbreak,
    ];

    for (const patternDef of allPatterns) {
      const regex = new RegExp(patternDef.pattern.source, 'gi');
      let match;
      while ((match = regex.exec(decoded)) !== null) {
        // Boost confidence for nested encoded content
        const boostedConfidence = Math.min(
          patternDef.confidence + 0.1 * (depth + 1),
          1.0
        );
        if (boostedConfidence >= config.minConfidence) {
          matches.push({
            category: 'encoded-payload',
            pattern: `encoded(${patternDef.pattern.source})`,
            match: `[decoded] ${match[0]}`,
            position: { start: -1, end: -1 }, // Position unknown for decoded content
            confidence: boostedConfidence,
          });
        }
      }
    }

    // Recurse for nested encodings
    scanEncodedContent(decoded, matches, config, depth + 1);
  }

  // Try decoding hex escapes
  const hexPattern = /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2})+/g;
  let hexMatch;
  while ((hexMatch = hexPattern.exec(content)) !== null) {
    const decoded = decodeHexEscapes(hexMatch[0]);
    if (decoded) {
      scanDecodedForInjections(decoded, matches, config, depth);
    }
  }

  // Try decoding unicode escapes
  const unicodePattern = /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4})+/g;
  let unicodeMatch;
  while ((unicodeMatch = unicodePattern.exec(content)) !== null) {
    const decoded = decodeUnicodeEscapes(unicodeMatch[0]);
    if (decoded) {
      scanDecodedForInjections(decoded, matches, config, depth);
    }
  }

  // Try URL decoding
  const urlPattern = /%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2})+/g;
  let urlMatch;
  while ((urlMatch = urlPattern.exec(content)) !== null) {
    const decoded = decodeUrlEncoding(urlMatch[0]);
    if (decoded) {
      scanDecodedForInjections(decoded, matches, config, depth);
    }
  }
}

/**
 * Scan decoded content for injection patterns
 * @param decoded - Decoded content
 * @param matches - Accumulated matches
 * @param config - Scanner configuration
 * @param depth - Current recursion depth
 */
function scanDecodedForInjections(
  decoded: string,
  matches: InjectionMatch[],
  config: ScannerConfig,
  depth: number
): void {
  const allPatterns = [
    ...PATTERNS_BY_CATEGORY['instruction-override'],
    ...PATTERNS_BY_CATEGORY['system-leak'],
    ...PATTERNS_BY_CATEGORY.jailbreak,
  ];

  for (const patternDef of allPatterns) {
    const regex = new RegExp(patternDef.pattern.source, 'gi');
    let match;
    while ((match = regex.exec(decoded)) !== null) {
      const boostedConfidence = Math.min(
        patternDef.confidence + 0.1 * (depth + 1),
        1.0
      );
      if (boostedConfidence >= config.minConfidence) {
        matches.push({
          category: 'encoded-payload',
          pattern: `encoded(${patternDef.pattern.source})`,
          match: `[decoded] ${match[0]}`,
          position: { start: -1, end: -1 },
          confidence: boostedConfidence,
        });
      }
    }
  }

  // Recurse if depth allows
  if (depth < MAX_DECODE_DEPTH) {
    scanEncodedContent(decoded, matches, config, depth + 1);
  }
}

/**
 * Sanitize content by redacting matched injections
 * @param content - Original content
 * @param matches - Detected injection matches
 * @returns Sanitized content with redactions
 */
export function sanitize(content: string, matches: InjectionMatch[]): string {
  if (matches.length === 0) return content;

  // Filter to matches with valid positions
  const validMatches = matches.filter(
    (m) => m.position.start >= 0 && m.position.end > m.position.start
  );

  if (validMatches.length === 0) return content;

  // Sort by position descending to replace from end to start
  const sortedMatches = [...validMatches].sort(
    (a, b) => b.position.start - a.position.start
  );

  let result = content;
  for (const match of sortedMatches) {
    const before = result.slice(0, match.position.start);
    const after = result.slice(match.position.end);
    result = before + REDACTED + after;
  }

  return result;
}

/**
 * Create a scanner instance with preset configuration
 * @param config - Scanner configuration
 * @returns Scanner function
 */
export function createScanner(
  config?: Partial<ScannerConfig>
): (content: string) => ScanResult {
  const mergedConfig: ScannerConfig = {
    ...DEFAULT_SCANNER_CONFIG,
    ...config,
    categories: {
      ...DEFAULT_SCANNER_CONFIG.categories,
      ...config?.categories,
    },
  };

  return (content: string) => scan(content, mergedConfig);
}
