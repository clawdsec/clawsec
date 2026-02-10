/**
 * Token Detector
 * Detects tokens including JWTs, Bearer tokens, and session tokens
 */

import type {
  SecretsDetectionResult,
  SecretSubDetector,
  TokenMatch,
} from './types.js';
import type { Severity } from '../../config/index.js';
import { redactValue } from './api-key-detector.js';

/**
 * JWT pattern - three base64url-encoded parts separated by dots
 * Header starts with eyJ (base64 for '{"')
 */
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\b/g;

/**
 * Bearer token pattern in Authorization header
 */
const BEARER_PATTERN = /\b(?:Bearer|bearer|BEARER)\s+([A-Za-z0-9_.-]+)\b/g;

/**
 * Session token patterns
 */
const SESSION_PATTERNS = [
  /\bsession_[A-Za-z0-9_-]{20,}\b/g,
  /\bsess_[A-Za-z0-9_-]{20,}\b/g,
  /\bsid[_-][A-Za-z0-9_-]{20,}\b/gi,
];

/**
 * Refresh token patterns
 */
const REFRESH_PATTERNS = [
  /\brefresh_[A-Za-z0-9_-]{20,}\b/g,
  /\brt_[A-Za-z0-9_-]{20,}\b/g,
];

/**
 * Access token patterns (generic)
 */
const ACCESS_TOKEN_PATTERNS = [
  /\baccess_token[_=:]["']?([A-Za-z0-9_.-]{20,})["']?/gi,
  /\btoken[_=:]["']?([A-Za-z0-9_.-]{32,})["']?/gi,
];

/**
 * Validate JWT structure
 * Returns true if the token appears to be a valid JWT
 */
export function isValidJwtStructure(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 3) return false;

  // Each part should be base64url encoded
  const base64UrlRegex = /^[A-Za-z0-9_-]+$/;
  if (!parts.every(part => base64UrlRegex.test(part))) return false;

  // Try to decode and parse the header
  try {
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    // JWT headers typically have 'alg' and optionally 'typ'
    if (!header.alg) return false;
    
    // Try to decode the payload (should be valid JSON)
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    // Payload should be an object
    if (typeof payload !== 'object' || payload === null) return false;
    
    return true;
  } catch {
    // If we can't parse it, it's likely not a valid JWT
    return false;
  }
}

/**
 * Match JWTs in text
 */
export function matchJwt(text: string): TokenMatch[] {
  const matches: TokenMatch[] = [];
  const regex = new RegExp(JWT_PATTERN.source, JWT_PATTERN.flags);
  let match;

  while ((match = regex.exec(text)) !== null) {
    const value = match[0];
    const isValid = isValidJwtStructure(value);
    
    matches.push({
      matched: true,
      tokenType: 'jwt',
      value,
      redactedValue: redactValue(value, 10, 6),
      confidence: isValid ? 0.95 : 0.70,
    });
  }

  return matches;
}

/**
 * Match Bearer tokens in text
 */
export function matchBearerToken(text: string): TokenMatch[] {
  const matches: TokenMatch[] = [];
  const regex = new RegExp(BEARER_PATTERN.source, BEARER_PATTERN.flags);
  let match;

  while ((match = regex.exec(text)) !== null) {
    const value = match[1] || match[0];
    
    // Skip if it looks like a JWT (will be caught by JWT detector)
    if (value.startsWith('eyJ')) continue;
    
    matches.push({
      matched: true,
      tokenType: 'bearer',
      value,
      redactedValue: redactValue(value),
      confidence: 0.85,
    });
  }

  return matches;
}

/**
 * Match session tokens in text
 */
export function matchSessionToken(text: string): TokenMatch[] {
  const matches: TokenMatch[] = [];
  const seen = new Set<string>();

  for (const pattern of SESSION_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[0];
      if (seen.has(value)) continue;
      seen.add(value);

      matches.push({
        matched: true,
        tokenType: 'session',
        value,
        redactedValue: redactValue(value),
        confidence: 0.85,
      });
    }
  }

  return matches;
}

/**
 * Match refresh tokens in text
 */
export function matchRefreshToken(text: string): TokenMatch[] {
  const matches: TokenMatch[] = [];
  const seen = new Set<string>();

  for (const pattern of REFRESH_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[0];
      if (seen.has(value)) continue;
      seen.add(value);

      matches.push({
        matched: true,
        tokenType: 'refresh',
        value,
        redactedValue: redactValue(value),
        confidence: 0.85,
      });
    }
  }

  return matches;
}

/**
 * Match generic access tokens in text
 */
export function matchAccessToken(text: string): TokenMatch[] {
  const matches: TokenMatch[] = [];
  const seen = new Set<string>();

  for (const pattern of ACCESS_TOKEN_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[1] || match[0];
      if (seen.has(value)) continue;
      seen.add(value);

      // Skip if it looks like a JWT
      if (value.startsWith('eyJ')) continue;

      matches.push({
        matched: true,
        tokenType: 'bearer', // Treat generic access tokens as bearer-like
        value,
        redactedValue: redactValue(value),
        confidence: 0.70,
      });
    }
  }

  return matches;
}

/**
 * Match all token types in text
 */
export function matchTokens(text: string): TokenMatch[] {
  const allMatches: TokenMatch[] = [];
  
  allMatches.push(...matchJwt(text));
  allMatches.push(...matchBearerToken(text));
  allMatches.push(...matchSessionToken(text));
  allMatches.push(...matchRefreshToken(text));
  allMatches.push(...matchAccessToken(text));

  return allMatches;
}

/**
 * Token Detector class
 */
export class TokenDetector implements SecretSubDetector {
  private severity: Severity;

  constructor(severity: Severity, _logger?: any) {
    this.severity = severity;
  }

  /**
   * Scan text for tokens
   */
  scan(text: string, location: string): SecretsDetectionResult[] {
    const matches = matchTokens(text);
    
    return matches.map((match) => ({
      detected: true,
      category: 'secrets' as const,
      severity: this.severity,
      confidence: match.confidence,
      reason: `Detected ${match.tokenType.toUpperCase()} token`,
      metadata: {
        type: 'token' as const,
        subtype: match.tokenType,
        redactedValue: match.redactedValue,
        location,
      },
    }));
  }
}

/**
 * Create a token detector
 */
export function createTokenDetector(severity: Severity, logger?: any): TokenDetector {
  return new TokenDetector(severity, logger);
}
