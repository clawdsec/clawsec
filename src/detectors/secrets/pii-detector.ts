/**
 * PII Detector
 * Detects Personally Identifiable Information including SSNs and credit cards
 */

import type {
  SecretsDetectionResult,
  SecretSubDetector,
  PiiMatch,
  PiiType,
} from './types.js';
import type { Severity } from '../../config/index.js';

/**
 * Luhn algorithm for credit card validation
 * @param cardNumber The card number as a string (digits only)
 * @returns true if the card number passes Luhn validation
 */
export function luhnCheck(cardNumber: string): boolean {
  // Remove any non-digit characters
  const digits = cardNumber.replace(/\D/g, '');
  
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }

  let sum = 0;
  let isEven = false;

  // Process digits from right to left
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits[i], 10);

    if (isEven) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    isEven = !isEven;
  }

  return sum % 10 === 0;
}

/**
 * SSN pattern: xxx-xx-xxxx
 * Valid SSN rules:
 * - Area number (first 3 digits): 001-899, excluding 666
 * - Group number (middle 2 digits): 01-99
 * - Serial number (last 4 digits): 0001-9999
 */
const SSN_PATTERN = /\b(\d{3})-(\d{2})-(\d{4})\b/g;

/**
 * Credit card patterns (various formats)
 * Matches 13-19 digits with optional separators
 */
const CREDIT_CARD_PATTERNS = [
  // 16 digits with spaces or dashes (4-4-4-4)
  /\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b/g,
  // 15 digits (Amex: 4-6-5)
  /\b(\d{4}[\s-]?\d{6}[\s-]?\d{5})\b/g,
  // 13-19 continuous digits
  /\b(\d{13,19})\b/g,
];

/**
 * Email pattern
 */
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

/**
 * Validate SSN
 * Basic validation to reduce false positives
 */
export function isValidSsn(area: string, group: string, serial: string): boolean {
  const areaNum = parseInt(area, 10);
  const groupNum = parseInt(group, 10);
  const serialNum = parseInt(serial, 10);

  // Area number cannot be 000, 666, or 900-999
  if (areaNum === 0 || areaNum === 666 || areaNum >= 900) {
    return false;
  }

  // Group number cannot be 00
  if (groupNum === 0) {
    return false;
  }

  // Serial number cannot be 0000
  if (serialNum === 0) {
    return false;
  }

  return true;
}

/**
 * Redact PII value
 */
export function redactPii(value: string, type: PiiType): string {
  switch (type) {
    case 'ssn':
      // Show only last 4 digits
      return `***-**-${value.slice(-4)}`;
    case 'credit-card': {
      // Show first 4 and last 4 digits
      const digits = value.replace(/\D/g, '');
      if (digits.length <= 8) {
        return digits.slice(0, 4) + '***';
      }
      return digits.slice(0, 4) + '***' + digits.slice(-4);
    }
    case 'email': {
      // Redact middle of email
      const atIndex = value.indexOf('@');
      if (atIndex <= 2) {
        return '***' + value.slice(atIndex);
      }
      return value.slice(0, 2) + '***' + value.slice(atIndex);
    }
    default:
      return '***';
  }
}

/**
 * Match SSNs in text
 */
export function matchSsn(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const regex = new RegExp(SSN_PATTERN.source, SSN_PATTERN.flags);
  let match;

  while ((match = regex.exec(text)) !== null) {
    const fullMatch = match[0];
    const area = match[1];
    const group = match[2];
    const serial = match[3];

    const isValid = isValidSsn(area, group, serial);

    matches.push({
      matched: true,
      piiType: 'ssn',
      value: fullMatch,
      redactedValue: redactPii(fullMatch, 'ssn'),
      confidence: isValid ? 0.90 : 0.60,
    });
  }

  return matches;
}

/**
 * Match credit card numbers in text
 */
export function matchCreditCard(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  for (const pattern of CREDIT_CARD_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match;

    while ((match = regex.exec(text)) !== null) {
      const value = match[1] || match[0];
      const digits = value.replace(/\D/g, '');

      // Skip if we've already seen these digits
      if (seen.has(digits)) continue;
      
      // Skip numbers that are too short or too long
      if (digits.length < 13 || digits.length > 19) continue;
      
      // Skip numbers that are all the same digit (like 0000000000000000)
      if (/^(\d)\1+$/.test(digits)) continue;

      // Skip sequential numbers
      if (isSequential(digits)) continue;

      seen.add(digits);

      const luhnValid = luhnCheck(digits);

      // Only report if Luhn passes or if it looks very card-like
      if (!luhnValid) {
        // Skip low-confidence matches without Luhn validation
        continue;
      }

      matches.push({
        matched: true,
        piiType: 'credit-card',
        value: digits,
        redactedValue: redactPii(digits, 'credit-card'),
        confidence: 0.95, // High confidence since Luhn passed
        luhnValid,
      });
    }
  }

  return matches;
}

/**
 * Check if a number sequence is sequential (123456789...)
 */
function isSequential(digits: string): boolean {
  let ascending = true;
  let descending = true;

  for (let i = 1; i < digits.length; i++) {
    const curr = parseInt(digits[i], 10);
    const prev = parseInt(digits[i - 1], 10);
    
    if (curr !== (prev + 1) % 10) ascending = false;
    if (curr !== (prev - 1 + 10) % 10) descending = false;
  }

  return ascending || descending;
}

/**
 * Match email addresses in text
 */
export function matchEmail(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const regex = new RegExp(EMAIL_PATTERN.source, EMAIL_PATTERN.flags);
  const seen = new Set<string>();
  let match;

  while ((match = regex.exec(text)) !== null) {
    const value = match[0].toLowerCase();
    
    if (seen.has(value)) continue;
    seen.add(value);

    // Skip common test/example emails
    if (isExampleEmail(value)) continue;

    matches.push({
      matched: true,
      piiType: 'email',
      value,
      redactedValue: redactPii(value, 'email'),
      confidence: 0.70, // Lower confidence for emails
    });
  }

  return matches;
}

/**
 * Check if an email is a common test/example email
 */
function isExampleEmail(email: string): boolean {
  const exampleDomains = [
    'example.com',
    'example.org',
    'example.net',
    'test.com',
    'localhost',
    'placeholder.com',
  ];
  
  const exampleLocalParts = ['test', 'example', 'admin', 'info', 'noreply'];
  
  const [localPart, domain] = email.split('@');
  
  if (exampleDomains.some(d => domain.endsWith(d))) return true;
  if (exampleLocalParts.includes(localPart)) return true;
  
  return false;
}

/**
 * Match all PII types in text
 */
export function matchPii(text: string, includeEmail = false): PiiMatch[] {
  const allMatches: PiiMatch[] = [];
  
  allMatches.push(...matchSsn(text));
  allMatches.push(...matchCreditCard(text));
  
  if (includeEmail) {
    allMatches.push(...matchEmail(text));
  }

  return allMatches;
}

/**
 * PII Detector class
 */
export class PiiDetector implements SecretSubDetector {
  private severity: Severity;
  private includeEmail: boolean;

  constructor(severity: Severity, includeEmail = false, _logger?: any) {
    this.severity = severity;
    this.includeEmail = includeEmail;
  }

  /**
   * Scan text for PII
   */
  scan(text: string, location: string): SecretsDetectionResult[] {
    const matches = matchPii(text, this.includeEmail);
    
    return matches.map((match) => {
      // SSN and credit cards are higher severity
      const severity: Severity = 
        match.piiType === 'email' ? 'medium' : this.severity;

      return {
        detected: true,
        category: 'secrets' as const,
        severity,
        confidence: match.confidence,
        reason: `Detected ${match.piiType === 'credit-card' ? 'credit card number' : match.piiType.toUpperCase()}${match.luhnValid !== undefined ? ' (Luhn validated)' : ''}`,
        metadata: {
          type: 'pii' as const,
          subtype: match.piiType,
          redactedValue: match.redactedValue,
          location,
        },
      };
    });
  }
}

/**
 * Create a PII detector
 */
export function createPiiDetector(severity: Severity, includeEmail = false, logger?: any): PiiDetector {
  return new PiiDetector(severity, includeEmail, logger);
}
