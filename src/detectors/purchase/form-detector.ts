/**
 * Form Field Detector
 * Detects payment-related form fields and inputs
 */

import type { FormFieldMatchResult, DetectionContext, DetectionResult, SubDetector } from './types.js';
import type { Severity } from '../../config/index.js';

/**
 * Credit card field patterns (field names, IDs, or labels)
 */
const CREDIT_CARD_PATTERNS = [
  // Card number
  'card-number',
  'cardnumber',
  'card_number',
  'cardNumber',
  'credit-card',
  'creditcard',
  'credit_card',
  'creditCard',
  'cc-number',
  'ccnumber',
  'cc_number',
  'ccNumber',
  'pan', // Primary Account Number
  'account-number',
  'accountnumber',
  
  // CVV/CVC
  'cvv',
  'cvc',
  'cvv2',
  'cvc2',
  'security-code',
  'securitycode',
  'security_code',
  'securityCode',
  'card-security',
  'card-code',
  'verification-code',
  'verificationcode',
  'csv', // Card Security Value
  
  // Expiry
  'expiry',
  'expiration',
  'exp-date',
  'expdate',
  'exp_date',
  'expDate',
  'exp-month',
  'expmonth',
  'exp_month',
  'expMonth',
  'exp-year',
  'expyear',
  'exp_year',
  'expYear',
  'card-expiry',
  'cardexpiry',
  'mm-yy',
  'mmyy',
  'mm/yy',
  
  // Card holder
  'cardholder',
  'card-holder',
  'card_holder',
  'cardHolder',
  'name-on-card',
  'nameoncard',
  'name_on_card',
  'nameOnCard',
];

/**
 * Billing address field patterns
 */
const BILLING_PATTERNS = [
  'billing-address',
  'billingaddress',
  'billing_address',
  'billingAddress',
  'billing-street',
  'billing-city',
  'billing-state',
  'billing-zip',
  'billing-postal',
  'billing-country',
  'payment-address',
  'paymentaddress',
  'payment_address',
];

/**
 * Payment method field patterns
 */
const PAYMENT_METHOD_PATTERNS = [
  'payment-method',
  'paymentmethod',
  'payment_method',
  'paymentMethod',
  'payment-type',
  'paymenttype',
  'payment_type',
  'paymentType',
  'pay-with',
  'paywith',
  'pay_with',
  'card-type',
  'cardtype',
  'card_type',
];

/**
 * Bank account patterns
 */
const BANK_ACCOUNT_PATTERNS = [
  'routing-number',
  'routingnumber',
  'routing_number',
  'routingNumber',
  'bank-account',
  'bankaccount',
  'bank_account',
  'bankAccount',
  'account-number',
  'iban',
  'swift',
  'bic',
  'aba',
];

/**
 * Amount/Price patterns
 */
const AMOUNT_PATTERNS = [
  'amount',
  'price',
  'total',
  'subtotal',
  'payment-amount',
  'paymentamount',
  'payment_amount',
  'charge-amount',
  'transaction-amount',
];

/**
 * All payment-related patterns combined
 */
const ALL_PAYMENT_PATTERNS = [
  ...CREDIT_CARD_PATTERNS,
  ...BILLING_PATTERNS,
  ...PAYMENT_METHOD_PATTERNS,
  ...BANK_ACCOUNT_PATTERNS,
  ...AMOUNT_PATTERNS,
];

/**
 * High-confidence patterns (definitely payment related)
 */
const HIGH_CONFIDENCE_PATTERNS = [
  ...CREDIT_CARD_PATTERNS,
  ...BANK_ACCOUNT_PATTERNS,
];

/**
 * Check if a field name/id matches payment patterns
 */
function matchesPattern(field: string, patterns: string[]): string | null {
  const fieldLower = field.toLowerCase().replace(/[-_\s]/g, '');

  for (const pattern of patterns) {
    const patternLower = pattern.toLowerCase().replace(/[-_\s]/g, '');
    // Only check if field contains pattern (one direction)
    // This allows "billing_address" to match "address"
    // But prevents "action" from matching "transaction-amount"
    if (fieldLower.includes(patternLower)) {
      return pattern;
    }
  }

  return null;
}

/**
 * Extract field names from tool input
 */
function extractFieldNames(input: Record<string, unknown>): string[] {
  const fields: string[] = [];
  
  // Direct field names in input
  for (const key of Object.keys(input)) {
    fields.push(key);
  }
  
  // Check for fields array (common in form-filling tools)
  if (Array.isArray(input.fields)) {
    for (const field of input.fields) {
      if (typeof field === 'string') {
        fields.push(field);
      } else if (typeof field === 'object' && field !== null) {
        const fieldObj = field as Record<string, unknown>;
        if (typeof fieldObj.name === 'string') {
          fields.push(fieldObj.name);
        }
        if (typeof fieldObj.id === 'string') {
          fields.push(fieldObj.id);
        }
        if (typeof fieldObj.label === 'string') {
          fields.push(fieldObj.label);
        }
        if (typeof fieldObj.ref === 'string') {
          fields.push(fieldObj.ref);
        }
      }
    }
  }
  
  // Check for selector patterns (Playwright/Puppeteer style)
  if (typeof input.selector === 'string') {
    fields.push(input.selector);
  }
  if (typeof input.ref === 'string') {
    fields.push(input.ref);
  }
  if (typeof input.element === 'string') {
    fields.push(input.element);
  }
  
  // Check nested objects
  for (const value of Object.values(input)) {
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      const nested = value as Record<string, unknown>;
      for (const key of Object.keys(nested)) {
        fields.push(key);
      }
    }
  }
  
  return fields;
}

/**
 * Match form fields against payment patterns
 */
export function matchFormFields(fields: string[]): FormFieldMatchResult {
  const matchedFields: string[] = [];
  const matchedPatterns: string[] = [];
  let highConfidenceMatch = false;
  
  for (const field of fields) {
    // Check high-confidence patterns first
    const highMatch = matchesPattern(field, HIGH_CONFIDENCE_PATTERNS);
    if (highMatch) {
      matchedFields.push(field);
      matchedPatterns.push(highMatch);
      highConfidenceMatch = true;
      continue;
    }
    
    // Check all patterns
    const match = matchesPattern(field, ALL_PAYMENT_PATTERNS);
    if (match) {
      matchedFields.push(field);
      matchedPatterns.push(match);
    }
  }
  
  if (matchedFields.length === 0) {
    return { matched: false, confidence: 0 };
  }
  
  // Calculate confidence based on matches
  let confidence: number;
  if (highConfidenceMatch) {
    // High confidence for credit card/bank fields
    confidence = 0.9;
  } else if (matchedFields.length >= 3) {
    // Multiple billing/payment fields
    confidence = 0.85;
  } else if (matchedFields.length >= 2) {
    confidence = 0.75;
  } else {
    // Single match, lower confidence
    confidence = 0.6;
  }
  
  return {
    matched: true,
    fields: matchedFields,
    patterns: matchedPatterns,
    confidence,
  };
}

/**
 * Check if text content contains payment-related values
 */
export function containsPaymentValues(text: string): boolean {
  // Credit card number pattern (13-19 digits, possibly with spaces/dashes)
  const cardNumberRegex = /\b(?:\d{4}[-\s]?){3,4}\d{1,4}\b/;
  if (cardNumberRegex.test(text)) {
    return true;
  }
  
  // CVV pattern (3-4 digits)
  const cvvRegex = /\bcvv[:\s]*\d{3,4}\b/i;
  if (cvvRegex.test(text)) {
    return true;
  }
  
  // Expiry date pattern (MM/YY or MM/YYYY)
  const expiryRegex = /\b(?:0[1-9]|1[0-2])[-/]\d{2,4}\b/;
  if (expiryRegex.test(text)) {
    return true;
  }
  
  return false;
}

/**
 * Form field detector class
 */
export class FormDetector implements SubDetector {
  private severity: Severity;

  constructor(severity: Severity = "critical", _logger?: any) {
    this.severity = severity;
  }

  detect(context: DetectionContext): DetectionResult | null {
    const fields = extractFieldNames(context.toolInput);
    
    if (fields.length === 0) {
      return null;
    }

    const result = matchFormFields(fields);
    
    if (!result.matched) {
      // Also check for payment values in string inputs
      for (const value of Object.values(context.toolInput)) {
        if (typeof value === 'string' && containsPaymentValues(value)) {
          return {
            detected: true,
            category: 'purchase',
            severity: this.severity,
            confidence: 0.8,
            reason: 'Detected payment-related data (credit card number, CVV, or expiry)',
            metadata: {
              formFields: ['[embedded payment data]'],
            },
          };
        }
      }
      return null;
    }

    const fieldList = result.fields?.join(', ') || '';
    
    return {
      detected: true,
      category: 'purchase',
      severity: this.severity,
      confidence: result.confidence,
      reason: `Detected payment form fields: ${fieldList}`,
      metadata: {
        formFields: result.fields,
        matchedPattern: result.patterns?.join(', '),
      },
    };
  }
}

/**
 * Create a form detector with the given configuration
 */
export function createFormDetector(severity: Severity = "critical", logger?: any): FormDetector {
  return new FormDetector(severity, logger);
}
