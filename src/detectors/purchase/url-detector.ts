/**
 * URL Pattern Detector
 * Detects purchase-related URL paths and API endpoints
 */

import type { UrlMatchResult, DetectionContext, DetectionResult, SubDetector } from './types.js';
import type { Severity } from '../../config/index.js';

/**
 * Checkout and payment paths
 */
const CHECKOUT_PATHS = [
  '/checkout',
  '/checkout/',
  '/checkout/*',
  '/payment',
  '/payment/',
  '/payments',
  '/payments/',
  '/pay',
  '/pay/',
  '/cart/checkout',
  '/cart/confirm',
  '/cart/payment',
  '/secure/checkout',
  '/secure/payment',
  '/gp/buy',
  '/gp/checkout',
];

/**
 * Purchase and order paths
 */
const PURCHASE_PATHS = [
  '/buy',
  '/buy/',
  '/buy/*',
  '/purchase',
  '/purchase/',
  '/order',
  '/order/',
  '/orders',
  '/orders/',
  '/orders/create',
  '/orders/submit',
  '/confirm-order',
  '/place-order',
  '/complete-purchase',
];

/**
 * Subscription and billing paths
 */
const SUBSCRIPTION_PATHS = [
  '/subscribe',
  '/subscribe/',
  '/subscription',
  '/subscription/',
  '/subscriptions',
  '/billing',
  '/billing/',
  '/billing/payment',
  '/billing/subscribe',
  '/upgrade',
  '/upgrade/',
  '/premium',
  '/pro',
];

/**
 * API endpoints for orders and payments
 */
const API_ENDPOINTS = [
  '/api/orders',
  '/api/order',
  '/api/checkout',
  '/api/payment',
  '/api/payments',
  '/api/purchase',
  '/api/subscribe',
  '/api/subscription',
  '/api/billing',
  '/api/charge',
  '/api/transaction',
  '/api/transactions',
  '/api/v1/orders',
  '/api/v1/checkout',
  '/api/v1/payment',
  '/api/v1/payments',
  '/api/v2/orders',
  '/api/v2/checkout',
  '/api/v2/payment',
  '/api/v2/payments',
  '/graphql', // Often used for mutations
];

/**
 * URL path keywords (for partial matching)
 */
const URL_KEYWORDS = [
  'checkout',
  'payment',
  'purchase',
  'billing',
  'subscribe',
  'order',
  'transaction',
  'charge',
];

/**
 * Convert glob pattern to regex for URL matching
 */
function pathPatternToRegex(pattern: string): RegExp {
  // Normalize pattern - remove trailing slash for matching
  const normalizedPattern = pattern.endsWith('/') && pattern.length > 1
    ? pattern.slice(0, -1)
    : pattern;
  
  // Escape special regex characters except *
  const regex = normalizedPattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  
  // Match the pattern at the start of the path (or exact match)
  return new RegExp(`^${regex}(?:/.*)?$`, 'i');
}

/**
 * Extract path from URL
 */
export function extractPath(url: string): string | null {
  // If input is already a path (starts with /), return it directly
  if (url.startsWith('/')) {
    // Extract just the path without query string
    const pathMatch = url.match(/^(\/[^?#]*)/);
    return pathMatch ? pathMatch[1].toLowerCase() : url.toLowerCase();
  }
  
  try {
    let normalizedUrl = url;
    if (!url.includes('://')) {
      normalizedUrl = 'https://' + url;
    }
    const parsed = new URL(normalizedUrl);
    return parsed.pathname.toLowerCase();
  } catch {
    // If URL parsing fails, try to extract path directly
    const pathMatch = url.match(/^(?:https?:\/\/[^/]+)?(\/.*)$/i);
    if (pathMatch) {
      return pathMatch[1].toLowerCase();
    }
    return null;
  }
}

/**
 * Check if path matches a pattern
 */
function matchesPathPattern(path: string, pattern: string): boolean {
  const regex = pathPatternToRegex(pattern);
  return regex.test(path);
}

/**
 * Check URL path against known payment paths
 */
export function matchUrlPath(url: string): UrlMatchResult {
  const path = extractPath(url);
  if (!path) {
    return { matched: false, confidence: 0 };
  }

  // Normalize path for matching (remove trailing slash for comparison)
  const normalizedPath = path.endsWith('/') && path.length > 1 
    ? path.slice(0, -1) 
    : path;

  // Check checkout paths (highest priority)
  for (const pattern of CHECKOUT_PATHS) {
    if (matchesPathPattern(normalizedPath, pattern)) {
      return {
        matched: true,
        url: url,
        pattern: pattern,
        matchType: 'path',
        confidence: 0.9,
      };
    }
  }

  // Check purchase paths
  for (const pattern of PURCHASE_PATHS) {
    if (matchesPathPattern(normalizedPath, pattern)) {
      return {
        matched: true,
        url: url,
        pattern: pattern,
        matchType: 'path',
        confidence: 0.85,
      };
    }
  }

  // Check subscription paths
  for (const pattern of SUBSCRIPTION_PATHS) {
    if (matchesPathPattern(normalizedPath, pattern)) {
      return {
        matched: true,
        url: url,
        pattern: pattern,
        matchType: 'path',
        confidence: 0.85,
      };
    }
  }

  // Check API endpoints
  for (const pattern of API_ENDPOINTS) {
    if (matchesPathPattern(normalizedPath, pattern)) {
      return {
        matched: true,
        url: url,
        pattern: pattern,
        matchType: 'api',
        confidence: 0.8,
      };
    }
  }

  // Check for keywords in path (lower confidence)
  for (const keyword of URL_KEYWORDS) {
    if (normalizedPath.includes(keyword)) {
      return {
        matched: true,
        url: url,
        pattern: keyword,
        matchType: 'path',
        confidence: 0.6,
      };
    }
  }

  return { matched: false, confidence: 0 };
}

/**
 * URL pattern detector class
 */
export class UrlDetector implements SubDetector {
  private severity: Severity;

  constructor(severity: Severity = "critical", _logger?: any) {
    this.severity = severity;
  }

  /**
   * Extract URL from tool context
   */
  private extractUrl(context: DetectionContext): string | null {
    // Direct URL in context
    if (context.url) {
      return context.url;
    }
    
    // Check common tool input patterns
    const input = context.toolInput;
    
    if (typeof input.url === 'string') {
      return input.url;
    }
    
    if (typeof input.href === 'string') {
      return input.href;
    }
    
    if (typeof input.link === 'string') {
      return input.link;
    }
    
    if (typeof input.target === 'string' && input.target.includes('/')) {
      return input.target;
    }

    // Check for path-only inputs
    if (typeof input.path === 'string') {
      return input.path;
    }

    return null;
  }

  detect(context: DetectionContext): DetectionResult | null {
    const url = this.extractUrl(context);
    if (!url) {
      return null;
    }

    const result = matchUrlPath(url);
    
    if (!result.matched) {
      return null;
    }

    const matchTypeDescription = result.matchType === 'api' 
      ? 'API endpoint for payments/orders'
      : 'checkout/payment URL path';

    return {
      detected: true,
      category: 'purchase',
      severity: this.severity,
      confidence: result.confidence,
      reason: `Detected ${matchTypeDescription}: ${result.pattern}`,
      metadata: {
        url: result.url,
        matchedPattern: result.pattern,
      },
    };
  }
}

/**
 * Create a URL detector with the given configuration
 */
export function createUrlDetector(severity: Severity = "critical", logger?: any): UrlDetector {
  return new UrlDetector(severity, logger);
}
