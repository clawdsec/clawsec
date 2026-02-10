/**
 * Domain Detector
 * Detects purchase-related domains using exact matching, glob patterns, and keyword analysis
 */

import type { DomainMatchResult, DetectionContext, DetectionResult, SubDetector } from './types.js';
import type { Severity } from '../../config/index.js';

/**
 * Known e-commerce and payment domains
 */
const KNOWN_PAYMENT_DOMAINS = [
  // E-commerce giants
  'amazon.com',
  'amazon.co.uk',
  'amazon.de',
  'amazon.fr',
  'amazon.es',
  'amazon.it',
  'amazon.ca',
  'amazon.com.au',
  'amazon.co.jp',
  'amazon.in',
  'ebay.com',
  'ebay.co.uk',
  'walmart.com',
  'target.com',
  'bestbuy.com',
  'etsy.com',
  'alibaba.com',
  'aliexpress.com',
  
  // Payment processors
  'stripe.com',
  'paypal.com',
  'paypal.me',
  'square.com',
  'squareup.com',
  'braintreepayments.com',
  'authorize.net',
  'adyen.com',
  'worldpay.com',
  'checkout.com',
  '2checkout.com',
  'paddle.com',
  'gumroad.com',
  'lemonsqueezy.com',
  
  // E-commerce platforms
  'shopify.com',
  'myshopify.com',
  'bigcommerce.com',
  'woocommerce.com',
  'magento.com',
  'squarespace.com',
  'wix.com',
  
  // Digital goods
  'apple.com',
  'play.google.com',
  'steampowered.com',
  'gog.com',
  'epicgames.com',
  
  // Subscriptions
  'patreon.com',
  'buymeacoffee.com',
  'ko-fi.com',
  
  // Financial services
  'venmo.com',
  'cashapp.com',
  'zelle.com',
];

/**
 * Domain patterns that support glob matching
 */
const DOMAIN_PATTERNS = [
  'amazon.*',           // All Amazon TLDs
  '*.amazon.com',       // Amazon subdomains
  'pay.*.com',          // Payment subdomains
  '*.paypal.com',
  '*.stripe.com',
  '*.shopify.com',
  '*.myshopify.com',
  'checkout.*',
  'payment.*',
  'pay.*',
  'store.*',
  'shop.*',
  'buy.*',
];

/**
 * Keywords that indicate payment/purchase domains
 */
const PAYMENT_KEYWORDS = [
  'payment',
  'checkout',
  'pay',
  'purchase',
  'buy',
  'order',
  'cart',
  'store',
  'shop',
  'ecommerce',
  'e-commerce',
  'billing',
  'invoice',
  'transaction',
  'wallet',
  'credit',
  'debit',
];

/**
 * Extract domain from URL
 */
export function extractDomain(url: string): string | null {
  try {
    // Handle URLs without protocol
    let normalizedUrl = url;
    if (!url.includes('://')) {
      normalizedUrl = 'https://' + url;
    }
    const parsed = new URL(normalizedUrl);
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Convert glob pattern to regex
 */
export function globToRegex(pattern: string): RegExp {
  // Escape special regex characters except * and ?
  const regex = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  
  return new RegExp(`^${regex}$`, 'i');
}

/**
 * Check if domain matches a glob pattern
 */
export function matchesGlobPattern(domain: string, pattern: string): boolean {
  const regex = globToRegex(pattern);
  return regex.test(domain);
}

/**
 * Check if domain contains payment-related keywords
 */
export function hasPaymentKeyword(domain: string): string | null {
  const domainLower = domain.toLowerCase();
  // Remove TLD for keyword matching
  const domainWithoutTld = domainLower.replace(/\.[a-z]{2,}$/, '');
  
  for (const keyword of PAYMENT_KEYWORDS) {
    if (domainWithoutTld.includes(keyword)) {
      return keyword;
    }
  }
  return null;
}

/**
 * Check domain against known payment domains
 */
export function matchDomain(domain: string, customBlocklist: string[] = []): DomainMatchResult {
  const domainLower = domain.toLowerCase();
  
  // Check exact matches first (highest confidence)
  if (KNOWN_PAYMENT_DOMAINS.includes(domainLower)) {
    return {
      matched: true,
      domain: domainLower,
      pattern: domainLower,
      matchType: 'exact',
      confidence: 0.95,
    };
  }
  
  // Check custom blocklist (exact matches)
  for (const blocked of customBlocklist) {
    if (blocked.includes('*') || blocked.includes('?')) {
      if (matchesGlobPattern(domainLower, blocked)) {
        return {
          matched: true,
          domain: domainLower,
          pattern: blocked,
          matchType: 'glob',
          confidence: 0.9,
        };
      }
    } else if (domainLower === blocked.toLowerCase()) {
      return {
        matched: true,
        domain: domainLower,
        pattern: blocked,
        matchType: 'exact',
        confidence: 0.95,
      };
    }
  }
  
  // Check glob patterns
  for (const pattern of DOMAIN_PATTERNS) {
    if (matchesGlobPattern(domainLower, pattern)) {
      return {
        matched: true,
        domain: domainLower,
        pattern: pattern,
        matchType: 'glob',
        confidence: 0.9,
      };
    }
  }
  
  // Check for payment keywords in domain (lower confidence)
  const keyword = hasPaymentKeyword(domainLower);
  if (keyword) {
    return {
      matched: true,
      domain: domainLower,
      pattern: keyword,
      matchType: 'keyword',
      confidence: 0.7,
    };
  }
  
  return {
    matched: false,
    confidence: 0,
  };
}

/**
 * Domain detector class
 */
export class DomainDetector implements SubDetector {
  private severity: Severity;
  private customBlocklist: string[];

  constructor(severity: Severity = "critical", customBlocklist: string[] = [], _logger?: any) {
    this.severity = severity;
    this.customBlocklist = customBlocklist;
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
    
    // Browser navigation tools
    if (typeof input.url === 'string') {
      return input.url;
    }
    
    // Some tools use href
    if (typeof input.href === 'string') {
      return input.href;
    }
    
    // Check for URLs in link/target fields
    if (typeof input.link === 'string') {
      return input.link;
    }
    
    if (typeof input.target === 'string' && input.target.includes('://')) {
      return input.target;
    }
    
    return null;
  }

  detect(context: DetectionContext): DetectionResult | null {
    const url = this.extractUrl(context);
    if (!url) {
      return null;
    }

    const domain = extractDomain(url);
    if (!domain) {
      return null;
    }

    const result = matchDomain(domain, this.customBlocklist);
    
    if (!result.matched) {
      return null;
    }

    const matchTypeDescription = {
      exact: 'known payment/e-commerce domain',
      glob: 'payment-related domain pattern',
      keyword: 'domain containing payment keyword',
    }[result.matchType || 'exact'];

    return {
      detected: true,
      category: 'purchase',
      severity: this.severity,
      confidence: result.confidence,
      reason: `Detected ${matchTypeDescription}: ${result.domain}`,
      metadata: {
        domain: result.domain,
        url: url,
        matchedPattern: result.pattern,
      },
    };
  }
}

/**
 * Create a domain detector with the given configuration
 */
export function createDomainDetector(
  severity: Severity = 'critical',
  customBlocklist: string[] = []
): DomainDetector {
  return new DomainDetector(severity, customBlocklist);
}
