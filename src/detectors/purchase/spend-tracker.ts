/**
 * Spend Tracker
 * Monitors per-transaction and daily spending limits for purchase protection
 */

import type { SpendLimits } from '../../config/index.js';
import { createLogger, type Logger } from '../../utils/logger.js';

/**
 * Record of a tracked spend transaction
 */
export interface SpendRecord {
  /** Amount of the transaction */
  amount: number;
  /** Unix timestamp when the transaction was recorded */
  timestamp: number;
  /** Unique identifier for the transaction */
  transactionId: string;
  /** Domain where the transaction occurred */
  domain?: string;
  /** Whether the transaction was approved */
  approved: boolean;
}

/**
 * Result of a spend limit check
 */
export interface SpendLimitResult {
  /** Whether the transaction is allowed */
  allowed: boolean;
  /** Which limit was exceeded, if any */
  exceededLimit?: 'perTransaction' | 'daily';
  /** Current total spent today */
  currentDailyTotal: number;
  /** Remaining amount allowed today */
  remainingDaily: number;
  /** Human-readable message */
  message?: string;
}

/**
 * Interface for the spend tracker
 */
export interface ISpendTracker {
  /** Record a transaction (after approval) */
  record(amount: number, metadata?: { transactionId?: string; domain?: string }): void;
  /** Check if a transaction would exceed limits */
  checkLimits(amount: number, limits: SpendLimits): SpendLimitResult;
  /** Get current daily total */
  getDailyTotal(): number;
  /** Get recent transactions */
  getTransactions(since?: number): SpendRecord[];
  /** Reset (for testing) */
  reset(): void;
}

/**
 * Amount patterns for detecting prices in text
 */
const AMOUNT_PATTERNS = [
  // Currency with dollar sign: $100, $100.00, $1,000.00
  /\$\s*([0-9]{1,3}(?:,?[0-9]{3})*(?:\.[0-9]{2})?)/,
  // Currency with other symbols: €100, £100, ¥1000 (handle large numbers for yen)
  /[€£¥]\s*([0-9]+(?:,?[0-9]{3})*(?:\.[0-9]{2})?)/,
  // Labeled amounts: amount=100, price=99.99, total=50
  /(?:amount|price|total|cost|value)\s*[=:]\s*([0-9]{1,3}(?:,?[0-9]{3})*(?:\.[0-9]{2})?)/i,
  // USD/EUR labeled: 100 USD, 99.99 EUR
  /([0-9]{1,3}(?:,?[0-9]{3})*(?:\.[0-9]{2})?)\s*(?:USD|EUR|GBP|CAD|AUD)/i,
  // Plain decimal numbers (lower confidence): 99.99
  /^([0-9]{1,6}\.[0-9]{2})$/,
];

/**
 * Extract amount from a string value
 * @param value String that may contain an amount
 * @returns Parsed amount or null if not found
 */
export function extractAmount(value: string): number | null {
  if (!value || typeof value !== 'string') {
    return null;
  }

  const cleanValue = value.trim();

  for (const pattern of AMOUNT_PATTERNS) {
    const match = cleanValue.match(pattern);
    if (match && match[1]) {
      // Remove commas and parse
      const numStr = match[1].replace(/,/g, '');
      const num = parseFloat(numStr);
      if (!isNaN(num) && num > 0) {
        return num;
      }
    }
  }

  // Try direct parse if it looks like a number
  if (/^[0-9]+(?:\.[0-9]+)?$/.test(cleanValue)) {
    const num = parseFloat(cleanValue);
    if (!isNaN(num) && num > 0) {
      return num;
    }
  }

  return null;
}

/**
 * Extract amount from tool input
 * Searches common field names for price/amount values
 * @param toolInput Tool input object
 * @param this.logger Optional this.logger instance
 * @returns Extracted amount or null
 */
export function extractAmountFromInput(
  toolInput: Record<string, unknown>,
  logger?: Logger
): number | null {
  const log = logger ?? createLogger(null, null);
  // Priority field names to check
  const amountFields = [
    'amount',
    'price',
    'total',
    'cost',
    'value',
    'payment_amount',
    'paymentAmount',
    'transaction_amount',
    'transactionAmount',
    'subtotal',
    'grand_total',
    'grandTotal',
  ];

  // Check priority fields first
  for (const field of amountFields) {
    const value = toolInput[field];
    if (value !== undefined && value !== null) {
      if (typeof value === 'number' && value > 0) {
        log.debug(`[SpendTracker] Extracted amount: ${value} from field="${field}"`);
        return value;
      }
      if (typeof value === 'string') {
        const parsed = extractAmount(value);
        if (parsed !== null) {
          log.debug(`[SpendTracker] Extracted amount: ${parsed} from field="${field}"`);
          return parsed;
        }
      }
    }
  }

  // Check URL query parameters
  const url = toolInput.url;
  if (typeof url === 'string') {
    try {
      const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
      for (const field of amountFields) {
        const param = urlObj.searchParams.get(field);
        if (param) {
          const parsed = extractAmount(param);
          if (parsed !== null) {
            log.debug(`[SpendTracker] Extracted amount: ${parsed} from URL param="${field}"`);
            return parsed;
          }
        }
      }
    } catch {
      // Invalid URL, ignore
    }
  }

  // Check nested form data
  const formData = toolInput.data || toolInput.body || toolInput.formData;
  if (formData && typeof formData === 'object') {
    const result = extractAmountFromInput(formData as Record<string, unknown>, log);
    if (result !== null) {
      log.debug(`[SpendTracker] Extracted amount: ${result} from nested form data`);
      return result;
    }
  }

  // Check fields array (Playwright form fields)
  const fields = toolInput.fields;
  if (Array.isArray(fields)) {
    for (const field of fields) {
      if (field && typeof field === 'object') {
        const name = (field as Record<string, unknown>).name;
        const value = (field as Record<string, unknown>).value;
        if (typeof name === 'string' && amountFields.includes(name.toLowerCase())) {
          if (typeof value === 'number' && value > 0) {
            log.debug(`[SpendTracker] Extracted amount: ${value} from fields array (name="${name}")`);
            return value;
          }
          if (typeof value === 'string') {
            const parsed = extractAmount(value);
            if (parsed !== null) {
              log.debug(
                `[SpendTracker] Extracted amount: ${parsed} from fields array (name="${name}")`
              );
              return parsed;
            }
          }
        }
      }
    }
  }

  // Scan all string values in the input for currency patterns (last resort)
  for (const [key, value] of Object.entries(toolInput)) {
    // Skip non-string values and known non-amount fields
    if (typeof value !== 'string') continue;
    if (['url', 'path', 'href', 'selector', 'ref', 'element'].includes(key)) continue;

    // Look for explicit currency patterns only
    const currencyMatch = value.match(/\$\s*([0-9]{1,3}(?:,?[0-9]{3})*(?:\.[0-9]{2})?)/);
    if (currencyMatch && currencyMatch[1]) {
      const parsed = extractAmount(value);
      if (parsed !== null) {
        log.debug(`[SpendTracker] Extracted amount: ${parsed} from currency pattern in key="${key}"`);
        return parsed;
      }
    }
  }

  return null;
}

/**
 * Generate a unique transaction ID
 */
function generateTransactionId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `txn_${timestamp}_${random}`;
}

/**
 * Get the start of today (midnight in local timezone)
 */
function getStartOfDay(timestamp: number = Date.now()): number {
  const date = new Date(timestamp);
  date.setHours(0, 0, 0, 0);
  return date.getTime();
}

/**
 * SpendTracker implementation
 * Tracks spending transactions and enforces limits
 */
export class SpendTracker implements ISpendTracker {
  private transactions: SpendRecord[] = [];
  private readonly cleanupIntervalMs: number;
  private lastCleanup: number = Date.now();
  private readonly logger: Logger;

  /**
   * Create a new SpendTracker
   * @param cleanupIntervalMs How often to run cleanup (default: 1 hour)
   * @param logger Optional logger instance
   */
  constructor(cleanupIntervalMs: number = 60 * 60 * 1000, logger?: Logger) {
    this.cleanupIntervalMs = cleanupIntervalMs;
    this.logger = logger ?? createLogger(null, null);
  }

  /**
   * Record a transaction
   * @param amount Transaction amount
   * @param metadata Optional metadata (transactionId, domain)
   */
  record(amount: number, metadata?: { transactionId?: string; domain?: string }): void {
    // Run cleanup if needed
    this.maybeCleanup();

    const record: SpendRecord = {
      amount,
      timestamp: Date.now(),
      transactionId: metadata?.transactionId || generateTransactionId(),
      domain: metadata?.domain,
      approved: true,
    };

    this.transactions.push(record);
  }

  /**
   * Check if a transaction would exceed limits
   * @param amount Transaction amount
   * @param limits Spend limits to check against
   * @returns Result indicating if allowed and any exceeded limits
   */
  checkLimits(amount: number, limits: SpendLimits): SpendLimitResult {
    // Run cleanup if needed
    this.maybeCleanup();

    const dailyTotal = this.getDailyTotal();
    const remainingDaily = Math.max(0, limits.daily - dailyTotal);

    this.logger.debug(
      `[SpendTracker] Checking limits: amount=${amount}, dailyTotal=${dailyTotal}, perTxLimit=${limits.perTransaction}, dailyLimit=${limits.daily}`
    );

    // Check per-transaction limit first
    if (amount > limits.perTransaction) {
      this.logger.warn(
        `[SpendTracker] Limit exceeded: amount=${amount}, limit=${limits.perTransaction}, type=perTransaction`
      );
      return {
        allowed: false,
        exceededLimit: 'perTransaction',
        currentDailyTotal: dailyTotal,
        remainingDaily,
        message: `Transaction amount $${amount.toFixed(2)} exceeds per-transaction limit of $${limits.perTransaction.toFixed(2)}`,
      };
    }

    // Check if adding this amount would exceed daily limit
    if (dailyTotal + amount > limits.daily) {
      this.logger.warn(
        `[SpendTracker] Limit exceeded: amount=${amount}, dailyTotal=${dailyTotal}, limit=${limits.daily}, type=daily`
      );
      return {
        allowed: false,
        exceededLimit: 'daily',
        currentDailyTotal: dailyTotal,
        remainingDaily,
        message: `Transaction amount $${amount.toFixed(2)} would exceed daily limit of $${limits.daily.toFixed(2)} (current total: $${dailyTotal.toFixed(2)})`,
      };
    }

    // Transaction is allowed
    return {
      allowed: true,
      currentDailyTotal: dailyTotal,
      remainingDaily: remainingDaily - amount,
    };
  }

  /**
   * Get total amount spent today
   * @returns Sum of today's approved transactions
   */
  getDailyTotal(): number {
    const startOfDay = getStartOfDay();
    return this.transactions
      .filter((t) => t.timestamp >= startOfDay && t.approved)
      .reduce((sum, t) => sum + t.amount, 0);
  }

  /**
   * Get transactions since a given timestamp
   * @param since Unix timestamp (default: start of today)
   * @returns Array of transactions since the given time
   */
  getTransactions(since?: number): SpendRecord[] {
    const cutoff = since ?? getStartOfDay();
    return this.transactions
      .filter((t) => t.timestamp >= cutoff)
      .sort((a, b) => b.timestamp - a.timestamp);
  }

  /**
   * Reset all tracked transactions (for testing)
   */
  reset(): void {
    this.transactions = [];
    this.lastCleanup = Date.now();
  }

  /**
   * Run cleanup if enough time has passed
   */
  private maybeCleanup(): void {
    const now = Date.now();
    if (now - this.lastCleanup >= this.cleanupIntervalMs) {
      this.cleanup();
      this.lastCleanup = now;
    }
  }

  /**
   * Remove transactions older than 24 hours
   */
  private cleanup(): void {
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    this.transactions = this.transactions.filter((t) => t.timestamp >= cutoff);
  }
}

/**
 * Create a new SpendTracker instance
 */
export function createSpendTracker(): SpendTracker {
  return new SpendTracker();
}

/**
 * Singleton instance for the global spend tracker
 */
let globalSpendTracker: SpendTracker | null = null;

/**
 * Get the global spend tracker instance
 */
export function getGlobalSpendTracker(): SpendTracker {
  if (!globalSpendTracker) {
    globalSpendTracker = new SpendTracker();
  }
  return globalSpendTracker;
}

/**
 * Reset the global spend tracker (for testing)
 */
export function resetGlobalSpendTracker(): void {
  if (globalSpendTracker) {
    globalSpendTracker.reset();
  }
  globalSpendTracker = null;
}
