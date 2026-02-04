/**
 * Detection Result Cache
 * Simple in-memory cache with TTL-based expiration
 */

import type { AnalysisResult, CacheEntry, DetectionCache } from './types.js';
import { createHash } from 'crypto';

/**
 * Default cache TTL: 5 minutes
 */
export const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Maximum cache size to prevent memory issues
 */
export const MAX_CACHE_SIZE = 10000;

/**
 * Generate a cache key from tool name and input
 * Uses SHA256 hash of the JSON-serialized input
 */
export function generateCacheKey(toolName: string, toolInput: Record<string, unknown>): string {
  const data = JSON.stringify({ toolName, toolInput });
  return createHash('sha256').update(data).digest('hex').substring(0, 32);
}

/**
 * In-memory detection cache implementation
 */
export class InMemoryCache implements DetectionCache {
  private cache: Map<string, CacheEntry<AnalysisResult>>;
  private defaultTtl: number;

  constructor(defaultTtlMs: number = DEFAULT_CACHE_TTL_MS) {
    this.cache = new Map();
    this.defaultTtl = defaultTtlMs;
  }

  /**
   * Get a cached result by key
   * Returns undefined if not found or expired
   */
  get(key: string): AnalysisResult | undefined {
    const entry = this.cache.get(key);
    
    if (!entry) {
      return undefined;
    }

    // Check if expired
    if (this.isExpired(entry)) {
      this.cache.delete(key);
      return undefined;
    }

    // Return a copy with cached flag set
    return {
      ...entry.value,
      cached: true,
    };
  }

  /**
   * Set a cached result
   * @param key Cache key
   * @param result Analysis result to cache
   * @param ttl Optional TTL in milliseconds (uses default if not provided)
   */
  set(key: string, result: AnalysisResult, ttl?: number): void {
    // Evict expired entries if we're at capacity
    if (this.cache.size >= MAX_CACHE_SIZE) {
      this.evictExpired();
      
      // If still at capacity, evict oldest entries
      if (this.cache.size >= MAX_CACHE_SIZE) {
        this.evictOldest(Math.floor(MAX_CACHE_SIZE * 0.1));
      }
    }

    const entry: CacheEntry<AnalysisResult> = {
      value: { ...result, cached: false }, // Store original without cached flag
      createdAt: Date.now(),
      ttl: ttl ?? this.defaultTtl,
    };

    this.cache.set(key, entry);
  }

  /**
   * Check if a key exists and is not expired
   */
  has(key: string): boolean {
    const entry = this.cache.get(key);
    
    if (!entry) {
      return false;
    }

    if (this.isExpired(entry)) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Delete a specific entry
   */
  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  /**
   * Get the number of entries (including expired)
   */
  size(): number {
    return this.cache.size;
  }

  /**
   * Get the number of valid (non-expired) entries
   */
  validSize(): number {
    let count = 0;
    const now = Date.now();
    
    for (const [, entry] of this.cache) {
      if (now - entry.createdAt < entry.ttl) {
        count++;
      }
    }
    
    return count;
  }

  /**
   * Check if an entry is expired
   */
  private isExpired(entry: CacheEntry<AnalysisResult>): boolean {
    return Date.now() - entry.createdAt >= entry.ttl;
  }

  /**
   * Evict all expired entries
   */
  private evictExpired(): void {
    const now = Date.now();
    
    for (const [key, entry] of this.cache) {
      if (now - entry.createdAt >= entry.ttl) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Evict the oldest n entries
   */
  private evictOldest(count: number): void {
    const entries = Array.from(this.cache.entries())
      .sort((a, b) => a[1].createdAt - b[1].createdAt);
    
    for (let i = 0; i < Math.min(count, entries.length); i++) {
      this.cache.delete(entries[i][0]);
    }
  }
}

/**
 * Create a new cache instance
 */
export function createCache(defaultTtlMs?: number): DetectionCache {
  return new InMemoryCache(defaultTtlMs);
}

/**
 * Create a no-op cache that doesn't store anything
 * Used when caching is disabled
 */
export function createNoOpCache(): DetectionCache {
  return {
    get: () => undefined,
    set: () => {},
    has: () => false,
    clear: () => {},
    delete: () => false,
    size: () => 0,
  };
}
