/**
 * In-Memory Approval Store
 * Stores and manages pending approval records with TTL and auto-cleanup
 */

import type {
  ApprovalStore,
  PendingApprovalRecord,
  PendingApprovalInput,
} from './types.js';

/**
 * Configuration options for the approval store
 */
export interface ApprovalStoreConfig {
  /** Interval in milliseconds for automatic cleanup (0 to disable) */
  cleanupIntervalMs?: number;
  /** Whether to remove expired entries on cleanup (vs just marking them expired) */
  removeOnExpiry?: boolean;
}

/** Default cleanup interval: 60 seconds */
const DEFAULT_CLEANUP_INTERVAL_MS = 60_000;

/**
 * In-memory implementation of the approval store
 */
export class InMemoryApprovalStore implements ApprovalStore {
  private records: Map<string, PendingApprovalRecord> = new Map();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private removeOnExpiry: boolean;

  constructor(config: ApprovalStoreConfig = {}) {
    this.removeOnExpiry = config.removeOnExpiry ?? false;

    const cleanupInterval = config.cleanupIntervalMs ?? DEFAULT_CLEANUP_INTERVAL_MS;
    if (cleanupInterval > 0) {
      this.startCleanupTimer(cleanupInterval);
    }
  }

  /**
   * Start the periodic cleanup timer
   */
  private startCleanupTimer(intervalMs: number): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanup();
    }, intervalMs);

    // Unref the timer so it doesn't keep the process alive
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Stop the cleanup timer (useful for testing)
   */
  public stopCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /**
   * Add a new pending approval record
   */
  add(record: PendingApprovalInput): void {
    const fullRecord: PendingApprovalRecord = {
      ...record,
      status: 'pending',
    };
    this.records.set(record.id, fullRecord);
  }

  /**
   * Get an approval record by ID
   * Also checks and updates expiration status
   */
  get(id: string): PendingApprovalRecord | undefined {
    const record = this.records.get(id);
    if (!record) {
      return undefined;
    }

    // Check if expired and update status
    if (record.status === 'pending' && Date.now() > record.expiresAt) {
      record.status = 'expired';
    }

    return record;
  }

  /**
   * Mark an approval as approved
   * Only works if the approval is still pending and not expired
   */
  approve(id: string, approvedBy?: string): boolean {
    const record = this.get(id);
    if (!record) {
      return false;
    }

    // Can only approve pending records
    if (record.status !== 'pending') {
      return false;
    }

    record.status = 'approved';
    record.approvedBy = approvedBy;
    record.approvedAt = Date.now();
    return true;
  }

  /**
   * Mark an approval as denied
   * Only works if the approval is still pending and not expired
   */
  deny(id: string): boolean {
    const record = this.get(id);
    if (!record) {
      return false;
    }

    // Can only deny pending records
    if (record.status !== 'pending') {
      return false;
    }

    record.status = 'denied';
    return true;
  }

  /**
   * Remove an approval record
   */
  remove(id: string): void {
    this.records.delete(id);
  }

  /**
   * Clean up expired entries
   * Updates status of expired entries and optionally removes them
   */
  cleanup(): void {
    const now = Date.now();
    const toRemove: string[] = [];

    for (const [id, record] of this.records) {
      // Mark expired pending records
      if (record.status === 'pending' && now > record.expiresAt) {
        record.status = 'expired';
      }

      // Optionally remove expired/processed records
      if (this.removeOnExpiry && record.status !== 'pending') {
        toRemove.push(id);
      }
    }

    for (const id of toRemove) {
      this.records.delete(id);
    }
  }

  /**
   * Get all pending approval records
   * Checks expiration before returning
   */
  getPending(): PendingApprovalRecord[] {
    const now = Date.now();
    const pending: PendingApprovalRecord[] = [];

    for (const record of this.records.values()) {
      // Update expired status first
      if (record.status === 'pending' && now > record.expiresAt) {
        record.status = 'expired';
      }

      if (record.status === 'pending') {
        pending.push(record);
      }
    }

    return pending;
  }

  /**
   * Get the total number of records in the store
   * Useful for testing
   */
  size(): number {
    return this.records.size;
  }

  /**
   * Clear all records from the store
   * Useful for testing
   */
  clear(): void {
    this.records.clear();
  }
}

/**
 * Create an in-memory approval store with the given configuration
 */
export function createApprovalStore(config?: ApprovalStoreConfig): InMemoryApprovalStore {
  return new InMemoryApprovalStore(config);
}

/**
 * Default singleton store instance
 * Use this for the main application flow
 */
let defaultStore: InMemoryApprovalStore | null = null;

/**
 * Get the default approval store singleton
 * Creates it on first call
 */
export function getDefaultApprovalStore(): InMemoryApprovalStore {
  if (!defaultStore) {
    defaultStore = createApprovalStore();
  }
  return defaultStore;
}

/**
 * Reset the default store (mainly for testing)
 */
export function resetDefaultApprovalStore(): void {
  if (defaultStore) {
    defaultStore.stopCleanupTimer();
    defaultStore.clear();
    defaultStore = null;
  }
}
