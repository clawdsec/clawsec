/**
 * Type Definitions for Approval System
 * Handles pending approval records and approval operations
 */

import type { Detection, ToolCallContext } from '../engine/types.js';

/**
 * Status of a pending approval record
 */
export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired';

/**
 * A pending approval record storing all context needed for approval
 */
export interface PendingApprovalRecord {
  /** Unique identifier for this approval */
  id: string;
  /** Timestamp when the approval was created (ms since epoch) */
  createdAt: number;
  /** Timestamp when the approval expires (ms since epoch) */
  expiresAt: number;
  /** The detection that triggered this approval request */
  detection: Detection;
  /** The tool call context that requires approval */
  toolCall: ToolCallContext;
  /** Current status of the approval */
  status: ApprovalStatus;
  /** Who approved the action (if approved) */
  approvedBy?: string;
  /** Timestamp when the approval was granted (ms since epoch) */
  approvedAt?: number;
}

/**
 * Input for creating a new approval record (status is set automatically)
 */
export type PendingApprovalInput = Omit<PendingApprovalRecord, 'status'>;

/**
 * Interface for the approval store
 */
export interface ApprovalStore {
  /**
   * Add a new pending approval record
   * @param record - The approval record (without status, which defaults to 'pending')
   */
  add(record: PendingApprovalInput): void;

  /**
   * Get an approval record by ID
   * @param id - The approval ID
   * @returns The approval record or undefined if not found
   */
  get(id: string): PendingApprovalRecord | undefined;

  /**
   * Mark an approval as approved
   * @param id - The approval ID
   * @param approvedBy - Optional identifier for who approved
   * @returns true if successful, false if not found or already processed
   */
  approve(id: string, approvedBy?: string): boolean;

  /**
   * Mark an approval as denied
   * @param id - The approval ID
   * @returns true if successful, false if not found or already processed
   */
  deny(id: string): boolean;

  /**
   * Remove an approval record
   * @param id - The approval ID
   */
  remove(id: string): void;

  /**
   * Clean up expired entries
   * Updates status of expired entries and optionally removes them
   */
  cleanup(): void;

  /**
   * Get all pending approval records
   * @returns Array of pending approval records
   */
  getPending(): PendingApprovalRecord[];
}

/**
 * Result of an approval operation
 */
export interface ApprovalResult {
  /** Whether the operation succeeded */
  success: boolean;
  /** Human-readable message about the operation */
  message: string;
  /** The approval record (if found) */
  record?: PendingApprovalRecord;
}

/**
 * Interface for the native approval handler
 */
export interface NativeApprovalHandler {
  /**
   * Handle an /approve command
   * @param id - The approval ID
   * @param userId - Optional identifier for who is approving
   * @returns Result of the approval operation
   */
  handleApprove(id: string, userId?: string): ApprovalResult;

  /**
   * Handle a deny/reject command
   * @param id - The approval ID
   * @returns Result of the deny operation
   */
  handleDeny(id: string): ApprovalResult;

  /**
   * Check if a specific approval has been granted
   * @param id - The approval ID
   * @returns true if the approval exists and is approved
   */
  isApproved(id: string): boolean;

  /**
   * Get all pending approval records
   * @returns Array of pending approval records
   */
  getPendingApprovals(): PendingApprovalRecord[];
}
