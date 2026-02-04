/**
 * Native Approval Handler
 * Handles the /approve and /deny commands for OpenClaw native approval flow
 */

import type {
  ApprovalResult,
  NativeApprovalHandler,
  PendingApprovalRecord,
  ApprovalStore,
} from './types.js';
import { getDefaultApprovalStore } from './store.js';

/**
 * Configuration for the native approval handler
 */
export interface NativeApprovalHandlerConfig {
  /** The approval store to use (defaults to the default singleton) */
  store?: ApprovalStore;
}

/**
 * Default implementation of the native approval handler
 */
export class DefaultNativeApprovalHandler implements NativeApprovalHandler {
  private store: ApprovalStore;

  constructor(config: NativeApprovalHandlerConfig = {}) {
    this.store = config.store ?? getDefaultApprovalStore();
  }

  /**
   * Handle an /approve command
   */
  handleApprove(id: string, userId?: string): ApprovalResult {
    // Validate ID format
    if (!id || typeof id !== 'string' || id.trim() === '') {
      return {
        success: false,
        message: 'Invalid approval ID: ID cannot be empty',
      };
    }

    const trimmedId = id.trim();

    // Get the record
    const record = this.store.get(trimmedId);

    if (!record) {
      return {
        success: false,
        message: `Approval not found: No pending approval with ID "${trimmedId}"`,
      };
    }

    // Check status
    if (record.status === 'expired') {
      return {
        success: false,
        message: `Approval expired: The approval "${trimmedId}" has expired`,
        record,
      };
    }

    if (record.status === 'approved') {
      return {
        success: false,
        message: `Already approved: The approval "${trimmedId}" was already approved`,
        record,
      };
    }

    if (record.status === 'denied') {
      return {
        success: false,
        message: `Already denied: The approval "${trimmedId}" was already denied`,
        record,
      };
    }

    // Attempt to approve
    const success = this.store.approve(trimmedId, userId);

    if (!success) {
      // This shouldn't happen if our logic is correct, but handle it gracefully
      return {
        success: false,
        message: `Failed to approve: Unable to approve "${trimmedId}"`,
        record: this.store.get(trimmedId),
      };
    }

    // Get the updated record
    const approvedRecord = this.store.get(trimmedId);

    return {
      success: true,
      message: this.formatApprovalMessage(approvedRecord!),
      record: approvedRecord,
    };
  }

  /**
   * Handle a deny/reject command
   */
  handleDeny(id: string): ApprovalResult {
    // Validate ID format
    if (!id || typeof id !== 'string' || id.trim() === '') {
      return {
        success: false,
        message: 'Invalid approval ID: ID cannot be empty',
      };
    }

    const trimmedId = id.trim();

    // Get the record
    const record = this.store.get(trimmedId);

    if (!record) {
      return {
        success: false,
        message: `Approval not found: No pending approval with ID "${trimmedId}"`,
      };
    }

    // Check status
    if (record.status === 'expired') {
      return {
        success: false,
        message: `Approval expired: The approval "${trimmedId}" has expired`,
        record,
      };
    }

    if (record.status === 'approved') {
      return {
        success: false,
        message: `Already approved: The approval "${trimmedId}" was already approved and cannot be denied`,
        record,
      };
    }

    if (record.status === 'denied') {
      return {
        success: false,
        message: `Already denied: The approval "${trimmedId}" was already denied`,
        record,
      };
    }

    // Attempt to deny
    const success = this.store.deny(trimmedId);

    if (!success) {
      return {
        success: false,
        message: `Failed to deny: Unable to deny "${trimmedId}"`,
        record: this.store.get(trimmedId),
      };
    }

    // Get the updated record
    const deniedRecord = this.store.get(trimmedId);

    return {
      success: true,
      message: `Denied: The action for tool "${deniedRecord!.toolCall.toolName}" has been denied`,
      record: deniedRecord,
    };
  }

  /**
   * Check if a specific approval has been granted
   */
  isApproved(id: string): boolean {
    if (!id || typeof id !== 'string') {
      return false;
    }

    const record = this.store.get(id.trim());
    return record?.status === 'approved';
  }

  /**
   * Get all pending approval records
   */
  getPendingApprovals(): PendingApprovalRecord[] {
    return this.store.getPending();
  }

  /**
   * Format a success message for an approved action
   */
  private formatApprovalMessage(record: PendingApprovalRecord): string {
    const toolName = record.toolCall.toolName;
    const category = this.formatCategory(record.detection.category);

    return `Approved: You may now retry the ${category.toLowerCase()} action using tool "${toolName}"`;
  }

  /**
   * Format a threat category for display
   */
  private formatCategory(category: string): string {
    const categoryNames: Record<string, string> = {
      purchase: 'Purchase/Payment',
      website: 'Website Access',
      destructive: 'Destructive Command',
      secrets: 'Secrets/PII',
      exfiltration: 'Data Transfer',
    };
    return categoryNames[category] || category;
  }
}

/**
 * Create a native approval handler with the given configuration
 */
export function createNativeApprovalHandler(
  config?: NativeApprovalHandlerConfig
): DefaultNativeApprovalHandler {
  return new DefaultNativeApprovalHandler(config);
}

/**
 * Default singleton handler instance
 */
let defaultHandler: DefaultNativeApprovalHandler | null = null;

/**
 * Get the default native approval handler singleton
 */
export function getDefaultNativeApprovalHandler(): DefaultNativeApprovalHandler {
  if (!defaultHandler) {
    defaultHandler = createNativeApprovalHandler();
  }
  return defaultHandler;
}

/**
 * Reset the default handler (mainly for testing)
 */
export function resetDefaultNativeApprovalHandler(): void {
  defaultHandler = null;
}
