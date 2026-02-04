/**
 * Approval Module
 * Re-exports for the approval system
 */

// Types
export type {
  ApprovalStatus,
  PendingApprovalRecord,
  PendingApprovalInput,
  ApprovalStore,
  ApprovalResult,
  NativeApprovalHandler,
} from './types.js';

// Store
export type { ApprovalStoreConfig } from './store.js';
export {
  InMemoryApprovalStore,
  createApprovalStore,
  getDefaultApprovalStore,
  resetDefaultApprovalStore,
} from './store.js';

// Native handler
export type { NativeApprovalHandlerConfig } from './native.js';
export {
  DefaultNativeApprovalHandler,
  createNativeApprovalHandler,
  getDefaultNativeApprovalHandler,
  resetDefaultNativeApprovalHandler,
} from './native.js';
