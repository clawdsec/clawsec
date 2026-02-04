/**
 * Tool Result Persist Hook
 *
 * Scans tool outputs for secrets/PII and filters sensitive data
 * before persistence.
 */

// Handler exports
export {
  createToolResultPersistHandler,
  createDefaultToolResultPersistHandler,
} from './handler.js';
export type { ToolResultPersistHandlerOptions } from './handler.js';

// Filter exports
export {
  filterOutput,
  filterValue,
  redactString,
  redactObject,
  redactArray,
  detectionsToRedactions,
} from './filter.js';
export type { Redaction, FilterResult } from './filter.js';
