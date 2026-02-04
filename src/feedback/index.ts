/**
 * Feedback Module
 * User feedback for detection accuracy (false positives/negatives)
 */

// Type exports
export type {
  FeedbackStatus,
  FeedbackType,
  FeedbackDetectionContext,
  FeedbackEntry,
  FalsePositiveOptions,
  FalseNegativeOptions,
  FeedbackInput,
  FeedbackStore,
  FeedbackOptions,
  FeedbackResult,
} from './types.js';

// Store exports
export {
  FileFeedbackStore,
  getFeedbackStore,
  resetGlobalFeedbackStore,
  createFeedbackStore,
} from './store.js';

// Learner exports
export type {
  PatternWeight,
  LearnerStats,
  WeightStore,
  Learner,
} from './learner.js';

export {
  FileWeightStore,
  PatternLearner,
  getLearner,
  getWeightStore,
  resetGlobalLearner,
  createLearner,
  createWeightStore,
} from './learner.js';
