/**
 * Pattern Weight Learner
 * Adjusts pattern weights based on user feedback to improve detection accuracy
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { ThreatCategory } from '../engine/index.js';
import type { FeedbackEntry } from './types.js';

/** Default storage directory relative to project root */
const DEFAULT_STORAGE_DIR = '.clawsec';

/** Default weights filename */
const DEFAULT_WEIGHTS_FILE = 'weights.json';

/** Decay factor per false positive (reduces weight) */
const DECAY_FACTOR = 0.1;

/** Boost factor per false negative (increases weight) */
const BOOST_FACTOR = 0.05;

/** Minimum weight - never fully disable a pattern */
const MIN_WEIGHT = 0.1;

/** Maximum weight */
const MAX_WEIGHT = 1.0;

/**
 * Weight information for a pattern
 */
export interface PatternWeight {
  /** The regex pattern or identifier */
  pattern: string;
  /** Threat category this pattern belongs to */
  category: ThreatCategory;
  /** Original weight (0-1) */
  baseWeight: number;
  /** After feedback adjustment */
  adjustedWeight: number;
  /** Count of false positive reports */
  falsePositives: number;
  /** Count of false negative reports */
  falseNegatives: number;
  /** Unix timestamp of last update */
  lastUpdated: number;
}

/**
 * Statistics about learning activity
 */
export interface LearnerStats {
  /** Total number of weight adjustments made */
  totalAdjustments: number;
  /** Number of false positives processed */
  falsePositivesProcessed: number;
  /** Number of false negatives processed */
  falseNegativesProcessed: number;
  /** Number of patterns that have been adjusted */
  patternsAdjusted: number;
}

/**
 * Interface for weight storage operations
 */
export interface WeightStore {
  /** All pattern weights */
  weights: Map<string, PatternWeight>;
  /** Load weights from persistent storage */
  load(): Promise<void>;
  /** Save weights to persistent storage */
  save(): Promise<void>;
  /** Get the adjusted weight for a pattern */
  getWeight(pattern: string): number;
  /** Adjust weight for a false positive report */
  adjustForFalsePositive(pattern: string, category: ThreatCategory): void;
  /** Adjust weight for a false negative report */
  adjustForFalseNegative(pattern: string, category: ThreatCategory): void;
  /** Reset weights for a pattern or all patterns */
  reset(pattern?: string): void;
}

/**
 * Interface for the pattern weight learner
 */
export interface Learner {
  /** Process feedback and adjust weights */
  processFeedback(entry: FeedbackEntry): Promise<void>;
  /** Get adjusted confidence for a detection */
  getAdjustedConfidence(
    baseConfidence: number,
    pattern: string,
    category: ThreatCategory
  ): number;
  /** Get learning statistics */
  getStats(): LearnerStats;
}

/**
 * File-based weight storage implementation
 */
export class FileWeightStore implements WeightStore {
  weights: Map<string, PatternWeight> = new Map();
  private filePath: string;
  private loaded = false;

  /**
   * Create a new file-based weight store
   * 
   * @param projectRoot - Root directory of the project (default: current working directory)
   * @param filename - Name of the storage file (default: weights.json)
   */
  constructor(projectRoot?: string, filename?: string) {
    const root = projectRoot ?? process.cwd();
    const file = filename ?? DEFAULT_WEIGHTS_FILE;
    this.filePath = join(root, DEFAULT_STORAGE_DIR, file);
  }

  /**
   * Load weights from the storage file
   */
  async load(): Promise<void> {
    try {
      const json = await readFile(this.filePath, 'utf-8');
      const data = JSON.parse(json) as PatternWeight[];

      this.weights.clear();
      for (const weight of data) {
        this.weights.set(weight.pattern, weight);
      }
      this.loaded = true;
    } catch (error) {
      // File doesn't exist or is invalid - start with empty store
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        console.warn(`Warning: Could not load weight store: ${(error as Error).message}`);
      }
      this.weights.clear();
      this.loaded = true;
    }
  }

  /**
   * Save weights to the storage file
   */
  async save(): Promise<void> {
    // Ensure directory exists
    await mkdir(dirname(this.filePath), { recursive: true });

    // Convert weights to array for JSON serialization
    const data = Array.from(this.weights.values());
    const json = JSON.stringify(data, null, 2);

    await writeFile(this.filePath, json, 'utf-8');
  }

  /**
   * Get the adjusted weight for a pattern
   * Returns 1.0 if pattern has no adjustment
   * 
   * @param pattern - The pattern identifier
   * @returns The adjusted weight (0.1-1.0) or 1.0 if not found
   */
  getWeight(pattern: string): number {
    const weight = this.weights.get(pattern);
    return weight ? weight.adjustedWeight : 1.0;
  }

  /**
   * Calculate the adjusted weight based on false positive/negative counts
   */
  private calculateAdjustedWeight(baseWeight: number, fpCount: number, fnCount: number): number {
    // False positive: adjustedWeight = baseWeight * (1 - decayFactor * fpCount)
    // False negative: adjustedWeight = min(1, baseWeight * (1 + boostFactor * fnCount))
    
    // Apply false positive decay
    let adjusted = baseWeight * (1 - DECAY_FACTOR * fpCount);
    
    // Apply false negative boost
    adjusted = adjusted * (1 + BOOST_FACTOR * fnCount);
    
    // Clamp to bounds
    return Math.max(MIN_WEIGHT, Math.min(MAX_WEIGHT, adjusted));
  }

  /**
   * Adjust weight for a false positive report
   * 
   * @param pattern - The pattern identifier
   * @param category - The threat category
   */
  adjustForFalsePositive(pattern: string, category: ThreatCategory): void {
    let weight = this.weights.get(pattern);

    if (!weight) {
      // Create new weight entry with default base weight
      weight = {
        pattern,
        category,
        baseWeight: 1.0,
        adjustedWeight: 1.0,
        falsePositives: 0,
        falseNegatives: 0,
        lastUpdated: Date.now(),
      };
    }

    weight.falsePositives++;
    weight.adjustedWeight = this.calculateAdjustedWeight(
      weight.baseWeight,
      weight.falsePositives,
      weight.falseNegatives
    );
    weight.lastUpdated = Date.now();

    this.weights.set(pattern, weight);
  }

  /**
   * Adjust weight for a false negative report
   * 
   * @param pattern - The pattern identifier
   * @param category - The threat category
   */
  adjustForFalseNegative(pattern: string, category: ThreatCategory): void {
    let weight = this.weights.get(pattern);

    if (!weight) {
      // Create new weight entry with default base weight
      weight = {
        pattern,
        category,
        baseWeight: 1.0,
        adjustedWeight: 1.0,
        falsePositives: 0,
        falseNegatives: 0,
        lastUpdated: Date.now(),
      };
    }

    weight.falseNegatives++;
    weight.adjustedWeight = this.calculateAdjustedWeight(
      weight.baseWeight,
      weight.falsePositives,
      weight.falseNegatives
    );
    weight.lastUpdated = Date.now();

    this.weights.set(pattern, weight);
  }

  /**
   * Reset weights for a specific pattern or all patterns
   * 
   * @param pattern - Optional pattern to reset (resets all if omitted)
   */
  reset(pattern?: string): void {
    if (pattern) {
      const weight = this.weights.get(pattern);
      if (weight) {
        weight.adjustedWeight = weight.baseWeight;
        weight.falsePositives = 0;
        weight.falseNegatives = 0;
        weight.lastUpdated = Date.now();
      }
    } else {
      // Reset all weights
      for (const weight of this.weights.values()) {
        weight.adjustedWeight = weight.baseWeight;
        weight.falsePositives = 0;
        weight.falseNegatives = 0;
        weight.lastUpdated = Date.now();
      }
    }
  }

  /**
   * Check if the store has been loaded from disk
   */
  isLoaded(): boolean {
    return this.loaded;
  }

  /**
   * Get the number of patterns in the store
   */
  size(): number {
    return this.weights.size;
  }

  /**
   * Clear all weights from the store
   */
  clear(): void {
    this.weights.clear();
  }

  /**
   * Get the storage file path
   */
  getFilePath(): string {
    return this.filePath;
  }
}

/**
 * Pattern weight learner implementation
 */
export class PatternLearner implements Learner {
  private weightStore: WeightStore;
  private stats: LearnerStats = {
    totalAdjustments: 0,
    falsePositivesProcessed: 0,
    falseNegativesProcessed: 0,
    patternsAdjusted: 0,
  };
  private adjustedPatterns: Set<string> = new Set();

  /**
   * Create a new pattern learner
   * 
   * @param weightStore - The weight store to use
   */
  constructor(weightStore: WeightStore) {
    this.weightStore = weightStore;
  }

  /**
   * Process feedback and adjust weights
   * Only processes feedback entries with 'applied' status
   * 
   * @param entry - The feedback entry to process
   */
  async processFeedback(entry: FeedbackEntry): Promise<void> {
    // Only process applied feedback
    if (entry.status !== 'applied') {
      return;
    }

    // Extract pattern from detection context
    const pattern = this.extractPattern(entry);
    if (!pattern) {
      return;
    }

    const category = entry.detection?.category ?? entry.suggestedCategory;
    if (!category) {
      return;
    }

    if (entry.type === 'false-positive') {
      this.weightStore.adjustForFalsePositive(pattern, category);
      this.stats.falsePositivesProcessed++;
    } else if (entry.type === 'false-negative') {
      this.weightStore.adjustForFalseNegative(pattern, category);
      this.stats.falseNegativesProcessed++;
    }

    this.stats.totalAdjustments++;
    this.adjustedPatterns.add(pattern);
    this.stats.patternsAdjusted = this.adjustedPatterns.size;

    // Save after processing
    await this.weightStore.save();
  }

  /**
   * Process multiple feedback entries in batch
   * 
   * @param entries - Array of feedback entries to process
   */
  async processFeedbackBatch(entries: FeedbackEntry[]): Promise<void> {
    for (const entry of entries) {
      // Process without saving each time
      if (entry.status !== 'applied') {
        continue;
      }

      const pattern = this.extractPattern(entry);
      if (!pattern) {
        continue;
      }

      const category = entry.detection?.category ?? entry.suggestedCategory;
      if (!category) {
        continue;
      }

      if (entry.type === 'false-positive') {
        this.weightStore.adjustForFalsePositive(pattern, category);
        this.stats.falsePositivesProcessed++;
      } else if (entry.type === 'false-negative') {
        this.weightStore.adjustForFalseNegative(pattern, category);
        this.stats.falseNegativesProcessed++;
      }

      this.stats.totalAdjustments++;
      this.adjustedPatterns.add(pattern);
    }

    this.stats.patternsAdjusted = this.adjustedPatterns.size;

    // Save once after batch processing
    if (entries.length > 0) {
      await this.weightStore.save();
    }
  }

  /**
   * Get adjusted confidence for a detection
   * 
   * @param baseConfidence - The original confidence score (0-1)
   * @param pattern - The pattern identifier
   * @param category - The threat category
   * @returns The adjusted confidence score
   */
  getAdjustedConfidence(
    baseConfidence: number,
    pattern: string,
    category: ThreatCategory
  ): number {
    // Suppress unused parameter warning - category could be used for
    // category-specific adjustments in the future
    void category;

    const weight = this.weightStore.getWeight(pattern);
    
    // If no adjustment exists, return base confidence unchanged
    if (weight === 1.0) {
      return baseConfidence;
    }

    // Apply weight to confidence
    return Math.max(0, Math.min(1, baseConfidence * weight));
  }

  /**
   * Get learning statistics
   */
  getStats(): LearnerStats {
    return { ...this.stats };
  }

  /**
   * Extract pattern identifier from a feedback entry
   * Uses detection reason or description as the pattern identifier
   */
  private extractPattern(entry: FeedbackEntry): string | null {
    // For false positives, use the detection reason
    if (entry.detection?.reason) {
      return entry.detection.reason;
    }

    // For false negatives, use the description
    if (entry.description) {
      return entry.description;
    }

    // Fallback to detection ID
    if (entry.detectionId) {
      return `detection:${entry.detectionId}`;
    }

    return null;
  }

  /**
   * Reset learning statistics
   */
  resetStats(): void {
    this.stats = {
      totalAdjustments: 0,
      falsePositivesProcessed: 0,
      falseNegativesProcessed: 0,
      patternsAdjusted: 0,
    };
    this.adjustedPatterns.clear();
  }
}

/**
 * Global learner instance
 */
let globalLearner: PatternLearner | null = null;
let globalWeightStore: FileWeightStore | null = null;

/**
 * Get the global learner instance
 * 
 * @param projectRoot - Optional project root for weight storage
 * @returns The global learner instance
 */
export function getLearner(projectRoot?: string): PatternLearner {
  if (!globalLearner) {
    globalWeightStore = new FileWeightStore(projectRoot);
    globalLearner = new PatternLearner(globalWeightStore);
  }
  return globalLearner;
}

/**
 * Get the global weight store instance
 * 
 * @param projectRoot - Optional project root for weight storage
 * @returns The global weight store instance
 */
export function getWeightStore(projectRoot?: string): FileWeightStore {
  if (!globalWeightStore) {
    globalWeightStore = new FileWeightStore(projectRoot);
  }
  return globalWeightStore;
}

/**
 * Reset the global learner and weight store (primarily for testing)
 */
export function resetGlobalLearner(): void {
  if (globalWeightStore) {
    globalWeightStore.clear();
  }
  globalLearner = null;
  globalWeightStore = null;
}

/**
 * Create a new learner with a specific weight store
 * 
 * @param weightStore - The weight store to use
 * @returns A new PatternLearner instance
 */
export function createLearner(weightStore: WeightStore): PatternLearner {
  return new PatternLearner(weightStore);
}

/**
 * Create a new weight store with a specific storage location
 * 
 * @param projectRoot - Project root directory
 * @param filename - Optional custom filename
 * @returns A new FileWeightStore instance
 */
export function createWeightStore(projectRoot: string, filename?: string): FileWeightStore {
  return new FileWeightStore(projectRoot, filename);
}
