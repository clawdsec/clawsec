/**
 * Destructive Detector Types
 * Type definitions for detecting dangerous/destructive operations
 */

import type { Severity, Action } from '../../config/index.js';

/**
 * Detection context passed to detectors
 */
export interface DetectionContext {
  /** Name of the tool being invoked */
  toolName: string;
  /** Input parameters to the tool */
  toolInput: Record<string, unknown>;
  /** URL being accessed (for browser/navigation tools) */
  url?: string;
}

/**
 * Type of destructive operation detected
 */
export type DestructiveType = 'shell' | 'cloud' | 'git' | 'code';

/**
 * Result of a destructive operation detection
 */
export interface DestructiveDetectionResult {
  /** Whether a destructive operation was detected */
  detected: boolean;
  /** Category of the detection */
  category: 'destructive';
  /** Severity level of the detection */
  severity: Severity;
  /** Confidence score from 0 to 1 */
  confidence: number;
  /** Human-readable reason for the detection */
  reason: string;
  /** Additional metadata about the detection */
  metadata?: {
    /** The command that triggered detection */
    command?: string;
    /** Type of destructive operation */
    type: DestructiveType;
    /** Specific operation detected (e.g., 'rm -rf', 'DROP DATABASE') */
    operation?: string;
    /** Resource affected (e.g., path, database name) */
    affectedResource?: string;
  };
}

/**
 * Configuration for the destructive detector
 */
export interface DestructiveDetectorConfig {
  /** Whether the detector is enabled */
  enabled: boolean;
  /** Severity level to assign to detections */
  severity: Severity;
  /** Action to take when destructive operation is detected */
  action: Action;
  /** Shell command protection settings */
  shell?: {
    enabled: boolean;
    /** Custom regex patterns for shell command detection */
    patterns?: string[];
  };
  /** Cloud operation protection settings */
  cloud?: {
    enabled: boolean;
    /** Custom regex patterns for cloud operation detection */
    patterns?: string[];
  };
  /** Code pattern protection settings */
  code?: {
    enabled: boolean;
    /** Custom regex patterns for code pattern detection */
    patterns?: string[];
  };
}

/**
 * Interface for the main destructive detector
 */
export interface DestructiveDetector {
  /**
   * Detect destructive operations
   * @param context Detection context with tool information
   * @returns Detection result
   */
  detect(context: DetectionContext): Promise<DestructiveDetectionResult>;
}

/**
 * Interface for sub-detectors (shell, cloud, code)
 */
export interface SubDetector {
  /**
   * Check if the given context matches this detector's patterns
   * @param context Detection context
   * @returns Detection result or null if no match
   */
  detect(context: DetectionContext): DestructiveDetectionResult | null;
}

/**
 * Shell command match result
 */
export interface ShellMatchResult {
  /** Whether a match was found */
  matched: boolean;
  /** The command that matched */
  command?: string;
  /** The operation type (e.g., 'rm', 'dd', 'DROP DATABASE') */
  operation?: string;
  /** The affected resource (path, database, etc.) */
  affectedResource?: string;
  /** Confidence score */
  confidence: number;
  /** Additional description of the risk */
  riskDescription?: string;
}

/**
 * Cloud operation match result
 */
export interface CloudMatchResult {
  /** Whether a match was found */
  matched: boolean;
  /** The command that matched */
  command?: string;
  /** The cloud provider (aws, gcp, azure, k8s, terraform) */
  provider?: string;
  /** The operation detected */
  operation?: string;
  /** The affected resource */
  affectedResource?: string;
  /** Confidence score */
  confidence: number;
}

/**
 * Code pattern match result
 */
export interface CodeMatchResult {
  /** Whether a match was found */
  matched: boolean;
  /** The code/command that matched */
  code?: string;
  /** The language detected (python, node, go, etc.) */
  language?: string;
  /** The operation detected (e.g., 'rmtree', 'removeAll') */
  operation?: string;
  /** The affected path/resource */
  affectedResource?: string;
  /** Confidence score */
  confidence: number;
}
