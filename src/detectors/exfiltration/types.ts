/**
 * Exfiltration Detector Types
 * Type definitions for detecting data exfiltration attempts
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
 * Method of exfiltration detected
 */
export type ExfiltrationMethod = 'http' | 'cloud' | 'network' | 'encoded';

/**
 * Result of an exfiltration detection
 */
export interface ExfiltrationDetectionResult {
  /** Whether exfiltration was detected */
  detected: boolean;
  /** Category of the detection */
  category: 'exfiltration';
  /** Severity level of the detection */
  severity: Severity;
  /** Confidence score from 0 to 1 */
  confidence: number;
  /** Human-readable reason for the detection */
  reason: string;
  /** Additional metadata about the detection */
  metadata?: {
    /** Method of exfiltration */
    method: ExfiltrationMethod;
    /** Destination URL, IP, or hostname */
    destination?: string;
    /** What data is being sent */
    dataSource?: string;
    /** The command that triggered detection */
    command?: string;
  };
}

/**
 * Configuration for the exfiltration detector
 */
export interface ExfiltrationDetectorConfig {
  /** Whether the detector is enabled */
  enabled: boolean;
  /** Severity level to assign to detections */
  severity: Severity;
  /** Action to take when exfiltration is detected */
  action: Action;
  /** Custom patterns to detect (optional) */
  patterns?: string[];
}

/**
 * Interface for the main exfiltration detector
 */
export interface ExfiltrationDetector {
  /**
   * Detect exfiltration attempts
   * @param context Detection context with tool information
   * @returns Detection result
   */
  detect(context: DetectionContext): Promise<ExfiltrationDetectionResult>;
}

/**
 * Interface for sub-detectors (http, cloud, network)
 */
export interface SubDetector {
  /**
   * Check if the given context matches this detector's patterns
   * @param context Detection context
   * @returns Detection result or null if no match
   */
  detect(context: DetectionContext): ExfiltrationDetectionResult | null;
}

/**
 * HTTP exfiltration match result
 */
export interface HttpMatchResult {
  /** Whether a match was found */
  matched: boolean;
  /** The command or code that matched */
  command?: string;
  /** The HTTP method used (POST, PUT) */
  httpMethod?: string;
  /** The destination URL */
  destination?: string;
  /** What data is being sent */
  dataSource?: string;
  /** Confidence score */
  confidence: number;
  /** Description of the exfiltration attempt */
  description?: string;
}

/**
 * Cloud upload match result
 */
export interface CloudUploadMatchResult {
  /** Whether a match was found */
  matched: boolean;
  /** The command that matched */
  command?: string;
  /** The cloud provider (aws, gcp, azure) */
  provider?: string;
  /** The operation detected (cp, sync) */
  operation?: string;
  /** The destination (S3 bucket, GCS bucket, etc.) */
  destination?: string;
  /** The source file/directory being uploaded */
  dataSource?: string;
  /** Confidence score */
  confidence: number;
}

/**
 * Network exfiltration match result
 */
export interface NetworkMatchResult {
  /** Whether a match was found */
  matched: boolean;
  /** The command that matched */
  command?: string;
  /** The tool used (nc, netcat, socat, etc.) */
  tool?: string;
  /** The destination host/IP */
  destination?: string;
  /** The port being used */
  port?: string;
  /** What data is being sent */
  dataSource?: string;
  /** Confidence score */
  confidence: number;
  /** Description of the exfiltration attempt */
  description?: string;
}
