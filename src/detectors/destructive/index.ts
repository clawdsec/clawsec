/**
 * Destructive Detector
 * Main detector that combines shell, cloud, git, and code pattern detection
 */

import type {
  DetectionContext,
  DestructiveDetectionResult,
  DestructiveDetector as IDestructiveDetector,
  DestructiveDetectorConfig,
} from './types.js';
import { createLogger, type Logger } from '../../utils/logger.js';
import { ShellDetector, createShellDetector } from './shell-detector.js';
import { CloudDetector, createCloudDetector } from './cloud-detector.js';
import { CodeDetector, createCodeDetector } from './code-detector.js';
import type { DestructiveRule, Severity } from '../../config/index.js';

// Re-export types
export * from './types.js';

// Re-export sub-detectors
export { ShellDetector, createShellDetector } from './shell-detector.js';
export { CloudDetector, createCloudDetector } from './cloud-detector.js';
export { CodeDetector, createCodeDetector } from './code-detector.js';

// Re-export utility functions
export {
  isDangerousPath,
  matchRmCommand,
  matchSqlCommand,
  matchSystemCommand,
  matchShellCommand,
} from './shell-detector.js';

export {
  matchAwsCommand,
  matchGcpCommand,
  matchAzureCommand,
  matchKubernetesCommand,
  matchTerraformCommand,
  matchGitCommand,
  matchCloudCommand,
} from './cloud-detector.js';

export {
  matchPythonCode,
  matchNodeCode,
  matchGoCode,
  matchRustCode,
  matchRubyCode,
  matchJavaCode,
  matchCSharpCode,
  matchPhpCode,
  matchCodePattern,
} from './code-detector.js';

/**
 * No detection result (used when disabled or no match)
 */
function noDetection(severity: Severity): DestructiveDetectionResult {
  return {
    detected: false,
    category: 'destructive',
    severity,
    confidence: 0,
    reason: 'No destructive operation detected',
  };
}

/**
 * Combine multiple detection results, taking the highest confidence
 */
function combineResults(
  results: (DestructiveDetectionResult | null)[],
  severity: Severity
): DestructiveDetectionResult {
  const validResults = results.filter(
    (r): r is DestructiveDetectionResult => r !== null && r.detected
  );

  if (validResults.length === 0) {
    return noDetection(severity);
  }

  // Sort by confidence (highest first)
  validResults.sort((a, b) => b.confidence - a.confidence);

  // Take the highest confidence result as primary
  const primary = validResults[0];

  // Build combined reason if multiple detections
  let reason = primary.reason;
  if (validResults.length > 1) {
    const additionalReasons = validResults.slice(1).map((r) => r.reason);
    reason = `${primary.reason}. Additional signals: ${additionalReasons.join('; ')}`;
  }

  // Boost confidence if multiple detectors triggered
  let confidence = primary.confidence;
  if (validResults.length >= 2) {
    // Boost confidence but cap at 0.99
    confidence = Math.min(0.99, confidence + 0.05 * (validResults.length - 1));
  }

  return {
    detected: true,
    category: 'destructive',
    severity,
    confidence,
    reason,
    metadata: primary.metadata,
  };
}

/**
 * Main destructive detector implementation
 */
export class DestructiveDetectorImpl implements IDestructiveDetector {
  private config: DestructiveDetectorConfig;
  private shellDetector: ShellDetector | null;
  private cloudDetector: CloudDetector | null;
  private codeDetector: CodeDetector | null;
  private logger: Logger;

  constructor(config: DestructiveDetectorConfig, logger?: Logger) {
    this.config = config;
    this.logger = logger ?? createLogger(null, null);

    // Initialize sub-detectors based on config
    this.shellDetector =
      config.shell?.enabled !== false
        ? createShellDetector(config.severity, config.shell?.patterns || [], this.logger)
        : null;

    this.cloudDetector =
      config.cloud?.enabled !== false
        ? createCloudDetector(config.severity, config.cloud?.patterns || [], this.logger)
        : null;

    this.codeDetector =
      config.code?.enabled !== false
        ? createCodeDetector(config.severity, config.code?.patterns || [], this.logger)
        : null;
  }

  async detect(context: DetectionContext): Promise<DestructiveDetectionResult> {
    this.logger.debug(`[DestructiveDetector] Starting detection: tool=${context.toolName}`);

    // Check if detector is enabled
    if (!this.config.enabled) {
      this.logger.debug(`[DestructiveDetector] Detector disabled`);
      return noDetection(this.config.severity);
    }

    const results: (DestructiveDetectionResult | null)[] = [];

    // Run shell detector
    if (this.shellDetector) {
      this.logger.debug(`[DestructiveDetector] Running shell detector`);
      const result = this.shellDetector.detect(context);
      if (result && result.detected) {
        this.logger.info(`[DestructiveDetector] Shell detection: operation=${result.metadata?.operation || 'unknown'}, confidence=${result.confidence}`);
      }
      results.push(result);
    }

    // Run cloud detector (includes git commands)
    if (this.cloudDetector) {
      this.logger.debug(`[DestructiveDetector] Running cloud detector`);
      const result = this.cloudDetector.detect(context);
      if (result && result.detected) {
        this.logger.info(`[DestructiveDetector] Cloud detection: operation=${result.metadata?.operation || 'unknown'}, confidence=${result.confidence}`);
      }
      results.push(result);
    }

    // Run code detector
    if (this.codeDetector) {
      this.logger.debug(`[DestructiveDetector] Running code detector`);
      const result = this.codeDetector.detect(context);
      if (result && result.detected) {
        this.logger.info(`[DestructiveDetector] Code detection: operation=${result.metadata?.operation || 'unknown'}, confidence=${result.confidence}`);
      }
      results.push(result);
    }

    // Combine results
    const validDetections = results.filter((r): r is DestructiveDetectionResult => r !== null && r.detected);
    if (validDetections.length === 0) {
      this.logger.debug(`[DestructiveDetector] No detections found`);
    } else {
      this.logger.debug(`[DestructiveDetector] Combining ${validDetections.length} detections`);
      if (validDetections.length > 1) {
        this.logger.info(`[DestructiveDetector] Confidence boost: multiple sub-detectors triggered (${validDetections.length})`);
      }
    }

    const combined = combineResults(results, this.config.severity);
    this.logger.debug(`[DestructiveDetector] Detection complete: detected=${combined.detected}, confidence=${combined.confidence}`);
    
    return combined;
  }

  /**
   * Get the configured action for detected destructive operations
   */
  getAction() {
    return this.config.action;
  }

  /**
   * Check if the detector is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }

  /**
   * Check if shell detection is enabled
   */
  isShellEnabled(): boolean {
    return this.config.shell?.enabled !== false;
  }

  /**
   * Check if cloud detection is enabled
   */
  isCloudEnabled(): boolean {
    return this.config.cloud?.enabled !== false;
  }

  /**
   * Check if code detection is enabled
   */
  isCodeEnabled(): boolean {
    return this.config.code?.enabled !== false;
  }
}

/**
 * Create a destructive detector from DestructiveRule configuration
 */
export function createDestructiveDetector(
  rule: DestructiveRule,
  logger?: Logger
): DestructiveDetectorImpl {
  const config: DestructiveDetectorConfig = {
    enabled: rule.enabled,
    severity: rule.severity,
    action: rule.action,
    shell: rule.shell,
    cloud: rule.cloud,
    code: rule.code,
  };

  return new DestructiveDetectorImpl(config, logger);
}

/**
 * Create a destructive detector with default configuration
 */
export function createDefaultDestructiveDetector(): DestructiveDetectorImpl {
  return new DestructiveDetectorImpl({
    enabled: true,
    severity: 'critical',
    action: 'confirm',
    shell: { enabled: true },
    cloud: { enabled: true },
    code: { enabled: true },
  });
}

// Default export
export default DestructiveDetectorImpl;
