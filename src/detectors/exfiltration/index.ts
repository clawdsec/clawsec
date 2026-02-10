/**
 * Exfiltration Detector
 * Main export for detecting data exfiltration attempts via HTTP, cloud, and network methods
 */

// Re-export types
export type {
  DetectionContext,
  ExfiltrationMethod,
  ExfiltrationDetectionResult,
  ExfiltrationDetectorConfig,
  ExfiltrationDetector as IExfiltrationDetector,
  SubDetector,
  HttpMatchResult,
  CloudUploadMatchResult,
  NetworkMatchResult,
} from './types.js';

// Re-export HTTP detector
export {
  HttpDetector,
  createHttpDetector,
  matchCurlCommand,
  matchWgetCommand,
  matchHttpieCommand,
  matchCodeHttpPattern,
  matchEncodedExfiltration,
  matchHttpExfiltration,
} from './http-detector.js';

// Re-export cloud upload detector
export {
  CloudUploadDetector,
  createCloudUploadDetector,
  matchAwsS3Upload,
  matchGcpUpload,
  matchAzureUpload,
  matchRcloneUpload,
  matchOtherCloudUpload,
  matchCloudSdkUpload,
  matchCloudUpload,
} from './cloud-detector.js';

// Re-export network detector
export {
  NetworkDetector,
  createNetworkDetector,
  matchNetcatCommand,
  matchDevTcpPattern,
  matchSocatCommand,
  matchTelnetCommand,
  matchSshExfiltration,
  matchDnsExfiltration,
  matchOtherNetworkPattern,
  matchNetworkExfiltration,
} from './network-detector.js';

import type {
  DetectionContext,
  ExfiltrationDetectionResult,
  ExfiltrationDetectorConfig,
  ExfiltrationDetector,
} from './types.js';
import { createLogger, type Logger } from '../../utils/logger.js';
import { HttpDetector, createHttpDetector } from './http-detector.js';
import { CloudUploadDetector, createCloudUploadDetector } from './cloud-detector.js';
import { NetworkDetector, createNetworkDetector } from './network-detector.js';
import type { Severity, ExfiltrationRule } from '../../config/index.js';

/**
 * Create a no-detection result
 */
function noDetection(severity: Severity): ExfiltrationDetectionResult {
  return {
    detected: false,
    category: 'exfiltration',
    severity,
    confidence: 0,
    reason: 'No exfiltration detected',
  };
}

/**
 * Combine results from multiple sub-detectors
 */
function combineResults(
  results: (ExfiltrationDetectionResult | null)[],
  defaultSeverity: Severity
): ExfiltrationDetectionResult {
  // Filter out null results
  const validResults = results.filter(
    (r): r is ExfiltrationDetectionResult => r !== null && r.detected
  );

  if (validResults.length === 0) {
    return noDetection(defaultSeverity);
  }

  // Sort by confidence (highest first)
  validResults.sort((a, b) => b.confidence - a.confidence);

  // Take the highest confidence result
  const best = validResults[0];

  // Boost confidence if multiple detectors matched
  let confidence = best.confidence;
  if (validResults.length > 1) {
    // Boost by 5% for each additional detection, max 0.99
    confidence = Math.min(0.99, confidence + (validResults.length - 1) * 0.05);
  }

  return {
    ...best,
    confidence,
    reason: validResults.length > 1
      ? `${best.reason} (confirmed by ${validResults.length} detection methods)`
      : best.reason,
  };
}

/**
 * Main exfiltration detector implementation
 */
export class ExfiltrationDetectorImpl implements ExfiltrationDetector {
  private config: ExfiltrationDetectorConfig;
  private httpDetector: HttpDetector;
  private cloudDetector: CloudUploadDetector;
  private networkDetector: NetworkDetector;
  private logger: Logger;

  constructor(config: ExfiltrationDetectorConfig, logger?: Logger) {
    this.config = config;
    this.logger = logger ?? createLogger(null, null);

    // Initialize sub-detectors with custom patterns
    const customPatterns = config.patterns || [];
    this.httpDetector = createHttpDetector(config.severity, customPatterns, this.logger);
    this.cloudDetector = createCloudUploadDetector(config.severity, customPatterns, this.logger);
    this.networkDetector = createNetworkDetector(config.severity, customPatterns, this.logger);
  }

  async detect(context: DetectionContext): Promise<ExfiltrationDetectionResult> {
    this.logger.debug(`[ExfiltrationDetector] Starting detection: tool=${context.toolName}`);

    // Check if detector is enabled
    if (!this.config.enabled) {
      this.logger.debug(`[ExfiltrationDetector] Detector disabled`);
      return noDetection(this.config.severity);
    }

    const results: (ExfiltrationDetectionResult | null)[] = [];

    // Run HTTP detector
    this.logger.debug(`[ExfiltrationDetector] Running HTTP detector`);
    const httpResult = this.httpDetector.detect(context);
    if (httpResult && httpResult.detected) {
      this.logger.info(`[ExfiltrationDetector] HTTP detection: method=${httpResult.metadata?.method || 'unknown'}, confidence=${httpResult.confidence}`);
    }
    results.push(httpResult);

    // Run cloud upload detector
    this.logger.debug(`[ExfiltrationDetector] Running cloud upload detector`);
    const cloudResult = this.cloudDetector.detect(context);
    if (cloudResult && cloudResult.detected) {
      this.logger.info(`[ExfiltrationDetector] Cloud upload detection: method=${cloudResult.metadata?.method || 'unknown'}, confidence=${cloudResult.confidence}`);
    }
    results.push(cloudResult);

    // Run network detector
    this.logger.debug(`[ExfiltrationDetector] Running network detector`);
    const networkResult = this.networkDetector.detect(context);
    if (networkResult && networkResult.detected) {
      this.logger.info(`[ExfiltrationDetector] Network detection: method=${networkResult.metadata?.method || 'unknown'}, confidence=${networkResult.confidence}`);
    }
    results.push(networkResult);

    // Combine results
    const validDetections = results.filter((r): r is ExfiltrationDetectionResult => r !== null && r.detected);
    if (validDetections.length === 0) {
      this.logger.debug(`[ExfiltrationDetector] No detections found`);
    } else {
      this.logger.debug(`[ExfiltrationDetector] Combining ${validDetections.length} detections`);
      if (validDetections.length > 1) {
        this.logger.info(`[ExfiltrationDetector] Confidence boost: multiple sub-detectors triggered (${validDetections.length})`);
      }
    }

    const combined = combineResults(results, this.config.severity);
    this.logger.debug(`[ExfiltrationDetector] Detection complete: detected=${combined.detected}, confidence=${combined.confidence}`);
    
    return combined;
  }

  /**
   * Get the configured action for detected exfiltration
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
}

/**
 * Create an exfiltration detector from configuration
 */
export function createExfiltrationDetector(
  config: ExfiltrationDetectorConfig | ExfiltrationRule,
  logger?: Logger
): ExfiltrationDetectorImpl {
  return new ExfiltrationDetectorImpl(config, logger);
}

/**
 * Create a default exfiltration detector with standard settings
 */
export function createDefaultExfiltrationDetector(): ExfiltrationDetectorImpl {
  return new ExfiltrationDetectorImpl({
    enabled: true,
    severity: 'high',
    action: 'block',
  });
}

// Default export
export default {
  ExfiltrationDetectorImpl,
  createExfiltrationDetector,
  createDefaultExfiltrationDetector,
};
