/**
 * Cloud Upload Detector
 * Detects cloud storage uploads that could be data exfiltration
 */

import type {
  CloudUploadMatchResult,
  DetectionContext,
  ExfiltrationDetectionResult,
  SubDetector,
} from './types.js';
import type { Severity } from '../../config/index.js';

/**
 * AWS S3 upload patterns
 * Detects uploads TO S3 (not downloads FROM S3)
 */
const AWS_S3_UPLOAD_PATTERNS = [
  // aws s3 cp local_file s3://bucket
  {
    pattern: /\baws\s+s3\s+cp\s+(?!s3:\/\/)([^\s]+)\s+(s3:\/\/[^\s]+)/i,
    operation: 's3 cp',
    description: 'AWS S3 upload',
  },
  // aws s3 mv local_file s3://bucket
  {
    pattern: /\baws\s+s3\s+mv\s+(?!s3:\/\/)([^\s]+)\s+(s3:\/\/[^\s]+)/i,
    operation: 's3 mv',
    description: 'AWS S3 move/upload',
  },
  // aws s3 sync local_dir s3://bucket
  {
    pattern: /\baws\s+s3\s+sync\s+(?!s3:\/\/)([^\s]+)\s+(s3:\/\/[^\s]+)/i,
    operation: 's3 sync',
    description: 'AWS S3 sync upload',
  },
  // aws s3api put-object
  {
    pattern: /\baws\s+s3api\s+put-object\s+[^|;]*--bucket\s+([^\s]+)[^|;]*--key\s+([^\s]+)/i,
    operation: 's3api put-object',
    description: 'AWS S3 API upload',
  },
  // aws s3api put-object (alternate order)
  {
    pattern: /\baws\s+s3api\s+put-object\s+[^|;]*--key\s+([^\s]+)[^|;]*--bucket\s+([^\s]+)/i,
    operation: 's3api put-object',
    description: 'AWS S3 API upload',
  },
];

/**
 * GCP Storage upload patterns
 */
const GCP_UPLOAD_PATTERNS = [
  // gsutil cp local_file gs://bucket
  {
    pattern: /\bgsutil\s+(?:-m\s+)?cp\s+(?:-[rRn]\s+)*(?!gs:\/\/)([^\s]+)\s+(gs:\/\/[^\s]+)/i,
    operation: 'gsutil cp',
    description: 'GCP Storage upload',
  },
  // gsutil mv local_file gs://bucket
  {
    pattern: /\bgsutil\s+(?:-m\s+)?mv\s+(?!gs:\/\/)([^\s]+)\s+(gs:\/\/[^\s]+)/i,
    operation: 'gsutil mv',
    description: 'GCP Storage move/upload',
  },
  // gsutil rsync local_dir gs://bucket
  {
    pattern: /\bgsutil\s+(?:-m\s+)?rsync\s+(?:-[rRdC]\s+)*(?!gs:\/\/)([^\s]+)\s+(gs:\/\/[^\s]+)/i,
    operation: 'gsutil rsync',
    description: 'GCP Storage rsync upload',
  },
  // gcloud storage cp
  {
    pattern: /\bgcloud\s+storage\s+cp\s+(?:-[rR]\s+)*(?!gs:\/\/)([^\s]+)\s+(gs:\/\/[^\s]+)/i,
    operation: 'gcloud storage cp',
    description: 'GCP Storage upload',
  },
];

/**
 * Azure Storage upload patterns
 */
const AZURE_UPLOAD_PATTERNS = [
  // azcopy copy local_file https://account.blob.core.windows.net
  {
    pattern: /\bazcopy\s+copy\s+(?!https?:\/\/)([^\s]+)\s+(https:\/\/[^\s]*blob\.core\.windows\.net[^\s]*)/i,
    operation: 'azcopy copy',
    description: 'Azure Blob upload',
  },
  // azcopy sync local_dir https://account.blob.core.windows.net
  {
    pattern: /\bazcopy\s+sync\s+(?!https?:\/\/)([^\s]+)\s+(https:\/\/[^\s]*blob\.core\.windows\.net[^\s]*)/i,
    operation: 'azcopy sync',
    description: 'Azure Blob sync upload',
  },
  // az storage blob upload
  {
    pattern: /\baz\s+storage\s+blob\s+upload\s+[^|;]*(?:--file|-f)\s+([^\s]+)/i,
    operation: 'az storage blob upload',
    description: 'Azure CLI blob upload',
  },
  // az storage blob upload-batch
  {
    pattern: /\baz\s+storage\s+blob\s+upload-batch\s+[^|;]*(?:--source|-s)\s+([^\s]+)/i,
    operation: 'az storage blob upload-batch',
    description: 'Azure CLI batch upload',
  },
];

/**
 * Rclone upload patterns
 */
const RCLONE_UPLOAD_PATTERNS = [
  // rclone copy local remote:path
  {
    pattern: /\brclone\s+(?:copy|sync|move)\s+(?![\w-]+:)([^\s]+)\s+([\w-]+:[^\s]*)/i,
    operation: 'rclone',
    description: 'Rclone cloud upload',
  },
  // rclone copyto local remote:path
  {
    pattern: /\brclone\s+copyto\s+(?![\w-]+:)([^\s]+)\s+([\w-]+:[^\s]*)/i,
    operation: 'rclone copyto',
    description: 'Rclone cloud upload',
  },
];

/**
 * Other cloud upload patterns (DigitalOcean Spaces, Backblaze B2, etc.)
 */
const OTHER_CLOUD_PATTERNS = [
  // s3cmd put (S3-compatible)
  {
    pattern: /\bs3cmd\s+put\s+([^\s]+)\s+(s3:\/\/[^\s]+)/i,
    operation: 's3cmd put',
    description: 'S3-compatible upload',
  },
  // mc (MinIO client) cp
  {
    pattern: /\bmc\s+cp\s+(?![\w-]+\/)([^\s]+)\s+([\w-]+\/[^\s]+)/i,
    operation: 'mc cp',
    description: 'MinIO client upload',
  },
  // b2 upload-file (Backblaze B2)
  {
    pattern: /\bb2\s+(?:upload-file|upload_file)\s+([^\s]+)\s+([^\s]+)/i,
    operation: 'b2 upload',
    description: 'Backblaze B2 upload',
  },
];

/**
 * SDK/Code patterns for cloud uploads
 */
const CLOUD_SDK_PATTERNS = [
  // AWS SDK - S3 upload (Python boto3)
  {
    pattern: /\.upload_file\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*["'`]([^"'`]+)["'`]/i,
    operation: 'boto3 upload_file',
    description: 'AWS SDK upload',
  },
  // AWS SDK - S3 put_object
  {
    pattern: /\.put_object\s*\([^)]*Bucket\s*=\s*["'`]([^"'`]+)["'`]/i,
    operation: 'boto3 put_object',
    description: 'AWS SDK put_object',
  },
  // GCP SDK - upload_from_filename
  {
    pattern: /\.upload_from_filename\s*\(\s*["'`]([^"'`]+)["'`]/i,
    operation: 'gcp upload_from_filename',
    description: 'GCP SDK upload',
  },
  // Azure SDK - upload_blob
  {
    pattern: /\.upload_blob\s*\(/i,
    operation: 'azure upload_blob',
    description: 'Azure SDK upload',
  },
  // JavaScript AWS SDK - upload/putObject
  {
    pattern: /\b(?:s3|S3)\s*\.\s*(?:upload|putObject)\s*\(/i,
    operation: 'aws-sdk upload',
    description: 'AWS JavaScript SDK upload',
  },
];

/**
 * Match AWS S3 upload commands
 */
export function matchAwsS3Upload(command: string): CloudUploadMatchResult {
  for (const { pattern, operation } of AWS_S3_UPLOAD_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        provider: 'aws',
        operation,
        dataSource: match[1],
        destination: match[2],
        confidence: 0.95,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match GCP Storage upload commands
 */
export function matchGcpUpload(command: string): CloudUploadMatchResult {
  for (const { pattern, operation } of GCP_UPLOAD_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        provider: 'gcp',
        operation,
        dataSource: match[1],
        destination: match[2],
        confidence: 0.95,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match Azure Storage upload commands
 */
export function matchAzureUpload(command: string): CloudUploadMatchResult {
  for (const { pattern, operation } of AZURE_UPLOAD_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        provider: 'azure',
        operation,
        dataSource: match[1],
        destination: match[2] || 'Azure Blob Storage',
        confidence: 0.95,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match Rclone upload commands
 */
export function matchRcloneUpload(command: string): CloudUploadMatchResult {
  for (const { pattern, operation } of RCLONE_UPLOAD_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        provider: 'rclone',
        operation,
        dataSource: match[1],
        destination: match[2],
        confidence: 0.9,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match other cloud upload commands
 */
export function matchOtherCloudUpload(command: string): CloudUploadMatchResult {
  for (const { pattern, operation } of OTHER_CLOUD_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        provider: 's3-compatible',
        operation,
        dataSource: match[1],
        destination: match[2],
        confidence: 0.9,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match cloud SDK upload patterns in code
 */
export function matchCloudSdkUpload(code: string): CloudUploadMatchResult {
  for (const { pattern, operation } of CLOUD_SDK_PATTERNS) {
    const match = code.match(pattern);
    if (match) {
      let provider = 'unknown';
      if (operation.includes('boto3') || operation.includes('aws')) {
        provider = 'aws';
      } else if (operation.includes('gcp')) {
        provider = 'gcp';
      } else if (operation.includes('azure')) {
        provider = 'azure';
      }

      return {
        matched: true,
        command: code,
        provider,
        operation,
        dataSource: match[1] || undefined,
        destination: match[2] || undefined,
        confidence: 0.85,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Comprehensive cloud upload matching
 */
export function matchCloudUpload(text: string): CloudUploadMatchResult {
  // Try AWS S3
  const awsResult = matchAwsS3Upload(text);
  if (awsResult.matched) {
    return awsResult;
  }
  
  // Try GCP Storage
  const gcpResult = matchGcpUpload(text);
  if (gcpResult.matched) {
    return gcpResult;
  }
  
  // Try Azure Storage
  const azureResult = matchAzureUpload(text);
  if (azureResult.matched) {
    return azureResult;
  }
  
  // Try Rclone
  const rcloneResult = matchRcloneUpload(text);
  if (rcloneResult.matched) {
    return rcloneResult;
  }
  
  // Try other S3-compatible
  const otherResult = matchOtherCloudUpload(text);
  if (otherResult.matched) {
    return otherResult;
  }
  
  // Try SDK patterns
  const sdkResult = matchCloudSdkUpload(text);
  if (sdkResult.matched) {
    return sdkResult;
  }
  
  return { matched: false, confidence: 0 };
}

/**
 * Cloud upload detector class
 */
export class CloudUploadDetector implements SubDetector {
  private severity: Severity;
  private customPatterns: RegExp[];

  constructor(severity: Severity = "high", customPatterns: string[] = [], _logger?: any) {
    this.severity = severity;
    this.customPatterns = customPatterns.map(p => new RegExp(p, 'i'));
  }

  /**
   * Extract text content from tool context
   */
  private extractContent(context: DetectionContext): string | null {
    const input = context.toolInput;
    
    // Direct command field
    if (typeof input.command === 'string') {
      return input.command;
    }
    
    // Shell/bash command field
    if (typeof input.shell === 'string') {
      return input.shell;
    }
    
    if (typeof input.bash === 'string') {
      return input.bash;
    }
    
    // Script field
    if (typeof input.script === 'string') {
      return input.script;
    }
    
    // Code field
    if (typeof input.code === 'string') {
      return input.code;
    }
    
    // Text content
    if (typeof input.text === 'string') {
      return input.text;
    }
    
    // Content field
    if (typeof input.content === 'string') {
      return input.content;
    }
    
    // Body field
    if (typeof input.body === 'string') {
      return input.body;
    }
    
    return null;
  }

  detect(context: DetectionContext): ExfiltrationDetectionResult | null {
    const content = this.extractContent(context);
    if (!content) {
      return null;
    }

    // Check custom patterns FIRST (highest confidence)
    for (const pattern of this.customPatterns) {
      if (pattern.test(content)) {
        return {
          detected: true,
          category: 'exfiltration',
          severity: this.severity,
          confidence: 0.95,  // High confidence for explicit config patterns
          reason: `Matched custom exfiltration pattern: ${pattern.source}`,
          metadata: {
            method: 'cloud',
          },
        };
      }
    }

    // Then check hardcoded patterns
    const result = matchCloudUpload(content);
    
    if (!result.matched) {
      return null;
    }

    const providerNames: Record<string, string> = {
      aws: 'AWS S3',
      gcp: 'Google Cloud Storage',
      azure: 'Azure Blob Storage',
      rclone: 'Cloud (via rclone)',
      's3-compatible': 'S3-compatible storage',
      unknown: 'Cloud storage',
    };

    const providerName = providerNames[result.provider || 'unknown'] || result.provider;
    const destInfo = result.destination ? ` to ${result.destination}` : '';
    const srcInfo = result.dataSource ? ` (source: ${result.dataSource})` : '';

    return {
      detected: true,
      category: 'exfiltration',
      severity: this.severity,
      confidence: result.confidence,
      reason: `Cloud upload detected: ${result.operation} via ${providerName}${destInfo}${srcInfo}`,
      metadata: {
        method: 'cloud',
        destination: result.destination,
        dataSource: result.dataSource,
        command: result.command,
      },
    };
  }
}

/**
 * Create a cloud upload detector with the given severity
 */
export function createCloudUploadDetector(severity: Severity = "high", customPatterns: string[] = [], logger?: any): CloudUploadDetector {
  return new CloudUploadDetector(severity, customPatterns, logger);
}
