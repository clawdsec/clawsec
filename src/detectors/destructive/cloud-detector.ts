/**
 * Cloud Detector
 * Detects dangerous cloud operations including AWS, GCP, Azure, Kubernetes, and Terraform
 */

import type {
  CloudMatchResult,
  DetectionContext,
  DestructiveDetectionResult,
  SubDetector,
} from './types.js';
import type { Severity } from '../../config/index.js';
import { createLogger, type Logger } from '../../utils/logger.js';

/**
 * AWS destructive command patterns
 */
const AWS_PATTERNS = [
  // EC2 terminate instances
  { 
    pattern: /\baws\s+ec2\s+terminate-instances\b/i, 
    operation: 'terminate-instances',
    description: 'Terminate EC2 instances',
  },
  // S3 bucket removal
  { 
    pattern: /\baws\s+s3\s+rb\s+(?:--force\s+)?s3:\/\/([^\s]+)/i, 
    operation: 's3 rb',
    description: 'Remove S3 bucket',
  },
  { 
    pattern: /\baws\s+s3api\s+delete-bucket\b/i, 
    operation: 'delete-bucket',
    description: 'Delete S3 bucket',
  },
  // RDS delete
  { 
    pattern: /\baws\s+rds\s+delete-db-(?:instance|cluster)\b/i, 
    operation: 'delete-db',
    description: 'Delete RDS database',
  },
  // CloudFormation stack deletion
  { 
    pattern: /\baws\s+cloudformation\s+delete-stack\b/i, 
    operation: 'delete-stack',
    description: 'Delete CloudFormation stack',
  },
  // Lambda function deletion
  { 
    pattern: /\baws\s+lambda\s+delete-function\b/i, 
    operation: 'delete-function',
    description: 'Delete Lambda function',
  },
  // EKS cluster deletion
  { 
    pattern: /\baws\s+eks\s+delete-cluster\b/i, 
    operation: 'delete-cluster',
    description: 'Delete EKS cluster',
  },
  // IAM user/role deletion
  { 
    pattern: /\baws\s+iam\s+delete-(?:user|role)\b/i, 
    operation: 'delete-iam',
    description: 'Delete IAM user/role',
  },
  // VPC deletion
  { 
    pattern: /\baws\s+ec2\s+delete-vpc\b/i, 
    operation: 'delete-vpc',
    description: 'Delete VPC',
  },
  // DynamoDB table deletion
  { 
    pattern: /\baws\s+dynamodb\s+delete-table\b/i, 
    operation: 'delete-table',
    description: 'Delete DynamoDB table',
  },
];

/**
 * GCP destructive command patterns
 */
const GCP_PATTERNS = [
  // Compute instance deletion
  { 
    pattern: /\bgcloud\s+compute\s+instances\s+delete\b/i, 
    operation: 'instances delete',
    description: 'Delete GCP compute instances',
  },
  // Project deletion
  { 
    pattern: /\bgcloud\s+projects\s+delete\b/i, 
    operation: 'projects delete',
    description: 'Delete GCP project',
  },
  // GKE cluster deletion
  { 
    pattern: /\bgcloud\s+container\s+clusters\s+delete\b/i, 
    operation: 'clusters delete',
    description: 'Delete GKE cluster',
  },
  // Cloud SQL deletion
  { 
    pattern: /\bgcloud\s+sql\s+instances\s+delete\b/i, 
    operation: 'sql delete',
    description: 'Delete Cloud SQL instance',
  },
  // Cloud Functions deletion
  { 
    pattern: /\bgcloud\s+functions\s+delete\b/i, 
    operation: 'functions delete',
    description: 'Delete Cloud Function',
  },
  // Storage bucket deletion
  { 
    pattern: /\bgsutil\s+(?:-m\s+)?rm\s+-r\s+gs:\/\/([^\s]+)/i, 
    operation: 'gsutil rm -r',
    description: 'Remove GCS bucket recursively',
  },
  { 
    pattern: /\bgcloud\s+storage\s+(?:buckets\s+)?delete\b/i, 
    operation: 'storage delete',
    description: 'Delete GCS bucket',
  },
  // Pub/Sub deletion
  { 
    pattern: /\bgcloud\s+pubsub\s+(?:topics|subscriptions)\s+delete\b/i, 
    operation: 'pubsub delete',
    description: 'Delete Pub/Sub resource',
  },
];

/**
 * Azure destructive command patterns
 */
const AZURE_PATTERNS = [
  // VM deletion
  { 
    pattern: /\baz\s+vm\s+delete\b/i, 
    operation: 'vm delete',
    description: 'Delete Azure VM',
  },
  // Resource group deletion (VERY dangerous - deletes everything in group)
  { 
    pattern: /\baz\s+group\s+delete\b/i, 
    operation: 'group delete',
    description: 'Delete Azure resource group',
  },
  // Storage account deletion
  { 
    pattern: /\baz\s+storage\s+account\s+delete\b/i, 
    operation: 'storage delete',
    description: 'Delete Azure storage account',
  },
  // AKS cluster deletion
  { 
    pattern: /\baz\s+aks\s+delete\b/i, 
    operation: 'aks delete',
    description: 'Delete AKS cluster',
  },
  // SQL database deletion
  { 
    pattern: /\baz\s+sql\s+(?:db|server)\s+delete\b/i, 
    operation: 'sql delete',
    description: 'Delete Azure SQL resource',
  },
  // Function app deletion
  { 
    pattern: /\baz\s+functionapp\s+delete\b/i, 
    operation: 'functionapp delete',
    description: 'Delete Azure Function app',
  },
  // App Service deletion
  { 
    pattern: /\baz\s+webapp\s+delete\b/i, 
    operation: 'webapp delete',
    description: 'Delete Azure Web App',
  },
  // Container registry deletion
  { 
    pattern: /\baz\s+acr\s+delete\b/i, 
    operation: 'acr delete',
    description: 'Delete Azure Container Registry',
  },
];

/**
 * Kubernetes destructive command patterns
 */
const KUBERNETES_PATTERNS = [
  // Delete namespace (deletes everything in it)
  { 
    pattern: /\bkubectl\s+delete\s+(?:ns|namespace)\s+(\S+)/i, 
    operation: 'delete namespace',
    description: 'Delete Kubernetes namespace',
    critical: true,
  },
  // Delete all pods
  { 
    pattern: /\bkubectl\s+delete\s+pods?\s+--all\b/i, 
    operation: 'delete pods --all',
    description: 'Delete all pods',
    critical: true,
  },
  // Delete all resources of a type
  { 
    pattern: /\bkubectl\s+delete\s+\S+\s+--all\b/i, 
    operation: 'delete --all',
    description: 'Delete all resources',
  },
  // Delete with -A (all namespaces)
  { 
    pattern: /\bkubectl\s+delete\s+.*-A\b/i, 
    operation: 'delete -A',
    description: 'Delete across all namespaces',
  },
  // Delete deployment
  { 
    pattern: /\bkubectl\s+delete\s+(?:deploy|deployment)\s+(\S+)/i, 
    operation: 'delete deployment',
    description: 'Delete Kubernetes deployment',
  },
  // Delete service
  { 
    pattern: /\bkubectl\s+delete\s+(?:svc|service)\s+(\S+)/i, 
    operation: 'delete service',
    description: 'Delete Kubernetes service',
  },
  // Delete PVC
  { 
    pattern: /\bkubectl\s+delete\s+pvc\s+(\S+)/i, 
    operation: 'delete pvc',
    description: 'Delete persistent volume claim',
  },
  // Delete from file with force
  { 
    pattern: /\bkubectl\s+delete\s+-f\s+\S+\s+--force\b/i, 
    operation: 'delete -f --force',
    description: 'Force delete Kubernetes resources',
  },
  // Helm uninstall
  { 
    pattern: /\bhelm\s+(?:delete|uninstall)\s+(\S+)/i, 
    operation: 'helm uninstall',
    description: 'Uninstall Helm release',
  },
];

/**
 * Terraform destructive command patterns
 */
const TERRAFORM_PATTERNS = [
  // Terraform destroy
  { 
    pattern: /\bterraform\s+destroy\b/i, 
    operation: 'destroy',
    description: 'Destroy Terraform-managed infrastructure',
    critical: true,
  },
  // Terraform apply with auto-approve (can be destructive)
  { 
    pattern: /\bterraform\s+apply\s+.*-auto-approve\b/i, 
    operation: 'apply -auto-approve',
    description: 'Auto-approve Terraform changes',
  },
  // Terraform state rm
  { 
    pattern: /\bterraform\s+state\s+rm\b/i, 
    operation: 'state rm',
    description: 'Remove resource from Terraform state',
  },
  // Terragrunt destroy
  { 
    pattern: /\bterragrunt\s+destroy\b/i, 
    operation: 'terragrunt destroy',
    description: 'Destroy Terragrunt-managed infrastructure',
    critical: true,
  },
  // Pulumi destroy
  { 
    pattern: /\bpulumi\s+destroy\b/i, 
    operation: 'pulumi destroy',
    description: 'Destroy Pulumi-managed infrastructure',
    critical: true,
  },
];

/**
 * Git destructive command patterns
 */
const GIT_PATTERNS = [
  // Force push to main/master
  { 
    pattern: /\bgit\s+push\s+(?:--force|-f)\s+(?:\S+\s+)?(?:main|master)\b/i, 
    operation: 'push --force main/master',
    description: 'Force push to main/master branch',
    critical: true,
  },
  { 
    pattern: /\bgit\s+push\s+\S+\s+(?:main|master)\s+(?:--force|-f)\b/i, 
    operation: 'push --force main/master',
    description: 'Force push to main/master branch',
    critical: true,
  },
  // Git reset --hard
  { 
    pattern: /\bgit\s+reset\s+--hard\b/i, 
    operation: 'reset --hard',
    description: 'Hard reset discards local changes',
  },
  // Git clean -fd (force delete untracked)
  { 
    pattern: /\bgit\s+clean\s+(?:-[^\s]*)?-f(?:[^\s]*)?\s*(?:-d)?/i, 
    operation: 'clean -fd',
    description: 'Force delete untracked files',
  },
  // Git branch -D (force delete)
  { 
    pattern: /\bgit\s+branch\s+(?:-D|--delete\s+--force)\s+(\S+)/i, 
    operation: 'branch -D',
    description: 'Force delete branch',
  },
  // Git checkout . (discard changes)
  { 
    pattern: /\bgit\s+checkout\s+\.\s*$/i, 
    operation: 'checkout .',
    description: 'Discard all local changes',
  },
  // Git restore . (discard changes)
  { 
    pattern: /\bgit\s+restore\s+(?:--staged\s+)?\.\s*$/i, 
    operation: 'restore .',
    description: 'Discard all local changes',
  },
  // Git rebase with potential data loss
  { 
    pattern: /\bgit\s+rebase\s+(?:-i\s+)?(?:main|master|origin\/main|origin\/master)\b/i, 
    operation: 'rebase',
    description: 'Rebase onto main/master (can rewrite history)',
  },
];

/**
 * Match AWS commands
 */
export function matchAwsCommand(command: string): CloudMatchResult {
  for (const { pattern, operation } of AWS_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        provider: 'aws',
        operation,
        affectedResource: match[1] || undefined,
        confidence: 0.9,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match GCP commands
 */
export function matchGcpCommand(command: string): CloudMatchResult {
  for (const { pattern, operation } of GCP_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        provider: 'gcp',
        operation,
        affectedResource: match[1] || undefined,
        confidence: 0.9,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match Azure commands
 */
export function matchAzureCommand(command: string): CloudMatchResult {
  for (const { pattern, operation } of AZURE_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        provider: 'azure',
        operation,
        affectedResource: match[1] || undefined,
        confidence: 0.9,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match Kubernetes commands
 */
export function matchKubernetesCommand(command: string): CloudMatchResult {
  for (const { pattern, operation, critical } of KUBERNETES_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        provider: 'kubernetes',
        operation,
        affectedResource: match[1] || undefined,
        confidence: critical ? 0.95 : 0.85,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match Terraform/IaC commands
 */
export function matchTerraformCommand(command: string): CloudMatchResult {
  for (const { pattern, operation, critical } of TERRAFORM_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        provider: 'terraform',
        operation,
        affectedResource: match[1] || undefined,
        confidence: critical ? 0.95 : 0.85,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match Git destructive commands
 */
export function matchGitCommand(command: string): CloudMatchResult {
  for (const { pattern, operation, critical } of GIT_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        provider: 'git',
        operation,
        affectedResource: match[1] || undefined,
        confidence: critical ? 0.95 : 0.8,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Comprehensive cloud command matching
 */
export function matchCloudCommand(command: string): CloudMatchResult {
  // Try all cloud provider patterns
  const awsResult = matchAwsCommand(command);
  if (awsResult.matched) return awsResult;
  
  const gcpResult = matchGcpCommand(command);
  if (gcpResult.matched) return gcpResult;
  
  const azureResult = matchAzureCommand(command);
  if (azureResult.matched) return azureResult;
  
  const k8sResult = matchKubernetesCommand(command);
  if (k8sResult.matched) return k8sResult;
  
  const tfResult = matchTerraformCommand(command);
  if (tfResult.matched) return tfResult;
  
  const gitResult = matchGitCommand(command);
  if (gitResult.matched) return gitResult;
  
  return { matched: false, confidence: 0 };
}

/**
 * Cloud detector class
 */
export class CloudDetector implements SubDetector {
  private severity: Severity;
  private customPatterns: string[];
  private logger: Logger;

  constructor(severity: Severity = 'critical', customPatterns: string[] = [], logger?: Logger) {
    this.severity = severity;
    this.customPatterns = customPatterns;
    this.logger = logger ?? createLogger(null, null);
  }

  /**
   * Extract command from tool context
   */
  private extractCommand(context: DetectionContext): string | null {
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
    
    // CLI/args field
    if (typeof input.cli === 'string') {
      return input.cli;
    }
    
    if (typeof input.args === 'string') {
      return input.args;
    }
    
    // Text content
    if (typeof input.text === 'string') {
      return input.text;
    }
    
    // Content field
    if (typeof input.content === 'string') {
      return input.content;
    }
    
    return null;
  }

  /**
   * Match custom patterns against command
   */
  private matchCustomPatterns(command: string): CloudMatchResult {
    if (this.customPatterns.length === 0) {
      return { matched: false, confidence: 0 };
    }

    this.logger.debug(`[CloudDetector] Checking ${this.customPatterns.length} custom patterns`);

    for (const pattern of this.customPatterns) {
      try {
        const regex = new RegExp(pattern, 'i');
        if (regex.test(command)) {
          this.logger.info(`[CloudDetector] Custom pattern matched: ${pattern}`);
          return {
            matched: true,
            command,
            provider: 'custom',
            operation: 'custom-cloud-operation',
            confidence: 0.85,
          };
        }
      } catch (error) {
        this.logger.warn(`[CloudDetector] Invalid regex pattern skipped: "${pattern}" - ${error instanceof Error ? error.message : String(error)}`);
        continue;
      }
    }
    return { matched: false, confidence: 0 };
  }

  detect(context: DetectionContext): DestructiveDetectionResult | null {
    const command = this.extractCommand(context);
    if (!command) {
      return null;
    }

    // Try built-in patterns first
    let result = matchCloudCommand(command);

    // If no built-in match, try custom patterns
    if (!result.matched && this.customPatterns.length > 0) {
      result = this.matchCustomPatterns(command);
    }

    if (!result.matched) {
      return null;
    }

    // Determine the metadata type based on provider
    const metadataType = result.provider === 'git' ? 'git' : 'cloud';

    const providerDescriptions: Record<string, string> = {
      aws: 'AWS',
      gcp: 'Google Cloud',
      azure: 'Azure',
      kubernetes: 'Kubernetes',
      terraform: 'Terraform/IaC',
      git: 'Git',
      custom: 'Custom Cloud',
    };

    const providerDesc = providerDescriptions[result.provider || 'unknown'] || result.provider;

    return {
      detected: true,
      category: 'destructive',
      severity: this.severity,
      confidence: result.confidence,
      reason: `Dangerous ${providerDesc} operation detected: ${result.operation}`,
      metadata: {
        command: result.command,
        type: metadataType as 'cloud' | 'git',
        operation: result.operation,
        affectedResource: result.affectedResource,
      },
    };
  }
}

/**
 * Create a cloud detector with the given severity and custom patterns
 */
export function createCloudDetector(
  severity: Severity = 'critical',
  customPatterns: string[] = [],
  logger?: Logger
): CloudDetector {
  return new CloudDetector(severity, customPatterns, logger);
}
