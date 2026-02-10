/**
 * Shell Detector
 * Detects dangerous shell commands including file deletion, SQL operations, and system commands
 */

import type {
  ShellMatchResult,
  DetectionContext,
  DestructiveDetectionResult,
  SubDetector,
} from './types.js';
import type { Severity } from '../../config/index.js';
import { createLogger, type Logger } from '../../utils/logger.js';

/**
 * Dangerous paths that should never be deleted recursively
 */
const DANGEROUS_PATHS = [
  '/',
  '/home',
  '/etc',
  '/var',
  '/usr',
  '/bin',
  '/sbin',
  '/lib',
  '/lib64',
  '/boot',
  '/root',
  '/sys',
  '/proc',
  '/dev',
  '~',
  '$HOME',
  '%USERPROFILE%',
  'C:\\',
  'C:\\Windows',
  'C:\\Program Files',
];

/**
 * Patterns for rm commands with recursive/force flags
 */
const RM_DANGEROUS_PATTERNS = [
  // rm with -rf, -r -f, -fr flags
  /\brm\s+(?:-[rRfvP]+\s+)*(?:-[rR][^\s]*|-[^\s]*[rR])\s*(?:-[^\s]+\s+)*(\S+)/i,
  // rm -r or rm -R alone
  /\brm\s+(?:-[^\s]+\s+)*-[rR]\s+(\S+)/i,
  // rm -f (force) which can be dangerous
  /\brm\s+(?:-[^\s]+\s+)*-[fF]\s+(\S+)/i,
];

/**
 * SQL destructive operations
 */
const SQL_PATTERNS = [
  // DROP DATABASE
  { pattern: /\bDROP\s+DATABASE\s+(?:IF\s+EXISTS\s+)?[`"']?(\w+)[`"']?/i, operation: 'DROP DATABASE', critical: true },
  // DROP TABLE
  { pattern: /\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?[`"']?(\w+)[`"']?/i, operation: 'DROP TABLE', critical: true },
  // TRUNCATE TABLE
  { pattern: /\bTRUNCATE\s+(?:TABLE\s+)?[`"']?(\w+)[`"']?/i, operation: 'TRUNCATE TABLE', critical: true },
  // DELETE FROM without WHERE (dangerous)
  { pattern: /\bDELETE\s+FROM\s+[`"']?(\w+)[`"']?\s*(?:;|$)/i, operation: 'DELETE FROM (no WHERE)', critical: true },
  // DROP SCHEMA
  { pattern: /\bDROP\s+SCHEMA\s+(?:IF\s+EXISTS\s+)?[`"']?(\w+)[`"']?/i, operation: 'DROP SCHEMA', critical: true },
];

/**
 * System destructive commands
 */
const SYSTEM_DESTRUCTIVE_PATTERNS = [
  // mkfs - format filesystem
  { pattern: /\bmkfs(?:\.\w+)?\s+(\S+)/i, operation: 'mkfs', description: 'Format filesystem' },
  // dd writing to block device
  { pattern: /\bdd\s+.*\bof=\s*\/dev\/(\S+)/i, operation: 'dd to device', description: 'Write to block device' },
  // chmod 777 (world-writable) on dangerous paths
  { pattern: /\bchmod\s+(?:-[rR]\s+)?777\s+(\S+)/i, operation: 'chmod 777', description: 'Set world-writable permissions' },
  // Fork bomb patterns
  { pattern: /:\(\)\s*\{\s*:\|:&\s*\}\s*;?\s*:/i, operation: 'fork bomb', description: 'Fork bomb detected' },
  { pattern: /\bforkbomb\b/i, operation: 'fork bomb', description: 'Fork bomb detected' },
  // shred - secure delete
  { pattern: /\bshred\s+(?:-[^\s]+\s+)*(\S+)/i, operation: 'shred', description: 'Secure file deletion' },
  // Overwrite with /dev/null or /dev/zero
  { pattern: /\bcat\s+\/dev\/(?:null|zero)\s*>\s*(\S+)/i, operation: 'overwrite file', description: 'Overwrite file with null/zero' },
  // wipefs
  { pattern: /\bwipefs\s+(?:-[^\s]+\s+)*(\S+)/i, operation: 'wipefs', description: 'Wipe filesystem signatures' },
];

/**
 * Check if a path is dangerous for recursive deletion
 */
export function isDangerousPath(path: string): boolean {
  // Normalize path - keep the leading slash, remove trailing slashes
  const trimmed = path.trim();
  
  // Handle root path explicitly
  if (trimmed === '/' || trimmed === '//' || trimmed === '///') {
    return true;
  }
  
  // Remove trailing slashes for comparison (but not leading)
  const normalizedPath = trimmed.replace(/\/+$/, '').toLowerCase();
  
  // Check exact matches
  for (const dangerous of DANGEROUS_PATHS) {
    const dangerousLower = dangerous.toLowerCase().replace(/\/+$/, '');
    if (normalizedPath === dangerousLower) {
      return true;
    }
  }
  
  // Check if path is just a wildcard or root-level wildcard
  if (normalizedPath === '*' || normalizedPath === '/*' || normalizedPath === '.*') {
    return true;
  }
  
  // Check for home directory patterns
  if (/^~\/?$/.test(trimmed) || /^~\/?\*$/.test(trimmed) || /^\$HOME\/?$/i.test(trimmed) || /^\$HOME\/?\*$/i.test(trimmed)) {
    return true;
  }
  
  return false;
}

/**
 * Match rm commands for dangerous operations
 */
export function matchRmCommand(command: string): ShellMatchResult {
  const commandLower = command.toLowerCase();
  
  // Quick check for rm command
  if (!commandLower.includes('rm ') && !commandLower.includes('rm\t')) {
    return { matched: false, confidence: 0 };
  }
  
  // Check for recursive/force flags
  const hasRecursive = /-[rR]/.test(command) || /-[^\s]*[rR]/.test(command);
  const hasForce = /-[fF]/.test(command) || /-[^\s]*[fF]/.test(command);
  
  // Extract the target path(s)
  for (const pattern of RM_DANGEROUS_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      const targetPath = match[1];
      
      // Check if path is dangerous
      if (isDangerousPath(targetPath)) {
        return {
          matched: true,
          command,
          operation: hasRecursive && hasForce ? 'rm -rf' : (hasRecursive ? 'rm -r' : 'rm -f'),
          affectedResource: targetPath,
          confidence: 0.95,
          riskDescription: `Attempting to delete critical system path: ${targetPath}`,
        };
      }
      
      // Even if not a dangerous path, rm -rf is risky
      if (hasRecursive && hasForce) {
        return {
          matched: true,
          command,
          operation: 'rm -rf',
          affectedResource: targetPath,
          confidence: 0.85,
          riskDescription: `Recursive force deletion of: ${targetPath}`,
        };
      }
      
      // rm -r alone is still risky
      if (hasRecursive) {
        return {
          matched: true,
          command,
          operation: 'rm -r',
          affectedResource: targetPath,
          confidence: 0.75,
          riskDescription: `Recursive deletion of: ${targetPath}`,
        };
      }
    }
  }
  
  return { matched: false, confidence: 0 };
}

/**
 * Match SQL destructive operations
 */
export function matchSqlCommand(text: string): ShellMatchResult {
  for (const { pattern, operation, critical } of SQL_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      return {
        matched: true,
        command: text,
        operation,
        affectedResource: match[1],
        confidence: critical ? 0.95 : 0.85,
        riskDescription: `SQL ${operation} operation on: ${match[1]}`,
      };
    }
  }
  
  return { matched: false, confidence: 0 };
}

/**
 * Match system destructive commands
 */
export function matchSystemCommand(command: string): ShellMatchResult {
  for (const { pattern, operation, description } of SYSTEM_DESTRUCTIVE_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        operation,
        affectedResource: match[1] || undefined,
        confidence: 0.9,
        riskDescription: description,
      };
    }
  }
  
  return { matched: false, confidence: 0 };
}

/**
 * Comprehensive shell command matching
 */
export function matchShellCommand(command: string): ShellMatchResult {
  // Try rm command matching first
  const rmResult = matchRmCommand(command);
  if (rmResult.matched) {
    return rmResult;
  }
  
  // Try SQL matching
  const sqlResult = matchSqlCommand(command);
  if (sqlResult.matched) {
    return sqlResult;
  }
  
  // Try system command matching
  const systemResult = matchSystemCommand(command);
  if (systemResult.matched) {
    return systemResult;
  }
  
  return { matched: false, confidence: 0 };
}

/**
 * Shell detector class
 */
export class ShellDetector implements SubDetector {
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
    
    // Code field (might contain shell commands)
    if (typeof input.code === 'string') {
      return input.code;
    }
    
    // Query field (for SQL)
    if (typeof input.query === 'string') {
      return input.query;
    }
    
    // SQL field
    if (typeof input.sql === 'string') {
      return input.sql;
    }
    
    // Statement field
    if (typeof input.statement === 'string') {
      return input.statement;
    }
    
    // Text content that might contain commands
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
  private matchCustomPatterns(command: string): ShellMatchResult {
    if (this.customPatterns.length === 0) {
      return { matched: false, confidence: 0 };
    }

    this.logger.debug(`[ShellDetector] Checking ${this.customPatterns.length} custom patterns`);

    for (const pattern of this.customPatterns) {
      try {
        const regex = new RegExp(pattern, 'i');
        if (regex.test(command)) {
          this.logger.info(`[ShellDetector] Custom pattern matched: ${pattern}`);
          return {
            matched: true,
            command,
            operation: 'custom-shell-command',
            confidence: 0.85,
            riskDescription: `Custom shell pattern matched: ${pattern}`,
          };
        }
      } catch (error) {
        this.logger.warn(`[ShellDetector] Invalid regex pattern skipped: "${pattern}" - ${error instanceof Error ? error.message : String(error)}`);
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
    let result = matchShellCommand(command);

    // If no built-in match, try custom patterns
    if (!result.matched && this.customPatterns.length > 0) {
      result = this.matchCustomPatterns(command);
    }

    if (!result.matched) {
      return null;
    }

    return {
      detected: true,
      category: 'destructive',
      severity: this.severity,
      confidence: result.confidence,
      reason: result.riskDescription || `Dangerous shell operation detected: ${result.operation}`,
      metadata: {
        command: result.command,
        type: 'shell',
        operation: result.operation,
        affectedResource: result.affectedResource,
      },
    };
  }
}

/**
 * Create a shell detector with the given severity and custom patterns
 */
export function createShellDetector(
  severity: Severity = 'critical',
  customPatterns: string[] = [],
  logger?: Logger
): ShellDetector {
  return new ShellDetector(severity, customPatterns, logger);
}
