/**
 * Code Detector
 * Detects dangerous code patterns for file/directory deletion across multiple languages
 */

import type {
  CodeMatchResult,
  DetectionContext,
  DestructiveDetectionResult,
  SubDetector,
} from './types.js';
import type { Severity } from '../../config/index.js';
import { createLogger, type Logger } from '../../utils/logger.js';

/**
 * Python destructive patterns
 */
const PYTHON_PATTERNS = [
  // shutil.rmtree
  { 
    pattern: /\bshutil\.rmtree\s*\(\s*(?:['"`]([^'"`]+)['"`]|(\w+))/i, 
    operation: 'shutil.rmtree',
    description: 'Recursive directory deletion',
  },
  // os.remove / os.unlink
  { 
    pattern: /\bos\.(?:remove|unlink)\s*\(\s*(?:['"`]([^'"`]+)['"`]|(\w+))/i, 
    operation: 'os.remove',
    description: 'File deletion',
  },
  // os.rmdir
  { 
    pattern: /\bos\.rmdir\s*\(\s*(?:['"`]([^'"`]+)['"`]|(\w+))/i, 
    operation: 'os.rmdir',
    description: 'Directory deletion',
  },
  // pathlib rmdir/unlink
  { 
    pattern: /\.rmdir\s*\(\s*\)/i, 
    operation: 'Path.rmdir',
    description: 'Directory deletion via pathlib',
  },
  { 
    pattern: /\.unlink\s*\(\s*(?:missing_ok\s*=\s*(?:True|False))?\s*\)/i, 
    operation: 'Path.unlink',
    description: 'File deletion via pathlib',
  },
  // os.removedirs
  { 
    pattern: /\bos\.removedirs\s*\(\s*(?:['"`]([^'"`]+)['"`]|(\w+))/i, 
    operation: 'os.removedirs',
    description: 'Recursive directory deletion',
  },
  // subprocess/os.system with rm
  { 
    pattern: /(?:subprocess\.(?:run|call|Popen)|os\.system)\s*\(\s*['"`].*\brm\s+-r/i, 
    operation: 'subprocess rm -r',
    description: 'Subprocess recursive deletion',
  },
];

/**
 * Node.js/JavaScript destructive patterns
 */
const NODEJS_PATTERNS = [
  // fs.rm with recursive
  { 
    pattern: /\bfs(?:Promises)?\.rm\s*\(\s*(?:['"`]([^'"`]+)['"`]|(\w+))\s*,\s*\{[^}]*recursive\s*:\s*true/i, 
    operation: 'fs.rm(recursive)',
    description: 'Recursive deletion',
  },
  // fs.rmdir with recursive (deprecated but still used)
  { 
    pattern: /\bfs(?:Promises)?\.rmdir\s*\(\s*(?:['"`]([^'"`]+)['"`]|(\w+))\s*,\s*\{[^}]*recursive\s*:\s*true/i, 
    operation: 'fs.rmdir(recursive)',
    description: 'Recursive directory deletion',
  },
  // fs.rmSync with recursive
  { 
    pattern: /\bfs\.rmSync\s*\(\s*(?:['"`]([^'"`]+)['"`]|(\w+))\s*,\s*\{[^}]*recursive\s*:\s*true/i, 
    operation: 'fs.rmSync(recursive)',
    description: 'Synchronous recursive deletion',
  },
  // fs.rmdirSync with recursive
  { 
    pattern: /\bfs\.rmdirSync\s*\(\s*(?:['"`]([^'"`]+)['"`]|(\w+))\s*,\s*\{[^}]*recursive\s*:\s*true/i, 
    operation: 'fs.rmdirSync(recursive)',
    description: 'Synchronous recursive directory deletion',
  },
  // fs.unlink / fs.unlinkSync
  { 
    pattern: /\bfs(?:Promises)?\.unlink(?:Sync)?\s*\(\s*(?:['"`]([^'"`]+)['"`]|(\w+))/i, 
    operation: 'fs.unlink',
    description: 'File deletion',
  },
  // rimraf
  { 
    pattern: /\brimraf(?:Sync)?\s*\(\s*(?:['"`]([^'"`]+)['"`]|(\w+))/i, 
    operation: 'rimraf',
    description: 'Recursive deletion (rimraf)',
  },
  // del / del-cli
  { 
    pattern: /\bdel(?:Sync)?\s*\(\s*\[?\s*['"`]([^'"`]+)['"`]/i, 
    operation: 'del',
    description: 'File/directory deletion (del)',
  },
  // fs-extra remove/emptyDir
  { 
    pattern: /\b(?:fs-extra|fse?)\.(?:remove|emptyDir)(?:Sync)?\s*\(\s*(?:['"`]([^'"`]+)['"`]|(\w+))/i, 
    operation: 'fs-extra.remove',
    description: 'Recursive deletion (fs-extra)',
  },
  // exec/spawn with rm
  { 
    pattern: /(?:exec|spawn)(?:Sync)?\s*\(\s*['"`].*\brm\s+-r/i, 
    operation: 'exec rm -r',
    description: 'Child process recursive deletion',
  },
];

/**
 * Go destructive patterns
 */
const GO_PATTERNS = [
  // os.RemoveAll
  { 
    pattern: /\bos\.RemoveAll\s*\(\s*(?:"([^"]+)"|(\w+))/i, 
    operation: 'os.RemoveAll',
    description: 'Recursive deletion',
  },
  // os.Remove
  { 
    pattern: /\bos\.Remove\s*\(\s*(?:"([^"]+)"|(\w+))/i, 
    operation: 'os.Remove',
    description: 'File/directory deletion',
  },
  // filepath.Walk + os.Remove pattern
  { 
    pattern: /filepath\.Walk.*os\.Remove/is, 
    operation: 'filepath.Walk + Remove',
    description: 'Walking deletion pattern',
  },
];

/**
 * Rust destructive patterns
 */
const RUST_PATTERNS = [
  // std::fs::remove_dir_all
  { 
    pattern: /\bstd::fs::remove_dir_all\s*\(\s*(?:"([^"]+)"|(\w+))/i, 
    operation: 'remove_dir_all',
    description: 'Recursive directory deletion',
  },
  { 
    pattern: /\bfs::remove_dir_all\s*\(\s*(?:"([^"]+)"|(\w+))/i, 
    operation: 'remove_dir_all',
    description: 'Recursive directory deletion',
  },
  // std::fs::remove_file
  { 
    pattern: /\bstd::fs::remove_file\s*\(\s*(?:"([^"]+)"|(\w+))/i, 
    operation: 'remove_file',
    description: 'File deletion',
  },
  { 
    pattern: /\bfs::remove_file\s*\(\s*(?:"([^"]+)"|(\w+))/i, 
    operation: 'remove_file',
    description: 'File deletion',
  },
  // std::fs::remove_dir
  { 
    pattern: /\bstd::fs::remove_dir\s*\(\s*(?:"([^"]+)"|(\w+))/i, 
    operation: 'remove_dir',
    description: 'Directory deletion',
  },
  { 
    pattern: /\bfs::remove_dir\s*\(\s*(?:"([^"]+)"|(\w+))/i, 
    operation: 'remove_dir',
    description: 'Directory deletion',
  },
];

/**
 * Ruby destructive patterns
 */
const RUBY_PATTERNS = [
  // FileUtils.rm_rf
  { 
    pattern: /\bFileUtils\.rm_rf\s*\(?['"`]?([^'"`\s,)]+)/i, 
    operation: 'FileUtils.rm_rf',
    description: 'Recursive force deletion',
  },
  // FileUtils.rm_r
  { 
    pattern: /\bFileUtils\.rm_r\s*\(?['"`]?([^'"`\s,)]+)/i, 
    operation: 'FileUtils.rm_r',
    description: 'Recursive deletion',
  },
  // FileUtils.remove_entry
  { 
    pattern: /\bFileUtils\.remove_entry(?:_secure)?\s*\(?['"`]?([^'"`\s,)]+)/i, 
    operation: 'FileUtils.remove_entry',
    description: 'Entry removal',
  },
  // File.delete
  { 
    pattern: /\bFile\.delete\s*\(?['"`]?([^'"`\s,)]+)/i, 
    operation: 'File.delete',
    description: 'File deletion',
  },
  // Dir.rmdir
  { 
    pattern: /\bDir\.rmdir\s*\(?['"`]?([^'"`\s,)]+)/i, 
    operation: 'Dir.rmdir',
    description: 'Directory deletion',
  },
];

/**
 * Java/Kotlin destructive patterns
 */
const JAVA_PATTERNS = [
  // Files.delete / Files.deleteIfExists
  { 
    pattern: /\bFiles\.delete(?:IfExists)?\s*\(\s*(?:Paths\.get\s*\(\s*)?["']?([^"')\s]+)/i, 
    operation: 'Files.delete',
    description: 'File/directory deletion',
  },
  // FileUtils.deleteDirectory (Apache Commons)
  { 
    pattern: /\bFileUtils\.(?:deleteDirectory|deleteQuietly|forceDelete)\s*\(\s*(?:new\s+File\s*\(\s*)?["']?([^"')\s]+)/i, 
    operation: 'FileUtils.deleteDirectory',
    description: 'Recursive directory deletion',
  },
  // file.delete()
  { 
    pattern: /\.delete\s*\(\s*\)/i, 
    operation: 'File.delete()',
    description: 'File deletion',
  },
  // Files.walk + delete pattern
  { 
    pattern: /Files\.walk.*\.delete/is, 
    operation: 'Files.walk + delete',
    description: 'Walking deletion pattern',
  },
];

/**
 * C# destructive patterns
 */
const CSHARP_PATTERNS = [
  // Directory.Delete with recursive
  { 
    pattern: /\bDirectory\.Delete\s*\(\s*(?:@)?["']([^"']+)["']\s*,\s*true/i, 
    operation: 'Directory.Delete(recursive)',
    description: 'Recursive directory deletion',
  },
  // File.Delete
  { 
    pattern: /\bFile\.Delete\s*\(\s*(?:@)?["']([^"']+)/i, 
    operation: 'File.Delete',
    description: 'File deletion',
  },
  // DirectoryInfo.Delete
  { 
    pattern: /\.Delete\s*\(\s*true\s*\)/i, 
    operation: 'DirectoryInfo.Delete(recursive)',
    description: 'Recursive deletion via DirectoryInfo',
  },
];

/**
 * PHP destructive patterns
 */
const PHP_PATTERNS = [
  // unlink
  { 
    pattern: /\bunlink\s*\(\s*(?:\$\w+|['"`]([^'"`]+))/i, 
    operation: 'unlink',
    description: 'File deletion',
  },
  // rmdir
  { 
    pattern: /\brmdir\s*\(\s*(?:\$\w+|['"`]([^'"`]+))/i, 
    operation: 'rmdir',
    description: 'Directory deletion',
  },
  // array_map + unlink pattern (recursive deletion)
  { 
    pattern: /array_map\s*\(\s*['"`]unlink['"`]/i, 
    operation: 'array_map unlink',
    description: 'Batch file deletion',
  },
  // RecursiveIterator + unlink/rmdir
  { 
    pattern: /RecursiveIteratorIterator.*(?:unlink|rmdir)/is, 
    operation: 'recursive unlink',
    description: 'Recursive deletion',
  },
];

/**
 * Match Python code patterns
 */
export function matchPythonCode(code: string): CodeMatchResult {
  for (const { pattern, operation } of PYTHON_PATTERNS) {
    const match = code.match(pattern);
    if (match) {
      return {
        matched: true,
        code,
        language: 'python',
        operation,
        affectedResource: match[1] || match[2] || undefined,
        confidence: operation.includes('rmtree') || operation.includes('removedirs') ? 0.9 : 0.8,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match Node.js code patterns
 */
export function matchNodeCode(code: string): CodeMatchResult {
  for (const { pattern, operation } of NODEJS_PATTERNS) {
    const match = code.match(pattern);
    if (match) {
      return {
        matched: true,
        code,
        language: 'javascript',
        operation,
        affectedResource: match[1] || match[2] || undefined,
        confidence: operation.includes('recursive') || operation === 'rimraf' ? 0.9 : 0.8,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match Go code patterns
 */
export function matchGoCode(code: string): CodeMatchResult {
  for (const { pattern, operation } of GO_PATTERNS) {
    const match = code.match(pattern);
    if (match) {
      return {
        matched: true,
        code,
        language: 'go',
        operation,
        affectedResource: match[1] || match[2] || undefined,
        confidence: operation === 'os.RemoveAll' ? 0.9 : 0.8,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match Rust code patterns
 */
export function matchRustCode(code: string): CodeMatchResult {
  for (const { pattern, operation } of RUST_PATTERNS) {
    const match = code.match(pattern);
    if (match) {
      return {
        matched: true,
        code,
        language: 'rust',
        operation,
        affectedResource: match[1] || match[2] || undefined,
        confidence: operation === 'remove_dir_all' ? 0.9 : 0.8,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match Ruby code patterns
 */
export function matchRubyCode(code: string): CodeMatchResult {
  for (const { pattern, operation } of RUBY_PATTERNS) {
    const match = code.match(pattern);
    if (match) {
      return {
        matched: true,
        code,
        language: 'ruby',
        operation,
        affectedResource: match[1] || undefined,
        confidence: operation.includes('rm_rf') || operation.includes('rm_r') ? 0.9 : 0.8,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match Java/Kotlin code patterns
 */
export function matchJavaCode(code: string): CodeMatchResult {
  for (const { pattern, operation } of JAVA_PATTERNS) {
    const match = code.match(pattern);
    if (match) {
      return {
        matched: true,
        code,
        language: 'java',
        operation,
        affectedResource: match[1] || undefined,
        confidence: operation.includes('Directory') || operation.includes('walk') ? 0.9 : 0.75,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match C# code patterns
 */
export function matchCSharpCode(code: string): CodeMatchResult {
  for (const { pattern, operation } of CSHARP_PATTERNS) {
    const match = code.match(pattern);
    if (match) {
      return {
        matched: true,
        code,
        language: 'csharp',
        operation,
        affectedResource: match[1] || undefined,
        confidence: operation.includes('recursive') ? 0.9 : 0.8,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match PHP code patterns
 */
export function matchPhpCode(code: string): CodeMatchResult {
  for (const { pattern, operation } of PHP_PATTERNS) {
    const match = code.match(pattern);
    if (match) {
      return {
        matched: true,
        code,
        language: 'php',
        operation,
        affectedResource: match[1] || undefined,
        confidence: operation.includes('recursive') || operation.includes('array_map') ? 0.85 : 0.8,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Comprehensive code pattern matching
 */
export function matchCodePattern(code: string): CodeMatchResult {
  // Try all language patterns
  const pythonResult = matchPythonCode(code);
  if (pythonResult.matched) return pythonResult;
  
  const nodeResult = matchNodeCode(code);
  if (nodeResult.matched) return nodeResult;
  
  const goResult = matchGoCode(code);
  if (goResult.matched) return goResult;
  
  const rustResult = matchRustCode(code);
  if (rustResult.matched) return rustResult;
  
  const rubyResult = matchRubyCode(code);
  if (rubyResult.matched) return rubyResult;
  
  const javaResult = matchJavaCode(code);
  if (javaResult.matched) return javaResult;
  
  const csharpResult = matchCSharpCode(code);
  if (csharpResult.matched) return csharpResult;
  
  const phpResult = matchPhpCode(code);
  if (phpResult.matched) return phpResult;
  
  return { matched: false, confidence: 0 };
}

/**
 * Code detector class
 */
export class CodeDetector implements SubDetector {
  private severity: Severity;
  private customPatterns: string[];
  private logger: Logger;

  constructor(severity: Severity = 'critical', customPatterns?: string[], logger?: Logger) {
    this.severity = severity;
    this.customPatterns = customPatterns || [];
    this.logger = logger ?? createLogger(null, null);
  }

  /**
   * Extract code from tool context
   */
  private extractCode(context: DetectionContext): string | null {
    const input = context.toolInput;
    
    // Direct code field
    if (typeof input.code === 'string') {
      return input.code;
    }
    
    // Script field
    if (typeof input.script === 'string') {
      return input.script;
    }
    
    // Content field (for file writes)
    if (typeof input.content === 'string') {
      return input.content;
    }
    
    // Source field
    if (typeof input.source === 'string') {
      return input.source;
    }
    
    // Body field (for requests)
    if (typeof input.body === 'string') {
      return input.body;
    }
    
    // Text field
    if (typeof input.text === 'string') {
      return input.text;
    }
    
    // New source for replacements
    if (typeof input.new_source === 'string') {
      return input.new_source;
    }
    
    // Function field (for eval)
    if (typeof input.function === 'string') {
      return input.function;
    }
    
    return null;
  }

  /**
   * Match custom patterns against code
   */
  private matchCustomPatterns(code: string): CodeMatchResult {
    if (this.customPatterns.length === 0) {
      return { matched: false, confidence: 0 };
    }

    this.logger.debug(`[CodeDetector] Checking ${this.customPatterns.length} custom patterns`);

    for (const pattern of this.customPatterns) {
      try {
        const regex = new RegExp(pattern, 'i');
        if (regex.test(code)) {
          this.logger.info(`[CodeDetector] Custom pattern matched: ${pattern}`);
          return {
            matched: true,
            code,
            language: 'custom',
            operation: 'custom-code-operation',
            confidence: 0.85,
          };
        }
      } catch (error) {
        this.logger.warn(`[CodeDetector] Invalid regex pattern skipped: "${pattern}" - ${error instanceof Error ? error.message : String(error)}`);
        continue;
      }
    }
    return { matched: false, confidence: 0 };
  }

  detect(context: DetectionContext): DestructiveDetectionResult | null {
    const code = this.extractCode(context);
    if (!code) {
      return null;
    }

    // Try built-in patterns first
    let result = matchCodePattern(code);

    // If no built-in match, try custom patterns
    if (!result.matched && this.customPatterns.length > 0) {
      result = this.matchCustomPatterns(code);
    }

    if (!result.matched) {
      return null;
    }

    const languageNames: Record<string, string> = {
      python: 'Python',
      javascript: 'JavaScript/Node.js',
      go: 'Go',
      rust: 'Rust',
      ruby: 'Ruby',
      java: 'Java/Kotlin',
      csharp: 'C#',
      php: 'PHP',
    };

    const langName = languageNames[result.language || 'unknown'] || result.language;

    return {
      detected: true,
      category: 'destructive',
      severity: this.severity,
      confidence: result.confidence,
      reason: `Dangerous ${langName} file deletion operation detected: ${result.operation}`,
      metadata: {
        command: result.code,
        type: 'code',
        operation: result.operation,
        affectedResource: result.affectedResource,
      },
    };
  }
}

/**
 * Create a code detector with the given severity
 */
export function createCodeDetector(severity: Severity = 'critical', customPatterns?: string[], logger?: Logger): CodeDetector {
  return new CodeDetector(severity, customPatterns, logger);
}
