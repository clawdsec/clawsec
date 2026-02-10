/**
 * HTTP Exfiltration Detector
 * Detects HTTP POST/PUT requests that send data to external destinations
 */

import type {
  HttpMatchResult,
  DetectionContext,
  ExfiltrationDetectionResult,
  SubDetector,
} from './types.js';
import type { Severity } from '../../config/index.js';

/**
 * curl patterns for sending data via POST/PUT
 */
const CURL_POST_PATTERNS = [
  // curl -X PUT with data (check PUT first to avoid POST matching)
  {
    pattern: /\bcurl\s+(?:[^|;]+\s+)?(?:-X\s+PUT|-X\s*=?\s*PUT|--request\s+PUT|--request\s*=\s*PUT)\s+(?:[^|;]+\s+)?(?:-d|--data|--data-binary|--data-raw|--data-urlencode|-F|--form)\s+(?:["']?)([^"'\s][^|;]*)/i,
    method: 'PUT',
    description: 'curl PUT with data',
  },
  // curl -X POST with data flags
  {
    pattern: /\bcurl\s+(?:[^|;]+\s+)?(?:-X\s+POST|-X\s*=?\s*POST|--request\s+POST|--request\s*=\s*POST)\s+(?:[^|;]+\s+)?(?:-d|--data|--data-binary|--data-raw|--data-urlencode|-F|--form)\s+(?:["']?)([^"'\s][^|;]*)/i,
    method: 'POST',
    description: 'curl POST with data',
  },
  // curl with data flags (POST is implicit) - but NOT if -X PUT is present
  {
    pattern: /\bcurl\s+(?!.*-X\s+PUT)(?:[^|;]+\s+)?(?:-d|--data|--data-binary|--data-raw|--data-urlencode)\s+(?:["']?)([^"'\s][^|;]*)/i,
    method: 'POST',
    description: 'curl with data (implicit POST)',
  },
  // curl with -T (upload file)
  {
    pattern: /\bcurl\s+(?:[^|;]+\s+)?(?:-T|--upload-file)\s+(?:["']?)([^\s"']+)/i,
    method: 'PUT',
    description: 'curl file upload',
  },
  // curl with form file upload
  {
    pattern: /\bcurl\s+(?:[^|;]+\s+)?(?:-F|--form)\s+(?:["']?)([^"'\s]*@[^\s"';|]+)/i,
    method: 'POST',
    description: 'curl form file upload',
  },
];

/**
 * wget patterns for sending data
 */
const WGET_POST_PATTERNS = [
  // wget --post-data
  {
    pattern: /\bwget\s+(?:[^|;]+\s+)?(?:--post-data)\s*=?\s*(?:["']?)([^"'\s][^|;]*)/i,
    method: 'POST',
    description: 'wget POST with data',
  },
  // wget --post-file
  {
    pattern: /\bwget\s+(?:[^|;]+\s+)?(?:--post-file)\s*=?\s*(?:["']?)([^\s"']+)/i,
    method: 'POST',
    description: 'wget POST file',
  },
];

/**
 * httpie patterns (http/https commands)
 */
const HTTPIE_PATTERNS = [
  // http POST with data
  {
    pattern: /\bhttps?\s+POST\s+(\S+)\s+.*(?:=|:=|@)/i,
    method: 'POST',
    description: 'httpie POST with data',
  },
  // http PUT with data
  {
    pattern: /\bhttps?\s+PUT\s+(\S+)\s+.*(?:=|:=|@)/i,
    method: 'PUT',
    description: 'httpie PUT with data',
  },
];

/**
 * Code patterns for HTTP exfiltration (fetch, axios, requests, etc.)
 */
const CODE_HTTP_PATTERNS = [
  // JavaScript fetch with POST/PUT
  {
    pattern: /\bfetch\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*\{[^}]*method\s*:\s*["'`](POST|PUT)["'`][^}]*body\s*:/i,
    method: 'POST',
    description: 'fetch with POST/PUT and body',
  },
  {
    pattern: /\bfetch\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*\{[^}]*body\s*:[^}]*method\s*:\s*["'`](POST|PUT)["'`]/i,
    method: 'POST',
    description: 'fetch with body and POST/PUT',
  },
  // axios.post/put
  {
    pattern: /\baxios\s*\.\s*(post|put)\s*\(\s*["'`]([^"'`]+)["'`]/i,
    method: 'POST',
    description: 'axios POST/PUT',
  },
  // Python requests.post/put
  {
    pattern: /\brequests\s*\.\s*(post|put)\s*\(\s*["'`]([^"'`]+)["'`]/i,
    method: 'POST',
    description: 'Python requests POST/PUT',
  },
  // Python httpx.post/put
  {
    pattern: /\bhttpx\s*\.\s*(post|put)\s*\(\s*["'`]([^"'`]+)["'`]/i,
    method: 'POST',
    description: 'Python httpx POST/PUT',
  },
  // Python urllib with POST data
  {
    pattern: /\burllib\s*\.\s*request\s*\.\s*urlopen\s*\([^)]*data\s*=/i,
    method: 'POST',
    description: 'Python urllib with POST data',
  },
  // Node.js http.request with POST
  {
    pattern: /\bhttp[s]?\s*\.\s*request\s*\([^)]*method\s*:\s*["'`](POST|PUT)["'`]/i,
    method: 'POST',
    description: 'Node http.request POST',
  },
  // Ruby Net::HTTP.post/put
  {
    pattern: /\bNet::HTTP\s*\.\s*(post|put|post_form)\s*\(/i,
    method: 'POST',
    description: 'Ruby Net::HTTP POST',
  },
  // Go http.Post/PostForm
  {
    pattern: /\bhttp\s*\.\s*(Post|PostForm|NewRequest\s*\([^)]*"(POST|PUT)")/i,
    method: 'POST',
    description: 'Go http POST',
  },
  // PowerShell Invoke-WebRequest/RestMethod with POST
  {
    pattern: /\bInvoke-(?:WebRequest|RestMethod)\s+(?:[^|;]+\s+)?-Method\s+(POST|PUT)\s+(?:[^|;]+\s+)?-Body\s+/i,
    method: 'POST',
    description: 'PowerShell POST with body',
  },
];

/**
 * Encoded exfiltration patterns (piping encoded data to HTTP tools)
 */
const ENCODED_EXFIL_PATTERNS = [
  // base64 | curl
  {
    pattern: /\bbase64\s+(?:[^|]+)?\|\s*curl\b/i,
    method: 'POST',
    description: 'base64 encoded data to curl',
  },
  // gzip/compress | curl
  {
    pattern: /\b(?:gzip|bzip2|xz|compress|tar)\s+(?:[^|]+)?\|\s*curl\b/i,
    method: 'POST',
    description: 'compressed data to curl',
  },
  // openssl enc | curl
  {
    pattern: /\bopenssl\s+enc\s+(?:[^|]+)?\|\s*curl\b/i,
    method: 'POST',
    description: 'encrypted data to curl',
  },
  // xxd/hexdump | curl
  {
    pattern: /\b(?:xxd|hexdump|od)\s+(?:[^|]+)?\|\s*curl\b/i,
    method: 'POST',
    description: 'hex encoded data to curl',
  },
  // Any pipe to curl with POST
  {
    pattern: /\|\s*curl\s+(?:[^|;]+\s+)?(?:-X\s+POST|--data|--data-binary|-d)/i,
    method: 'POST',
    description: 'piped data to curl POST',
  },
];

/**
 * Extract URL from curl/wget command
 */
function extractUrl(command: string): string | undefined {
  // Try to find URL in the command
  const urlPatterns = [
    /\bhttps?:\/\/[^\s"'<>]+/i,
    /\bftp:\/\/[^\s"'<>]+/i,
  ];
  
  for (const pattern of urlPatterns) {
    const match = command.match(pattern);
    if (match) {
      return match[0];
    }
  }
  
  return undefined;
}

/**
 * Extract data source from command
 */
function extractDataSource(command: string): string | undefined {
  // Look for file references
  const filePatterns = [
    /-d\s*@([^\s"']+)/i,           // curl -d @file
    /--data-binary\s*@([^\s"']+)/i, // curl --data-binary @file
    /-F\s*[^@]*@([^\s"';]+)/i,      // curl -F file=@path
    /-T\s*([^\s"']+)/i,             // curl -T file
    /--post-file\s*=?\s*([^\s"']+)/i, // wget --post-file
    /--upload-file\s*([^\s"']+)/i,  // curl --upload-file
  ];
  
  for (const pattern of filePatterns) {
    const match = command.match(pattern);
    if (match) {
      return match[1];
    }
  }
  
  // Look for piped input
  if (command.includes('|')) {
    const pipeMatch = command.match(/([^|]+)\s*\|\s*(?:curl|wget)/i);
    if (pipeMatch) {
      return `piped from: ${pipeMatch[1].trim().substring(0, 50)}`;
    }
  }
  
  return undefined;
}

/**
 * Match curl POST/PUT commands
 */
export function matchCurlCommand(command: string): HttpMatchResult {
  for (const { pattern, method, description } of CURL_POST_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        httpMethod: method,
        destination: extractUrl(command),
        dataSource: extractDataSource(command),
        confidence: 0.9,
        description,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match wget POST commands
 */
export function matchWgetCommand(command: string): HttpMatchResult {
  for (const { pattern, method, description } of WGET_POST_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        httpMethod: method,
        destination: extractUrl(command),
        dataSource: match[1] || extractDataSource(command),
        confidence: 0.9,
        description,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match httpie commands
 */
export function matchHttpieCommand(command: string): HttpMatchResult {
  for (const { pattern, method, description } of HTTPIE_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        httpMethod: method,
        destination: match[1],
        confidence: 0.85,
        description,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match HTTP client library patterns in code
 */
export function matchCodeHttpPattern(code: string): HttpMatchResult {
  for (const { pattern, method, description } of CODE_HTTP_PATTERNS) {
    const match = code.match(pattern);
    if (match) {
      // Extract URL from the match
      const url = match[2] || match[1];
      return {
        matched: true,
        command: code,
        httpMethod: typeof match[1] === 'string' && ['post', 'put'].includes(match[1].toLowerCase()) 
          ? match[1].toUpperCase() 
          : method,
        destination: url?.startsWith('http') ? url : undefined,
        confidence: 0.85,
        description,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match encoded exfiltration patterns
 */
export function matchEncodedExfiltration(command: string): HttpMatchResult {
  for (const { pattern, method, description } of ENCODED_EXFIL_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        httpMethod: method,
        destination: extractUrl(command),
        dataSource: extractDataSource(command) || 'encoded/piped data',
        confidence: 0.95, // Higher confidence for encoded exfiltration
        description,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Comprehensive HTTP exfiltration matching
 */
export function matchHttpExfiltration(text: string): HttpMatchResult {
  // Try encoded exfiltration first (highest confidence)
  const encodedResult = matchEncodedExfiltration(text);
  if (encodedResult.matched) {
    return encodedResult;
  }
  
  // Try curl
  const curlResult = matchCurlCommand(text);
  if (curlResult.matched) {
    return curlResult;
  }
  
  // Try wget
  const wgetResult = matchWgetCommand(text);
  if (wgetResult.matched) {
    return wgetResult;
  }
  
  // Try httpie
  const httpieResult = matchHttpieCommand(text);
  if (httpieResult.matched) {
    return httpieResult;
  }
  
  // Try code patterns
  const codeResult = matchCodeHttpPattern(text);
  if (codeResult.matched) {
    return codeResult;
  }
  
  return { matched: false, confidence: 0 };
}

/**
 * HTTP exfiltration detector class
 */
export class HttpDetector implements SubDetector {
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
    
    // Body field (for write operations)
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
            method: 'http',
          },
        };
      }
    }

    // Then check hardcoded patterns
    const result = matchHttpExfiltration(content);
    
    if (!result.matched) {
      return null;
    }

    const destInfo = result.destination ? ` to ${result.destination}` : '';
    const dataInfo = result.dataSource ? ` (${result.dataSource})` : '';

    return {
      detected: true,
      category: 'exfiltration',
      severity: this.severity,
      confidence: result.confidence,
      reason: `HTTP exfiltration detected: ${result.description || `${result.httpMethod} request`}${destInfo}${dataInfo}`,
      metadata: {
        method: 'http',
        destination: result.destination,
        dataSource: result.dataSource,
        command: result.command,
      },
    };
  }
}

/**
 * Create an HTTP detector with the given severity
 */
export function createHttpDetector(severity: Severity = "high", customPatterns: string[] = [], logger?: any): HttpDetector {
  return new HttpDetector(severity, customPatterns, logger);
}
