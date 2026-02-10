/**
 * Network Exfiltration Detector
 * Detects raw network commands used for data exfiltration (netcat, socat, /dev/tcp, etc.)
 */

import type {
  NetworkMatchResult,
  DetectionContext,
  ExfiltrationDetectionResult,
  SubDetector,
} from './types.js';
import type { Severity } from '../../config/index.js';

/**
 * Netcat patterns for data exfiltration
 */
const NETCAT_PATTERNS = [
  // nc -e (execute shell - often used for reverse shells)
  {
    pattern: /\b(?:nc|netcat|ncat)\s+(?:[^|;]+\s+)?-e\s+(\S+)/i,
    tool: 'netcat',
    description: 'netcat with shell execution',
    critical: true,
  },
  // nc with output redirection (sending file contents)
  {
    pattern: /\bcat\s+([^\s|]+)\s*\|\s*(?:nc|netcat|ncat)\s+([^\s]+)\s+(\d+)/i,
    tool: 'netcat',
    description: 'file piped to netcat',
  },
  // nc reading from file directly
  {
    pattern: /\b(?:nc|netcat|ncat)\s+(?:[^|;]+\s+)?<\s*([^\s]+)/i,
    tool: 'netcat',
    description: 'netcat with file input',
  },
  // Any command piped to nc with host and port
  {
    pattern: /\|\s*(?:nc|netcat|ncat)\s+(-[^\s]+\s+)*([^\s]+)\s+(\d+)/i,
    tool: 'netcat',
    description: 'piped data to netcat',
  },
  // nc -q (quiet mode - data transfer)
  {
    pattern: /\b(?:nc|netcat)\s+(?:[^|;]+\s+)?-q\s+\d+\s+([^\s]+)\s+(\d+)/i,
    tool: 'netcat',
    description: 'netcat data transfer',
  },
  // ncat with --send-only or --recv-only
  {
    pattern: /\bncat\s+(?:[^|;]+\s+)?--(?:send-only|exec)\s+/i,
    tool: 'ncat',
    description: 'ncat data transfer',
    critical: true,
  },
];

/**
 * Bash /dev/tcp patterns (direct TCP connections)
 */
const DEV_TCP_PATTERNS = [
  // exec /dev/tcp (check first as it's most critical)
  {
    pattern: /\bexec\s+\d+<>\/dev\/tcp\/([^\/]+)\/(\d+)/i,
    tool: '/dev/tcp',
    description: 'bash TCP file descriptor',
    critical: true,
  },
  // Redirecting to /dev/tcp
  {
    pattern: />\s*\/dev\/tcp\/([^\/]+)\/(\d+)/i,
    tool: '/dev/tcp',
    description: 'bash TCP redirect (outbound)',
  },
  // Reading and sending via /dev/tcp
  {
    pattern: /\bcat\s+([^\s]+)\s*>\s*\/dev\/tcp\/([^\/]+)\/(\d+)/i,
    tool: '/dev/tcp',
    description: 'file sent via bash TCP',
  },
  // /dev/udp patterns
  {
    pattern: />\s*\/dev\/udp\/([^\/]+)\/(\d+)/i,
    tool: '/dev/udp',
    description: 'bash UDP redirect (outbound)',
  },
];

/**
 * Socat patterns
 */
const SOCAT_PATTERNS = [
  // socat sending file to TCP
  {
    pattern: /\bsocat\s+(?:[^|;]+\s+)?(?:FILE|OPEN):([^\s,]+)\s+TCP(?:4|6)?:([^:]+):(\d+)/i,
    tool: 'socat',
    description: 'socat file to TCP',
  },
  // socat with EXEC (shell execution)
  {
    pattern: /\bsocat\s+(?:[^|;]+\s+)?TCP(?:4|6)?:([^:]+):(\d+)\s+EXEC:/i,
    tool: 'socat',
    description: 'socat TCP with exec',
    critical: true,
  },
  // socat stdin to TCP
  {
    pattern: /\bsocat\s+(?:[^|;]+\s+)?-\s+TCP(?:4|6)?:([^:]+):(\d+)/i,
    tool: 'socat',
    description: 'socat stdin to TCP',
  },
  // Piped data to socat
  {
    pattern: /\|\s*socat\s+(?:[^|;]+\s+)?-\s+TCP(?:4|6)?:([^:]+):(\d+)/i,
    tool: 'socat',
    description: 'piped data to socat',
  },
];

/**
 * Telnet patterns
 */
const TELNET_PATTERNS = [
  // Piping data to telnet
  {
    pattern: /\|\s*telnet\s+([^\s]+)\s+(\d+)/i,
    tool: 'telnet',
    description: 'piped data to telnet',
  },
  // File redirected to telnet
  {
    pattern: /\btelnet\s+([^\s]+)\s+(\d+)\s*<\s*([^\s]+)/i,
    tool: 'telnet',
    description: 'file input to telnet',
  },
  // expect script with telnet
  {
    pattern: /\bexpect\s+.*telnet\s+([^\s]+)\s+(\d+)/i,
    tool: 'telnet/expect',
    description: 'automated telnet session',
  },
];

/**
 * SSH/SCP exfiltration patterns
 */
const SSH_EXFIL_PATTERNS = [
  // scp upload: local file to remote (local path first, then user@host:remote)
  // Detect pattern like: scp /local/file user@host:/remote/
  {
    pattern: /\bscp\s+(?:-[^\s]+\s+)*([^\s@:]+)\s+(\S+@[^:\s]+):(\S*)/i,
    tool: 'scp',
    description: 'scp upload to remote',
  },
  // rsync upload: local to remote
  {
    pattern: /\brsync\s+(?:-[^\s]+\s+)*([^\s@:]+)\s+(\S+@[^:\s]+):(\S*)/i,
    tool: 'rsync',
    description: 'rsync upload to remote',
  },
  // ssh with piped input
  {
    pattern: /\bcat\s+([^\s|]+)\s*\|\s*ssh\s+([^@\s]+@)?([^\s]+)/i,
    tool: 'ssh',
    description: 'file piped to ssh',
  },
  // sftp put command
  {
    pattern: /\bsftp\s+(?:[^|;]+\s+)?.*\bput\s+([^\s]+)/i,
    tool: 'sftp',
    description: 'sftp file upload',
  },
];

/**
 * DNS exfiltration patterns
 */
const DNS_EXFIL_PATTERNS = [
  // nslookup/dig with long subdomain (potential data encoding)
  {
    pattern: /\b(?:nslookup|dig|host)\s+([a-zA-Z0-9]{30,})\./i,
    tool: 'dns',
    description: 'potential DNS exfiltration',
  },
  // dig with TXT record query
  {
    pattern: /\bdig\s+(?:[^|;]+\s+)?TXT\s+([^\s]+)/i,
    tool: 'dns/txt',
    description: 'DNS TXT record query',
  },
];

/**
 * Other network exfiltration patterns
 */
const OTHER_NETWORK_PATTERNS = [
  // xxd/hexdump to network
  {
    pattern: /\b(?:xxd|hexdump)\s+[^\|]+\|\s*(?:nc|netcat|ncat|curl)/i,
    tool: 'hex-encoded',
    description: 'hex-encoded network exfiltration',
  },
  // openssl s_client for data transfer
  {
    pattern: /\bopenssl\s+s_client\s+(?:[^|;]+\s+)?-connect\s+([^:]+):(\d+)/i,
    tool: 'openssl',
    description: 'openssl encrypted connection',
  },
  // Python network exfiltration
  {
    pattern: /\bsocket\.(?:connect|sendto|send)\s*\(/i,
    tool: 'python-socket',
    description: 'Python socket connection',
  },
];

/**
 * Extract host and port from match
 */
function extractDestination(match: RegExpMatchArray, _pattern: {
  pattern: RegExp;
  tool: string;
}): { host?: string; port?: string } {
  // Different patterns capture host/port in different positions
  const groups = match.slice(1);
  let host: string | undefined;
  let port: string | undefined;
  
  for (const group of groups) {
    if (!group) continue;
    
    // Check if it looks like a port (all digits)
    if (/^\d+$/.test(group)) {
      port = group;
    } 
    // Check if it looks like a host/IP
    else if (/^[a-zA-Z0-9.-]+$/.test(group) && !group.match(/^\//) && group.length < 256) {
      host = group;
    }
  }
  
  return { host, port };
}

/**
 * Match netcat patterns
 */
export function matchNetcatCommand(command: string): NetworkMatchResult {
  for (const { pattern, tool, description, critical } of NETCAT_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      const { host, port } = extractDestination(match, { pattern, tool });
      const dataSource = match[1] && !match[1].match(/^\d+$/) && !match[1].match(/^-/) 
        ? match[1] 
        : undefined;
      
      return {
        matched: true,
        command,
        tool,
        destination: host,
        port,
        dataSource,
        confidence: critical ? 0.95 : 0.9,
        description,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match /dev/tcp patterns
 */
export function matchDevTcpPattern(command: string): NetworkMatchResult {
  for (const entry of DEV_TCP_PATTERNS) {
    const { pattern, tool, description } = entry;
    const critical = 'critical' in entry ? entry.critical : false;
    const match = command.match(pattern);
    if (match) {
      // For /dev/tcp, match[1] is typically the host, match[2] is the port
      const host = match.find((m, i) => i > 0 && m && !m.match(/^\d+$/) && m.length < 256);
      const port = match.find((m, i) => i > 0 && m && /^\d+$/.test(m));
      
      return {
        matched: true,
        command,
        tool,
        destination: host,
        port,
        confidence: critical ? 0.95 : 0.9,
        description,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match socat patterns
 */
export function matchSocatCommand(command: string): NetworkMatchResult {
  for (const { pattern, tool, description, critical } of SOCAT_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      const { host, port } = extractDestination(match, { pattern, tool });
      const dataSource = match[1] && !match[1].match(/^\d+$/) && !match[1].match(/^[a-zA-Z0-9.-]+$/) 
        ? match[1] 
        : undefined;
      
      return {
        matched: true,
        command,
        tool,
        destination: host,
        port,
        dataSource,
        confidence: critical ? 0.95 : 0.85,
        description,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match telnet patterns
 */
export function matchTelnetCommand(command: string): NetworkMatchResult {
  for (const { pattern, tool, description } of TELNET_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        tool,
        destination: match[1],
        port: match[2],
        dataSource: match[3],
        confidence: 0.85,
        description,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match SSH/SCP exfiltration patterns
 */
export function matchSshExfiltration(command: string): NetworkMatchResult {
  for (const { pattern, tool, description } of SSH_EXFIL_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      // Extract user@host
      const userHost = match.find((m, i) => i > 0 && m && m.includes('@'));
      const host = userHost?.split('@')[1] || match[2] || match[3];
      
      return {
        matched: true,
        command,
        tool,
        destination: host,
        dataSource: match[1],
        confidence: 0.85,
        description,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match DNS exfiltration patterns
 */
export function matchDnsExfiltration(command: string): NetworkMatchResult {
  for (const { pattern, tool, description } of DNS_EXFIL_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        tool,
        destination: match[1],
        confidence: 0.7, // Lower confidence as this could be legitimate
        description,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Match other network exfiltration patterns
 */
export function matchOtherNetworkPattern(command: string): NetworkMatchResult {
  for (const { pattern, tool, description } of OTHER_NETWORK_PATTERNS) {
    const match = command.match(pattern);
    if (match) {
      return {
        matched: true,
        command,
        tool,
        destination: match[1],
        port: match[2],
        confidence: 0.8,
        description,
      };
    }
  }
  return { matched: false, confidence: 0 };
}

/**
 * Comprehensive network exfiltration matching
 */
export function matchNetworkExfiltration(text: string): NetworkMatchResult {
  // Try netcat patterns first
  const ncResult = matchNetcatCommand(text);
  if (ncResult.matched) {
    return ncResult;
  }
  
  // Try /dev/tcp patterns
  const devTcpResult = matchDevTcpPattern(text);
  if (devTcpResult.matched) {
    return devTcpResult;
  }
  
  // Try socat patterns
  const socatResult = matchSocatCommand(text);
  if (socatResult.matched) {
    return socatResult;
  }
  
  // Try telnet patterns
  const telnetResult = matchTelnetCommand(text);
  if (telnetResult.matched) {
    return telnetResult;
  }
  
  // Try SSH/SCP patterns
  const sshResult = matchSshExfiltration(text);
  if (sshResult.matched) {
    return sshResult;
  }
  
  // Try DNS exfiltration patterns
  const dnsResult = matchDnsExfiltration(text);
  if (dnsResult.matched) {
    return dnsResult;
  }
  
  // Try other patterns
  const otherResult = matchOtherNetworkPattern(text);
  if (otherResult.matched) {
    return otherResult;
  }
  
  return { matched: false, confidence: 0 };
}

/**
 * Network exfiltration detector class
 */
export class NetworkDetector implements SubDetector {
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
            method: 'network',
          },
        };
      }
    }

    // Then check hardcoded patterns
    const result = matchNetworkExfiltration(content);
    
    if (!result.matched) {
      return null;
    }

    const destInfo = result.destination 
      ? ` to ${result.destination}${result.port ? ':' + result.port : ''}`
      : '';
    const srcInfo = result.dataSource ? ` (source: ${result.dataSource})` : '';

    return {
      detected: true,
      category: 'exfiltration',
      severity: this.severity,
      confidence: result.confidence,
      reason: `Network exfiltration detected: ${result.description || result.tool}${destInfo}${srcInfo}`,
      metadata: {
        method: 'network',
        destination: result.destination 
          ? (result.port ? `${result.destination}:${result.port}` : result.destination)
          : undefined,
        dataSource: result.dataSource,
        command: result.command,
      },
    };
  }
}

/**
 * Create a network detector with the given severity
 */
export function createNetworkDetector(severity: Severity = "high", customPatterns: string[] = [], logger?: any): NetworkDetector {
  return new NetworkDetector(severity, customPatterns, logger);
}
