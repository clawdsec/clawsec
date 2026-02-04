/**
 * Pattern definitions for prompt injection detection
 */

import type { InjectionCategory } from './types.js';

/**
 * Pattern definition with metadata
 */
export interface PatternDef {
  /** Regular expression pattern (case-insensitive by default) */
  pattern: RegExp;
  /** Base confidence score for this pattern */
  confidence: number;
  /** Description of what this pattern detects */
  description: string;
}

/**
 * Instruction override patterns
 * Detects attempts to override or ignore previous instructions
 */
export const INSTRUCTION_OVERRIDE_PATTERNS: PatternDef[] = [
  {
    pattern: /ignore\s+(all\s+)?previous\s+(instructions?|prompts?|messages?)/i,
    confidence: 0.95,
    description: 'Direct instruction to ignore previous instructions',
  },
  {
    pattern: /disregard\s+(all\s+)?(previous\s+|prior\s+|above\s+)?(instructions?|prompts?|directives?)/i,
    confidence: 0.95,
    description: 'Instruction to disregard previous directives',
  },
  {
    pattern: /forget\s+(everything|all)\s+(you\s+)?(know|were\s+told|learned)/i,
    confidence: 0.9,
    description: 'Attempt to reset context',
  },
  {
    pattern: /\bnew\s+task\s*:/i,
    confidence: 0.85,
    description: 'Attempt to inject a new task',
  },
  {
    pattern: /\bsystem\s*:\s*\w/i,
    confidence: 0.8,
    description: 'Fake system message prefix',
  },
  {
    pattern: /\bassistant\s*:\s*\w/i,
    confidence: 0.7,
    description: 'Fake assistant message prefix',
  },
  {
    pattern: /\buser\s*:\s*\w/i,
    confidence: 0.6,
    description: 'Fake user message prefix',
  },
  {
    pattern: /override\s+(your\s+)?(instructions?|programming|guidelines?)/i,
    confidence: 0.9,
    description: 'Direct override attempt',
  },
  {
    pattern: /from\s+now\s+on[,\s]+(you\s+)?(will|must|should|are)/i,
    confidence: 0.75,
    description: 'Attempt to change behavior going forward',
  },
  {
    pattern: /stop\s+being\s+(an?\s+)?(ai|assistant|helpful)/i,
    confidence: 0.85,
    description: 'Attempt to change AI persona',
  },
  {
    pattern: /do\s+not\s+follow\s+(your\s+)?(rules?|guidelines?|instructions?)/i,
    confidence: 0.9,
    description: 'Instruction to break rules',
  },
  {
    pattern: /your\s+(new|actual|real)\s+(instructions?|task|goal)\s+(is|are)/i,
    confidence: 0.9,
    description: 'Fake new instructions',
  },
];

/**
 * System prompt leak patterns
 * Detects attempts to extract system prompts or initial instructions
 */
export const SYSTEM_LEAK_PATTERNS: PatternDef[] = [
  {
    pattern: /your\s+system\s+prompt/i,
    confidence: 0.9,
    description: 'Direct reference to system prompt',
  },
  {
    pattern: /(show|reveal|display|print|output|tell\s+me)\s+(your\s+)?(system\s+prompt|initial\s+instructions?)/i,
    confidence: 0.95,
    description: 'Request to reveal system prompt',
  },
  {
    pattern: /initial\s+(instructions?|prompt|configuration)/i,
    confidence: 0.7,
    description: 'Reference to initial instructions',
  },
  {
    pattern: /original\s+(prompt|instructions?|system\s+message)/i,
    confidence: 0.75,
    description: 'Reference to original prompt',
  },
  {
    pattern: /what\s+(are|were)\s+your\s+(original|initial|first)\s+(instructions?|directives?)/i,
    confidence: 0.85,
    description: 'Question about initial instructions',
  },
  {
    pattern: /repeat\s+(your\s+)?(system|initial|original)\s+(prompt|instructions?)/i,
    confidence: 0.9,
    description: 'Request to repeat system prompt',
  },
  {
    pattern: /leak\s+(your\s+)?(system|initial)\s+(prompt|instructions?)/i,
    confidence: 0.95,
    description: 'Direct leak request',
  },
  {
    pattern: /hidden\s+(prompt|instructions?|directives?)/i,
    confidence: 0.8,
    description: 'Reference to hidden instructions',
  },
  {
    pattern: /confidential\s+(instructions?|prompt|configuration)/i,
    confidence: 0.75,
    description: 'Reference to confidential configuration',
  },
];

/**
 * Jailbreak patterns
 * Detects attempts to bypass safety restrictions
 */
export const JAILBREAK_PATTERNS: PatternDef[] = [
  {
    pattern: /\bDAN\s+(mode|enabled?)/i,
    confidence: 0.95,
    description: 'DAN (Do Anything Now) jailbreak',
  },
  {
    pattern: /\bdeveloper\s+mode\s+(enabled?|activated?|on)/i,
    confidence: 0.95,
    description: 'Developer mode jailbreak',
  },
  {
    pattern: /\bjailbr(eak|oken|eaking|eaked)\b/i,
    confidence: 0.9,
    description: 'Direct jailbreak reference',
  },
  {
    pattern: /pretend\s+(you\s+are|to\s+be|you're)\s+(an?\s+)?(different|another|evil|unrestricted)/i,
    confidence: 0.85,
    description: 'Persona manipulation attempt',
  },
  {
    pattern: /act\s+as\s+(if\s+)?(you\s+)?(have\s+no|without)\s+(restrictions?|limits?|rules?)/i,
    confidence: 0.9,
    description: 'Request to act without restrictions',
  },
  {
    pattern: /\bunlocked?\s+(mode|version|ai)/i,
    confidence: 0.85,
    description: 'Unlocked mode reference',
  },
  {
    pattern: /\bno\s+(ethical|moral|safety)\s+(guidelines?|restrictions?|limits?)/i,
    confidence: 0.9,
    description: 'Request to ignore ethical guidelines',
  },
  {
    pattern: /bypass\s+(your\s+)?(restrictions?|filters?|safety|guidelines?)/i,
    confidence: 0.9,
    description: 'Bypass attempt',
  },
  {
    pattern: /\benable\s+(god|admin|super)\s*mode/i,
    confidence: 0.9,
    description: 'Special mode enable attempt',
  },
  {
    pattern: /you\s+are\s+now\s+(free|unrestricted|unlimited|uncensored)/i,
    confidence: 0.85,
    description: 'Freedom assertion',
  },
  {
    pattern: /roleplay\s+as\s+(an?\s+)?(evil|malicious|unrestricted|unfiltered)/i,
    confidence: 0.85,
    description: 'Malicious roleplay request',
  },
  {
    pattern: /\banti[- ]?ai\s+(mode|prompt)/i,
    confidence: 0.85,
    description: 'Anti-AI prompt pattern',
  },
];

/**
 * Encoded payload patterns
 * Detects potentially malicious encoded content
 */
export const ENCODED_PAYLOAD_PATTERNS: PatternDef[] = [
  {
    pattern: /eyJ[A-Za-z0-9+/=]{20,}/,
    confidence: 0.7,
    description: 'Base64 encoded JSON (starts with eyJ)',
  },
  {
    pattern: /(?:^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{50,}={0,2}(?:[^A-Za-z0-9+/=]|$)/,
    confidence: 0.5,
    description: 'Long base64 string',
  },
  {
    pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/,
    confidence: 0.8,
    description: 'Hex escape sequence',
  },
  {
    pattern: /0x[0-9a-fA-F]{20,}/,
    confidence: 0.6,
    description: 'Long hex string',
  },
  {
    pattern: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}/,
    confidence: 0.75,
    description: 'Unicode escape sequence',
  },
  {
    pattern: /%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2}){10,}/,
    confidence: 0.7,
    description: 'URL encoded sequence',
  },
  {
    pattern: /&#x?[0-9a-fA-F]+;(?:&#x?[0-9a-fA-F]+;){5,}/,
    confidence: 0.75,
    description: 'HTML entity encoded sequence',
  },
];

/**
 * Map of category to patterns
 */
export const PATTERNS_BY_CATEGORY: Record<InjectionCategory, PatternDef[]> = {
  'instruction-override': INSTRUCTION_OVERRIDE_PATTERNS,
  'system-leak': SYSTEM_LEAK_PATTERNS,
  jailbreak: JAILBREAK_PATTERNS,
  'encoded-payload': ENCODED_PAYLOAD_PATTERNS,
};

/**
 * Get all patterns for enabled categories
 * @param categories - Which categories are enabled
 * @returns Array of [category, pattern] tuples
 */
export function getEnabledPatterns(categories: {
  instructionOverride: boolean;
  systemLeak: boolean;
  jailbreak: boolean;
  encodedPayload: boolean;
}): Array<[InjectionCategory, PatternDef]> {
  const result: Array<[InjectionCategory, PatternDef]> = [];

  if (categories.instructionOverride) {
    for (const pattern of INSTRUCTION_OVERRIDE_PATTERNS) {
      result.push(['instruction-override', pattern]);
    }
  }

  if (categories.systemLeak) {
    for (const pattern of SYSTEM_LEAK_PATTERNS) {
      result.push(['system-leak', pattern]);
    }
  }

  if (categories.jailbreak) {
    for (const pattern of JAILBREAK_PATTERNS) {
      result.push(['jailbreak', pattern]);
    }
  }

  if (categories.encodedPayload) {
    for (const pattern of ENCODED_PAYLOAD_PATTERNS) {
      result.push(['encoded-payload', pattern]);
    }
  }

  return result;
}
