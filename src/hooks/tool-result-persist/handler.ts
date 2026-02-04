/**
 * Tool Result Persist Hook Handler
 *
 * Hook handler that scans tool outputs for secrets/PII and filters
 * sensitive data before it's persisted.
 */

import type {
  ToolResultContext,
  ToolResultPersistResult,
  ToolResultPersistHandler,
} from '../../index.js';
import type { ClawsecConfig } from '../../config/schema.js';
import type { SecretsDetectionResult } from '../../detectors/secrets/types.js';
import { createSecretsDetector } from '../../detectors/secrets/index.js';
import { filterOutput } from './filter.js';

/**
 * Options for creating a tool-result-persist handler
 */
export interface ToolResultPersistHandlerOptions {
  /**
   * Whether to enable output filtering (redacting secrets)
   * @default true
   */
  filter?: boolean;
}

/**
 * Create an allow result with no filtering
 */
function createAllowResult(): ToolResultPersistResult {
  return {
    allow: true,
  };
}

/**
 * Create a result with filtered output and redaction info
 */
function createFilteredResult(
  filteredOutput: unknown,
  redactions: Array<{ type: string; description: string }>
): ToolResultPersistResult {
  return {
    allow: true,
    filteredOutput,
    redactions,
  };
}

/**
 * Create the tool-result-persist handler
 *
 * This handler runs after a tool executes but before the result is persisted.
 * It scans the output for secrets/PII and redacts sensitive data.
 *
 * Flow:
 * 1. Check if plugin is enabled
 * 2. Check if filtering is enabled
 * 3. Run secrets detector on tool output
 * 4. Filter output if secrets detected
 * 5. Return result with filtered output and redaction metadata
 *
 * @param config - Clawsec configuration
 * @param options - Optional handler options
 * @returns ToolResultPersistHandler function
 */
export function createToolResultPersistHandler(
  config: ClawsecConfig,
  options?: ToolResultPersistHandlerOptions
): ToolResultPersistHandler {
  const filterEnabled = options?.filter ?? true;

  // Create secrets detector from config
  const secretsDetector = createSecretsDetector({
    enabled: config.rules?.secrets?.enabled ?? true,
    severity: config.rules?.secrets?.severity ?? 'critical',
    action: config.rules?.secrets?.action ?? 'block',
  });

  return async (context: ToolResultContext): Promise<ToolResultPersistResult> => {
    // 1. Check if plugin is globally disabled
    if (config.global?.enabled === false) {
      return createAllowResult();
    }

    // 2. Check if filtering is disabled via options
    if (!filterEnabled) {
      return createAllowResult();
    }

    // 3. Check if secrets detection is disabled in config
    if (config.rules?.secrets?.enabled === false) {
      return createAllowResult();
    }

    // 4. Run secrets detector on the tool output
    // Convert toolOutput to string for the detector (it expects string | undefined)
    const toolOutputString =
      typeof context.toolOutput === 'string'
        ? context.toolOutput
        : context.toolOutput !== null && context.toolOutput !== undefined
          ? JSON.stringify(context.toolOutput)
          : undefined;

    let detections: SecretsDetectionResult[] = [];
    try {
      detections = await secretsDetector.detectAll({
        toolName: context.toolName,
        toolInput: context.toolInput,
        toolOutput: toolOutputString,
      });
    } catch {
      // If detection fails, allow the output through without filtering
      // This ensures tool results aren't lost due to detector errors
      return createAllowResult();
    }

    // 5. If no secrets detected, check output directly with pattern matching
    // This catches secrets the detector might have missed
    const filterResult = filterOutput(context.toolOutput, detections);

    // 6. If nothing was redacted, allow through unchanged
    if (!filterResult.wasRedacted) {
      return createAllowResult();
    }

    // 7. Return filtered result with redaction metadata
    return createFilteredResult(
      filterResult.filteredOutput,
      filterResult.redactions
    );
  };
}

/**
 * Create a default tool-result-persist handler with default configuration
 */
export function createDefaultToolResultPersistHandler(): ToolResultPersistHandler {
  const defaultConfig: ClawsecConfig = {
    version: '1.0',
    global: {
      enabled: true,
      logLevel: 'info',
    },
    llm: {
      enabled: true,
      model: null,
    },
    rules: {
      purchase: {
        enabled: true,
        severity: 'critical',
        action: 'block',
        spendLimits: { perTransaction: 100, daily: 500 },
        domains: { mode: 'blocklist', blocklist: [] },
      },
      website: {
        enabled: true,
        mode: 'blocklist',
        severity: 'high',
        action: 'block',
        blocklist: [],
        allowlist: [],
      },
      destructive: {
        enabled: true,
        severity: 'critical',
        action: 'confirm',
        shell: { enabled: true },
        cloud: { enabled: true },
        code: { enabled: true },
      },
      secrets: {
        enabled: true,
        severity: 'critical',
        action: 'block',
      },
      exfiltration: {
        enabled: true,
        severity: 'high',
        action: 'block',
      },
    },
    approval: {
      native: { enabled: true, timeout: 300 },
      agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
      webhook: { enabled: false, url: undefined, timeout: 30, headers: {} },
    },
  };

  return createToolResultPersistHandler(defaultConfig);
}
