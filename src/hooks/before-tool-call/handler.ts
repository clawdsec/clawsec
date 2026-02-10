/**
 * Before Tool Call Hook Handler
 *
 * Main hook handler that intercepts tool calls, runs detection,
 * and blocks/confirms dangerous actions.
 */

import type {
  ToolCallContext as HookToolCallContext,
  BeforeToolCallResult,
  BeforeToolCallHandler,
  ThreatCategory,
  Severity,
} from '../../index.js';
import type {
  Analyzer,
  ToolCallContext as EngineToolCallContext,
  Detection,
} from '../../engine/types.js';
import type { ActionExecutor, ActionContext, ActionResult } from '../../actions/types.js';
import type { ClawsecConfig } from '../../config/schema.js';
import type { AgentConfirmHandler } from '../../approval/agent-confirm.js';
import { createAnalyzer } from '../../engine/analyzer.js';
import { createActionExecutor } from '../../actions/executor.js';
import { createAgentConfirmHandler } from '../../approval/agent-confirm.js';
import { getDefaultApprovalStore } from '../../approval/store.js';
import { createLogger, type Logger } from '../../utils/logger.js';

/**
 * Options for creating a before-tool-call handler
 */
export interface BeforeToolCallHandlerOptions {
  /** Custom analyzer instance */
  analyzer?: Analyzer;
  /** Custom action executor instance */
  executor?: ActionExecutor;
  /** Custom agent confirm handler instance */
  agentConfirm?: AgentConfirmHandler;
}

/**
 * Convert hook ToolCallContext to engine ToolCallContext
 * The engine context has a slightly different shape
 */
function toEngineContext(hookContext: HookToolCallContext): EngineToolCallContext {
  const toolInput = hookContext.toolInput || {};
  return {
    toolName: hookContext.toolName,
    toolInput,
    // url can be extracted from toolInput if present
    url: typeof toolInput.url === 'string' ? toolInput.url : undefined,
  };
}

/**
 * Convert analysis result and action result to BeforeToolCallResult (modern API)
 */
function toBeforeToolCallResult(
  actionResult: ActionResult,
  detection?: Detection
): BeforeToolCallResult {
  const result: BeforeToolCallResult = {
    block: !actionResult.allowed, // Inverted: !allow = block
  };

  // Add block reason if blocked
  if (!actionResult.allowed && actionResult.message) {
    result.blockReason = actionResult.message;
  }

  // Add metadata from primary detection
  if (detection) {
    result.metadata = {
      category: detection.category as ThreatCategory,
      severity: detection.severity as Severity,
      reason: detection.reason,
    };

    // Add rule if present in detection metadata
    if (detection.metadata?.rule && typeof detection.metadata.rule === 'string') {
      result.metadata.rule = detection.metadata.rule;
    }
  }

  // Add pending approval instructions to block reason if present
  if (actionResult.pendingApproval) {
    const approvalInfo = `\n\nApproval ID: ${actionResult.pendingApproval.id}\nTimeout: ${actionResult.pendingApproval.timeout}s\nMethods: ${actionResult.pendingApproval.methods.join(', ')}`;
    result.blockReason = (result.blockReason || 'Approval required') + approvalInfo;
  }

  return result;
}

/**
 * Create the allow result for when no threats are detected (modern API)
 */
function createAllowResult(): BeforeToolCallResult {
  return {
    block: false, // Modern: explicit false means allow
  };
}

/**
 * Create a result for valid agent-confirm flow (modern API)
 */
function createAgentConfirmAllowResult(
  strippedInput: Record<string, unknown>
): BeforeToolCallResult {
  return {
    block: false,
    params: strippedInput, // Modern: renamed from modifiedInput
  };
}

/**
 * Create a result for invalid agent-confirm flow (modern API)
 */
function createAgentConfirmInvalidResult(error?: string): BeforeToolCallResult {
  return {
    block: true, // Modern: true = block
    blockReason: error || 'Invalid or expired approval confirmation',
    metadata: {
      reason: 'Agent confirmation parameter was present but invalid',
    },
  };
}

/**
 * Create a result for disabled plugin (modern API)
 */
function createDisabledResult(): BeforeToolCallResult {
  return {
    block: false,
  };
}

/**
 * Create the before-tool-call handler
 *
 * Flow:
 * 1. Check if plugin is enabled
 * 2. Check for agent-confirm parameter -> validate and allow if valid
 * 3. Run HybridAnalyzer on tool call context
 * 4. Execute action based on analysis result
 * 5. Return appropriate BeforeToolCallResult
 *
 * @param config - Clawsec configuration
 * @param options - Optional custom components
 * @param logger - Optional logger instance
 * @returns BeforeToolCallHandler function
 */
export function createBeforeToolCallHandler(
  config: ClawsecConfig,
  options?: BeforeToolCallHandlerOptions,
  logger?: Logger
): BeforeToolCallHandler {
  const log = logger ?? createLogger(null, null);

  // Create or use provided components
  const analyzer = options?.analyzer ?? createAnalyzer(config, undefined, log);
  const executor = options?.executor ?? createActionExecutor({ logger: log });
  const agentConfirm =
    options?.agentConfirm ??
    createAgentConfirmHandler({
      enabled: config.approval?.agentConfirm?.enabled ?? true,
      parameterName: config.approval?.agentConfirm?.parameterName,
      store: getDefaultApprovalStore(),
      logger: log,
    });

  // Get the parameter name from config
  const confirmParamName = config.approval?.agentConfirm?.parameterName ?? '_clawsec_confirm';

  return async (context: HookToolCallContext): Promise<BeforeToolCallResult> => {
    try {
      // Normalize context: OpenClaw may send 'params' instead of 'toolInput'
      // Support both field names for backward compatibility
      const normalizedContext: HookToolCallContext = {
        ...context,
        toolInput: context.toolInput || (context as any).params || {},
      };

      const toolName = normalizedContext.toolName;
      log.info(`[Hook:before-tool-call] Entry: tool=${toolName}`);

      // Validate context (using normalized version)
      if (!normalizedContext || !normalizedContext.toolName || !normalizedContext.toolInput) {
        log.error(`[Hook:before-tool-call] Invalid context received`, context);
        return createAllowResult(); // Fail-open for invalid context
      }

      // 1. Check if plugin is disabled
      if (config.global?.enabled === false) {
        log.info(`[Hook:before-tool-call] Plugin disabled, allowing tool`);
        return createDisabledResult();
      }

      // 2. Check for agent-confirm parameter
    if (config.approval?.agentConfirm?.enabled !== false) {
      const confirmResult = agentConfirm.checkConfirmation(
        normalizedContext.toolInput,
        confirmParamName
      );

      if (confirmResult.confirmed) {
        // Agent is trying to confirm a previous action
        const processResult = agentConfirm.processConfirmation(
          normalizedContext.toolInput,
          confirmParamName
        );

        if (processResult.valid) {
          // Valid confirmation - strip the parameter and allow
          const strippedInput = agentConfirm.stripConfirmParameter(
            normalizedContext.toolInput,
            confirmParamName
          );
          log.info(`[Hook:before-tool-call] Exit: tool=${toolName}, result=allow (agent-confirm validated)`);
          return createAgentConfirmAllowResult(strippedInput);
        } else {
          // Invalid confirmation - block
          log.warn(`[Hook:before-tool-call] Exit: tool=${toolName}, result=block (invalid agent-confirm)`);
          return createAgentConfirmInvalidResult(processResult.error);
        }
      }
    }

    // 3. Run the analyzer (using normalized context)
    const engineContext = toEngineContext(normalizedContext);
    const analysis = await analyzer.analyze(engineContext);

    // 4. If no detections or action is allow/log/warn, handle appropriately
    if (analysis.action === 'allow') {
      log.debug(`[Hook:before-tool-call] Exit: tool=${toolName}, result=allow`);
      return createAllowResult();
    }

    // 5. Execute the action
    const actionContext: ActionContext = {
      analysis,
      toolCall: engineContext,
      config,
    };

    const actionResult = await executor.execute(actionContext);

      // 6. Convert to BeforeToolCallResult
      const result = toBeforeToolCallResult(actionResult, analysis.primaryDetection);
      log.info(`[Hook:before-tool-call] Exit: tool=${toolName}, result=${result.block ? 'block' : 'allow'}`);
      return result;
    } catch (error) {
      // Error handling: log and fail-open (allow the action)
      const errorMessage = error instanceof Error ? error.message : String(error);
      log.error(`[Hook:before-tool-call] Unhandled error: ${errorMessage}`, error);
      return createAllowResult(); // Fail-open on errors
    }
  };
}

/**
 * Create a default before-tool-call handler with default configuration
 */
export function createDefaultBeforeToolCallHandler(): BeforeToolCallHandler {
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
      sanitization: {
        enabled: true,
        severity: 'high',
        action: 'block',
        minConfidence: 0.5,
        redactMatches: false,
        categories: {
          instructionOverride: true,
          systemLeak: true,
          jailbreak: true,
          encodedPayload: true,
        },
      },
    },
    approval: {
      native: { enabled: true, timeout: 300 },
      agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
      webhook: { enabled: false, url: undefined, timeout: 30, headers: {} },
    },
  };

  return createBeforeToolCallHandler(defaultConfig);
}
