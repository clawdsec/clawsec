/**
 * Agent Confirm Handler
 * Handles agent-side confirmation via _clawsec_confirm parameter
 *
 * When a tool call is flagged for confirmation, the agent can acknowledge
 * the risk by retrying the call with a _clawsec_confirm parameter set to
 * the approval ID.
 */

import type { ApprovalStore } from './types.js';
import { getDefaultApprovalStore } from './store.js';
import { createLogger, type Logger } from '../utils/logger.js';

/** Default parameter name for agent confirmation */
export const DEFAULT_CONFIRM_PARAMETER = '_clawsec_confirm';

/**
 * Result of checking for agent confirmation
 */
export interface AgentConfirmResult {
  /** Whether the tool input contains a confirmation parameter */
  confirmed: boolean;
  /** The approval ID from the confirmation parameter */
  approvalId?: string;
  /** Whether the approval ID is valid and the approval can proceed */
  valid: boolean;
  /** Error message if confirmation is invalid */
  error?: string;
}

/**
 * Interface for the agent confirm handler
 */
export interface AgentConfirmHandler {
  /**
   * Check if tool input contains a valid confirmation
   * @param toolInput - The tool input object
   * @param parameterName - Custom parameter name (defaults to _clawsec_confirm)
   * @returns Result indicating if confirmation is present and valid
   */
  checkConfirmation(
    toolInput: Record<string, unknown>,
    parameterName?: string
  ): AgentConfirmResult;

  /**
   * Remove the confirm parameter from tool input for clean execution
   * @param toolInput - The tool input object
   * @param parameterName - Custom parameter name (defaults to _clawsec_confirm)
   * @returns Tool input without the confirm parameter
   */
  stripConfirmParameter(
    toolInput: Record<string, unknown>,
    parameterName?: string
  ): Record<string, unknown>;

  /**
   * Process agent confirmation: validate and approve if valid
   * @param toolInput - The tool input object
   * @param parameterName - Custom parameter name (defaults to _clawsec_confirm)
   * @returns Result indicating if confirmation succeeded
   */
  processConfirmation(
    toolInput: Record<string, unknown>,
    parameterName?: string
  ): AgentConfirmResult;
}

/**
 * Configuration for the agent confirm handler
 */
export interface AgentConfirmHandlerConfig {
  /** The approval store to use (defaults to the default singleton) */
  store?: ApprovalStore;
  /** Whether agent confirmation is enabled */
  enabled?: boolean;
  /** Custom parameter name for confirmation */
  parameterName?: string;
  /** Optional logger instance */
  logger?: Logger;
}

/**
 * Default implementation of the agent confirm handler
 */
export class DefaultAgentConfirmHandler implements AgentConfirmHandler {
  private store: ApprovalStore;
  private enabled: boolean;
  private defaultParameterName: string;
  private logger: Logger;

  constructor(config: AgentConfirmHandlerConfig = {}) {
    this.store = config.store ?? getDefaultApprovalStore();
    this.enabled = config.enabled ?? true;
    this.defaultParameterName = config.parameterName ?? DEFAULT_CONFIRM_PARAMETER;
    this.logger = config.logger ?? createLogger(null, null);
  }

  /**
   * Check if tool input contains a valid confirmation
   */
  checkConfirmation(
    toolInput: Record<string, unknown>,
    parameterName?: string
  ): AgentConfirmResult {
    const paramName = parameterName ?? this.defaultParameterName;

    this.logger.debug(`[AgentConfirm] Checking for confirmation parameter: ${paramName}`);

    // Check if confirmation is disabled
    if (!this.enabled) {
      this.logger.debug(`[AgentConfirm] Agent confirmation is disabled`);
      return {
        confirmed: false,
        valid: false,
        error: 'Agent confirmation is disabled',
      };
    }

    // Check if parameter exists
    if (!(paramName in toolInput)) {
      this.logger.debug(`[AgentConfirm] Confirmation parameter not found`);
      return {
        confirmed: false,
        valid: false,
      };
    }

    const approvalId = toolInput[paramName];
    this.logger.debug(`[AgentConfirm] Confirmation parameter found: ${paramName}=${approvalId}`);

    // Validate the approval ID is a non-empty string
    if (typeof approvalId !== 'string' || approvalId.trim() === '') {
      this.logger.warn(`[AgentConfirm] Invalid approval ID format`);
      return {
        confirmed: true,
        valid: false,
        error: 'Invalid approval ID: must be a non-empty string',
      };
    }

    const trimmedId = approvalId.trim();

    // Look up the approval record
    const record = this.store.get(trimmedId);

    if (!record) {
      this.logger.warn(`[AgentConfirm] Approval not found: id=${trimmedId}`);
      return {
        confirmed: true,
        approvalId: trimmedId,
        valid: false,
        error: `Approval not found: No pending approval with ID "${trimmedId}"`,
      };
    }

    // Check the record status
    if (record.status === 'expired') {
      this.logger.warn(`[AgentConfirm] Approval expired: id=${trimmedId}`);
      return {
        confirmed: true,
        approvalId: trimmedId,
        valid: false,
        error: `Approval expired: The approval "${trimmedId}" has expired`,
      };
    }

    if (record.status === 'approved') {
      this.logger.warn(`[AgentConfirm] Approval already used: id=${trimmedId}`);
      return {
        confirmed: true,
        approvalId: trimmedId,
        valid: false,
        error: `Already approved: The approval "${trimmedId}" was already approved`,
      };
    }

    if (record.status === 'denied') {
      this.logger.warn(`[AgentConfirm] Approval was denied: id=${trimmedId}`);
      return {
        confirmed: true,
        approvalId: trimmedId,
        valid: false,
        error: `Already denied: The approval "${trimmedId}" was denied`,
      };
    }

    // Valid pending approval
    this.logger.info(`[AgentConfirm] Approval validated: id=${trimmedId}, allowing tool call`);
    return {
      confirmed: true,
      approvalId: trimmedId,
      valid: true,
    };
  }

  /**
   * Remove the confirm parameter from tool input
   */
  stripConfirmParameter(
    toolInput: Record<string, unknown>,
    parameterName?: string
  ): Record<string, unknown> {
    const paramName = parameterName ?? this.defaultParameterName;

    if (!(paramName in toolInput)) {
      return toolInput;
    }

    // Create a shallow copy without the confirm parameter
    const { [paramName]: _, ...cleanedInput } = toolInput;
    return cleanedInput;
  }

  /**
   * Process agent confirmation: validate and approve if valid
   * This combines checkConfirmation with actually approving the record
   */
  processConfirmation(
    toolInput: Record<string, unknown>,
    parameterName?: string
  ): AgentConfirmResult {
    const result = this.checkConfirmation(toolInput, parameterName);

    // If not valid, return the check result as-is
    if (!result.valid || !result.approvalId) {
      return result;
    }

    // Attempt to approve the record
    const success = this.store.approve(result.approvalId, 'agent');

    if (!success) {
      // This could happen if the record expired between check and approve
      return {
        confirmed: true,
        approvalId: result.approvalId,
        valid: false,
        error: `Failed to approve: Unable to approve "${result.approvalId}"`,
      };
    }

    return {
      confirmed: true,
      approvalId: result.approvalId,
      valid: true,
    };
  }

  /**
   * Check if agent confirmation is enabled
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Get the default parameter name
   */
  getParameterName(): string {
    return this.defaultParameterName;
  }
}

/**
 * Create an agent confirm handler with the given configuration
 */
export function createAgentConfirmHandler(
  config?: AgentConfirmHandlerConfig
): DefaultAgentConfirmHandler {
  return new DefaultAgentConfirmHandler(config);
}

/**
 * Default singleton handler instance
 */
let defaultHandler: DefaultAgentConfirmHandler | null = null;

/**
 * Get the default agent confirm handler singleton
 */
export function getDefaultAgentConfirmHandler(): DefaultAgentConfirmHandler {
  if (!defaultHandler) {
    defaultHandler = createAgentConfirmHandler();
  }
  return defaultHandler;
}

/**
 * Reset the default handler (mainly for testing)
 */
export function resetDefaultAgentConfirmHandler(): void {
  defaultHandler = null;
}
