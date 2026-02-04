/**
 * Clawsec - Security plugin for OpenClaw.ai
 * Prevents AI agents from taking dangerous actions
 */

// =============================================================================
// VERSION & CONSTANTS
// =============================================================================

export const VERSION = '1.0.0';
export const PLUGIN_ID = 'clawsec';
export const PLUGIN_NAME = 'Clawsec Security Plugin';

// Logger utility for safe API logging with fallback
import { createLogger, createNoOpLogger, type Logger } from './utils/logger.js';

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

/**
 * Severity levels for security detections
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Actions that can be taken when a threat is detected
 */
export type Action = 'block' | 'confirm' | 'agent-confirm' | 'warn' | 'log';

/**
 * Categories of security threats
 */
export type ThreatCategory = 'purchase' | 'website' | 'destructive' | 'secrets' | 'exfiltration';

/**
 * Base context provided to all hooks
 */
export interface HookContext {
  sessionId: string;
  userId?: string;
  timestamp: number;
}

/**
 * Tool call information passed to before-tool-call hook
 */
export interface ToolCallContext extends HookContext {
  toolName: string;
  toolInput: Record<string, unknown>;
  conversationHistory?: Array<{
    role: 'user' | 'assistant';
    content: string;
  }>;
}

/**
 * Result from before-tool-call hook
 */
export interface BeforeToolCallResult {
  /** Whether to allow the tool call to proceed */
  allow: boolean;
  /** Modified tool input (if transformed) */
  modifiedInput?: Record<string, unknown>;
  /** Message to display when blocked */
  blockMessage?: string;
  /** Metadata about the detection */
  metadata?: {
    category?: ThreatCategory;
    severity?: Severity;
    rule?: string;
    reason?: string;
  };
}

/**
 * Handler type for before-tool-call hook
 */
export type BeforeToolCallHandler = (
  context: ToolCallContext
) => Promise<BeforeToolCallResult>;

/**
 * Agent start context passed to before-agent-start hook
 */
export interface AgentStartContext extends HookContext {
  systemPrompt?: string;
  agentConfig?: Record<string, unknown>;
}

/**
 * Result from before-agent-start hook
 */
export interface BeforeAgentStartResult {
  /** Modified or injected system prompt content */
  systemPromptAddition?: string;
  /** Modified agent configuration */
  modifiedConfig?: Record<string, unknown>;
}

/**
 * Handler type for before-agent-start hook
 */
export type BeforeAgentStartHandler = (
  context: AgentStartContext
) => Promise<BeforeAgentStartResult>;

/**
 * Tool result context passed to tool-result-persist hook
 */
export interface ToolResultContext extends HookContext {
  toolName: string;
  toolInput: Record<string, unknown>;
  toolOutput: unknown;
}

/**
 * Result from tool-result-persist hook
 */
export interface ToolResultPersistResult {
  /** Whether to allow the result to be persisted */
  allow: boolean;
  /** Filtered/redacted output */
  filteredOutput?: unknown;
  /** Metadata about any redactions */
  redactions?: Array<{
    type: string;
    description: string;
  }>;
}

/**
 * Handler type for tool-result-persist hook
 */
export type ToolResultPersistHandler = (
  context: ToolResultContext
) => Promise<ToolResultPersistResult>;

/**
 * OpenClaw plugin API interface
 */
export interface OpenClawPluginAPI {
  /** Register a hook handler */
  registerHook: (hookName: string, handler: unknown, options?: HookOptions) => void;
  /** Unregister a hook handler */
  unregisterHook: (hookName: string, handlerId: string) => void;
  /** Plugin configuration */
  config: PluginConfig;
  /** Log a message */
  log: (level: 'debug' | 'info' | 'warn' | 'error', message: string, data?: unknown) => void;
  /** Request user approval */
  requestApproval: (request: ApprovalRequest) => Promise<ApprovalResponse>;
}

/**
 * Hook registration options
 */
export interface HookOptions {
  /** Display name for this hook handler */
  name?: string;
  /** Unique identifier for this handler */
  id?: string;
  /** Priority (lower runs first) */
  priority?: number;
  /** Whether this hook is enabled */
  enabled?: boolean;
}

/**
 * Plugin configuration from OpenClaw
 */
export interface PluginConfig {
  /** Path to clawsec.yaml config file */
  configPath?: string;
  /** Whether the plugin is enabled */
  enabled?: boolean;
  /** Log level */
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
}

/**
 * Approval request structure
 */
export interface ApprovalRequest {
  id: string;
  category: ThreatCategory;
  severity: Severity;
  reason: string;
  toolName: string;
  toolInput: Record<string, unknown>;
  timeout?: number;
}

/**
 * Approval response structure
 */
export interface ApprovalResponse {
  approved: boolean;
  approvedBy?: string;
  timestamp: number;
}

// =============================================================================
// PLUGIN STATE
// =============================================================================

interface PluginState {
  api: OpenClawPluginAPI | null;
  config: PluginConfig | null;
  initialized: boolean;
  logger: Logger;
  handlers: {
    beforeToolCall: BeforeToolCallHandler | null;
    beforeAgentStart: BeforeAgentStartHandler | null;
    toolResultPersist: ToolResultPersistHandler | null;
  };
}

const state: PluginState = {
  api: null,
  config: null,
  initialized: false,
  logger: createNoOpLogger(),
  handlers: {
    beforeToolCall: null,
    beforeAgentStart: null,
    toolResultPersist: null,
  },
};

// =============================================================================
// PLACEHOLDER HOOK HANDLERS
// =============================================================================

/**
 * Placeholder handler for before-tool-call hook.
 * Will be replaced with full implementation in Task 2.x
 */
const beforeToolCallHandler: BeforeToolCallHandler = async (
  context: ToolCallContext
): Promise<BeforeToolCallResult> => {
  // Log for debugging during development
  state.logger.debug(`before-tool-call: ${context.toolName}`, {
    sessionId: context.sessionId,
    toolInput: context.toolInput,
  });

  // Placeholder: Allow all tool calls
  // TODO: Implement actual detection logic in Task 2.x
  return {
    allow: true,
  };
};

/**
 * Placeholder handler for before-agent-start hook.
 * Will be replaced with full implementation in Task 2.x
 */
const beforeAgentStartHandler: BeforeAgentStartHandler = async (
  context: AgentStartContext
): Promise<BeforeAgentStartResult> => {
  // Log for debugging during development
  state.logger.debug('before-agent-start', {
    sessionId: context.sessionId,
  });

  // Placeholder: Inject basic security reminder into system prompt
  // TODO: Implement configurable prompts in Task 2.x
  const securityReminder = `
[CLAWSEC SECURITY CONTEXT]
This session is protected by Clawsec security plugin.
- Purchases and financial transactions require approval
- Destructive commands (rm -rf, DROP TABLE, etc.) are monitored
- Sensitive data in outputs may be filtered
`;

  return {
    systemPromptAddition: securityReminder,
  };
};

/**
 * Placeholder handler for tool-result-persist hook.
 * Will be replaced with full implementation in Task 2.x
 */
const toolResultPersistHandler: ToolResultPersistHandler = async (
  context: ToolResultContext
): Promise<ToolResultPersistResult> => {
  // Log for debugging during development
  state.logger.debug(`tool-result-persist: ${context.toolName}`, {
    sessionId: context.sessionId,
  });

  // Placeholder: Allow all results to persist
  // TODO: Implement actual filtering logic in Task 2.x
  return {
    allow: true,
  };
};

// =============================================================================
// PLUGIN LIFECYCLE
// =============================================================================

/**
 * Activates the Clawsec security plugin and registers all hooks.
 * 
 * @param api - The OpenClaw plugin API
 * @returns Cleanup function to deactivate the plugin
 */
export function activate(api: OpenClawPluginAPI): () => void {
  if (state.initialized) {
    state.logger.warn('Plugin already activated, skipping');
    return () => deactivate();
  }

  // Store API reference and config
  state.api = api;
  state.config = api.config;
  state.logger = createLogger(api, state.config);

  state.logger.info(`Activating Clawsec Security Plugin v${VERSION}`);

  // Check if plugin is enabled
  if (state.config?.enabled === false) {
    state.logger.info('Plugin is disabled via configuration');
    state.initialized = true;
    return () => deactivate();
  }

  // Store handler references
  state.handlers.beforeToolCall = beforeToolCallHandler;
  state.handlers.beforeAgentStart = beforeAgentStartHandler;
  state.handlers.toolResultPersist = toolResultPersistHandler;

  // Register hooks with OpenClaw
  api.registerHook('before-tool-call', beforeToolCallHandler, {
    name: 'before-tool-call',
    id: 'clawsec-before-tool-call',
    priority: 100,
    enabled: true,
  });

  api.registerHook('before-agent-start', beforeAgentStartHandler, {
    name: 'before-agent-start',
    id: 'clawsec-before-agent-start',
    priority: 50,
    enabled: true,
  });

  api.registerHook('tool-result-persist', toolResultPersistHandler, {
    name: 'tool-result-persist',
    id: 'clawsec-tool-result-persist',
    priority: 100,
    enabled: true,
  });

  state.initialized = true;
  state.logger.info('All hooks registered successfully');

  // Return cleanup function
  return () => deactivate();
}

/**
 * Deactivates the Clawsec security plugin and unregisters all hooks.
 */
export function deactivate(): void {
  if (!state.initialized) {
    return;
  }

  const api = state.api;
  if (api) {
    state.logger.info('Deactivating Clawsec Security Plugin');

    // Unregister all hooks
    api.unregisterHook('before-tool-call', 'clawsec-before-tool-call');
    api.unregisterHook('before-agent-start', 'clawsec-before-agent-start');
    api.unregisterHook('tool-result-persist', 'clawsec-tool-result-persist');

    state.logger.info('All hooks unregistered');
  }

  // Reset state
  state.api = null;
  state.config = null;
  state.initialized = false;
  state.logger = createNoOpLogger();
  state.handlers.beforeToolCall = null;
  state.handlers.beforeAgentStart = null;
  state.handlers.toolResultPersist = null;
}

/**
 * Check if the plugin is currently active
 */
export function isActive(): boolean {
  return state.initialized;
}

/**
 * Get the current plugin state (for testing/debugging)
 */
export function getState(): Readonly<PluginState> {
  return { ...state };
}

// =============================================================================
// CONFIG SCHEMA
// =============================================================================

/**
 * JSON Schema for plugin configuration (matches openclaw.plugin.json)
 */
export const pluginConfigSchema = {
  type: 'object',
  properties: {
    configPath: {
      type: 'string',
      default: './clawsec.yaml',
      description: 'Path to the Clawsec YAML configuration file',
    },
    enabled: {
      type: 'boolean',
      default: true,
      description: 'Whether the security plugin is enabled',
    },
    logLevel: {
      type: 'string',
      enum: ['debug', 'info', 'warn', 'error'],
      default: 'info',
      description: 'Logging verbosity level',
    },
  },
  additionalProperties: false,
} as const;

// =============================================================================
// REGISTER METHOD (OpenClaw Plugin API)
// =============================================================================

/**
 * Register method for OpenClaw plugin system.
 * This is the entry point called by OpenClaw when loading the plugin.
 *
 * @param api - The OpenClaw plugin API
 */
function register(api: OpenClawPluginAPI): void {
  activate(api);
}

// =============================================================================
// DEFAULT EXPORT
// =============================================================================

// Default export for OpenClaw plugin system
export default {
  id: PLUGIN_ID,
  name: PLUGIN_NAME,
  version: VERSION,
  configSchema: pluginConfigSchema,
  register,
  // Keep for backward compatibility
  activate,
  deactivate,
};
