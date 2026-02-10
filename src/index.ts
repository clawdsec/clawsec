/**
 * Clawsec - Security plugin for OpenClaw.ai
 * Prevents AI agents from taking dangerous actions
 */

// =============================================================================
// VERSION & CONSTANTS
// =============================================================================

export const VERSION = '0.0.1';
export const PLUGIN_ID = 'clawsec';
export const PLUGIN_NAME = 'Clawsec Security Plugin';

// Logger utility for safe API logging with fallback
import { createLogger, createNoOpLogger, type Logger } from './utils/logger.js';

// Config loader
import { loadConfig } from './config/loader.js';

// Hook handler factories
import { createBeforeToolCallHandler } from './hooks/before-tool-call/handler.js';
import { createBeforeAgentStartHandler } from './hooks/before-agent-start/handler.js';
import { createToolResultPersistHandler } from './hooks/tool-result-persist/handler.js';

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
export type ThreatCategory = 'purchase' | 'website' | 'destructive' | 'secrets' | 'exfiltration' | 'unknown';

/**
 * Base context provided to all hooks
 */
export interface HookContext {
  sessionId?: string;  // Optional - may need to be extracted/generated
  userId?: string;
  timestamp: number;
}

/**
 * Tool call information passed to before-tool-call hook
 */
export interface ToolCallContext extends HookContext {
  toolName: string;
  toolInput?: Record<string, unknown>;  // Optional - may be 'params' instead
  params?: Record<string, unknown>;     // Alternative field name from OpenClaw
  conversationHistory?: Array<{
    role: 'user' | 'assistant';
    content: string;
  }>;
}

/**
 * Result from before-tool-call hook (modern API)
 */
export interface BeforeToolCallResult {
  /** Whether to block the tool call (default: false = allow) */
  block?: boolean;
  /** Reason for blocking (if blocked) */
  blockReason?: string;
  /** Modified tool parameters (if transformed) */
  params?: Record<string, unknown>;
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
  // Expected fields (from our design)
  systemPrompt?: string;
  agentConfig?: Record<string, unknown>;

  // Alternative fields (what OpenClaw actually sends)
  prompt?: string;
  messages?: Array<{
    role: 'user' | 'assistant' | 'toolResult' | string;
    content: unknown;
    timestamp?: number;
    [key: string]: unknown;
  }>;
}

/**
 * Result from before-agent-start hook (modern API)
 */
export interface BeforeAgentStartResult {
  /** System prompt replacement (replaces entire prompt) */
  systemPrompt?: string;
  /** Context to prepend before user message (OpenClaw's actual API field) */
  prependContext?: string;
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
 * Result from tool-result-persist hook (modern API)
 */
export interface ToolResultPersistResult {
  /** Modified message object (if filtering/redacting) */
  message?: {
    content?: unknown;
    redactions?: Array<{
      type: string;
      description: string;
    }>;
  };
}

/**
 * Handler type for tool-result-persist hook
 * Note: This hook must be synchronous per OpenClaw requirements
 */
export type ToolResultPersistHandler = (
  context: ToolResultContext
) => ToolResultPersistResult;

/**
 * OpenClaw plugin API interface
 */
export interface OpenClawPluginAPI {
  /** Register a hook handler (modern event-based API) */
  on: (hookName: string, handler: unknown, options?: { priority?: number }) => void;
  /** Plugin configuration */
  config: PluginConfig;
  /** Log a message */
  log: (level: 'debug' | 'info' | 'warn' | 'error', message: string, data?: unknown) => void;
  /** Request user approval */
  requestApproval: (request: ApprovalRequest) => Promise<ApprovalResponse>;
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

import type { ClawsecConfig } from './config/schema.js';

interface PluginState {
  api: OpenClawPluginAPI | null;
  config: PluginConfig | null;
  clawsecConfig: ClawsecConfig | null;
  initialized: boolean;
  logger: Logger;
}

const state: PluginState = {
  api: null,
  config: null,
  clawsecConfig: null,
  initialized: false,
  logger: createNoOpLogger(),
};

// =============================================================================
// DEFAULT CONFIGURATION
// =============================================================================

/**
 * Generate default security configuration
 * Used as fallback when custom config fails to load
 */
function getDefaultConfig(): ClawsecConfig {
  return {
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
        action: 'block',
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
      webhook: { enabled: false, timeout: 30, headers: {} },
    },
  };
}

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

  // Load the clawsec.yaml configuration
  try {
    const configPath = state.config?.configPath;
    state.clawsecConfig = loadConfig(configPath, state.logger);
    state.logger.info('Configuration loaded successfully');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    state.logger.error(`Failed to load configuration: ${errorMessage}`);
    state.logger.warn('Using default security configuration');

    // Use default config instead of no config
    const defaultConfig = getDefaultConfig();
    state.clawsecConfig = defaultConfig;

    // Create handlers with default config
    const beforeToolCallHandlerWithConfig = createBeforeToolCallHandler(
      defaultConfig,
      undefined,
      state.logger
    );

    const beforeAgentStartHandlerWithConfig = createBeforeAgentStartHandler(
      defaultConfig,
      undefined,
      state.logger
    );

    const toolResultPersistHandlerWithConfig = createToolResultPersistHandler(
      defaultConfig,
      undefined,
      state.logger
    );

    // Register hooks with default config (modern API)
    api.on('before_tool_call', beforeToolCallHandlerWithConfig, { priority: 100 });
    api.on('before_agent_start', beforeAgentStartHandlerWithConfig, { priority: 50 });
    api.on('tool_result_persist', toolResultPersistHandlerWithConfig, { priority: 100 });

    state.initialized = true;
    state.logger.warn('Plugin initialized with default config due to error');
    return () => deactivate();
  }

  // Create handlers with loaded config
  const beforeToolCallHandlerWithConfig = createBeforeToolCallHandler(state.clawsecConfig, undefined, state.logger);
  const beforeAgentStartHandlerWithConfig = createBeforeAgentStartHandler(state.clawsecConfig, undefined, state.logger);
  const toolResultPersistHandlerWithConfig = createToolResultPersistHandler(state.clawsecConfig, undefined, state.logger);

  // Register hooks with OpenClaw (modern API)
  api.on('before_tool_call', beforeToolCallHandlerWithConfig, { priority: 100 });
  api.on('before_agent_start', beforeAgentStartHandlerWithConfig, { priority: 50 });
  api.on('tool_result_persist', toolResultPersistHandlerWithConfig, { priority: 100 });

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
    // Modern API: hooks are automatically unregistered by OpenClaw
  }

  // Reset state
  state.api = null;
  state.config = null;
  state.initialized = false;
  state.logger = createNoOpLogger();
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
function register(api: OpenClawPluginAPI): () => void {
  return activate(api);
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
