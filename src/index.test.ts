import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  VERSION,
  PLUGIN_ID,
  PLUGIN_NAME,
  activate,
  deactivate,
  isActive,
  getState,
  type OpenClawPluginAPI,
  type ToolCallContext,
  type AgentStartContext,
  type ToolResultContext,
  type PluginConfig,
} from './index.js';
import defaultExport from './index.js';

// =============================================================================
// MOCK SETUP
// =============================================================================

/**
 * Creates a mock OpenClaw plugin API for testing (modern API)
 */
function createMockAPI(configOverrides: Partial<PluginConfig> = {}): OpenClawPluginAPI {
  const registeredHooks = new Map<string, { handler: unknown; options?: { priority?: number } }>();

  return {
    on: vi.fn((hookName: string, handler: unknown, options?: { priority?: number }) => {
      registeredHooks.set(hookName, { handler, options });
    }),
    config: {
      configPath: './clawsec.yaml.example',
      enabled: true,
      logLevel: 'info' as const,
      ...configOverrides,
    },
    log: vi.fn(),
    requestApproval: vi.fn().mockResolvedValue({
      approved: true,
      approvedBy: 'test-user',
      timestamp: Date.now(),
    }),
  };
}

/**
 * Creates a mock ToolCallContext
 */
function createToolCallContext(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    sessionId: 'test-session-123',
    timestamp: Date.now(),
    toolName: 'exec',
    toolInput: { command: 'ls -la' },
    ...overrides,
  };
}

/**
 * Creates a mock AgentStartContext
 */
function createAgentStartContext(overrides: Partial<AgentStartContext> = {}): AgentStartContext {
  return {
    sessionId: 'test-session-123',
    timestamp: Date.now(),
    ...overrides,
  };
}

/**
 * Creates a mock ToolResultContext
 */
function createToolResultContext(overrides: Partial<ToolResultContext> = {}): ToolResultContext {
  return {
    sessionId: 'test-session-123',
    timestamp: Date.now(),
    toolName: 'exec',
    toolInput: { command: 'ls -la' },
    toolOutput: 'file1.txt\nfile2.txt',
    ...overrides,
  };
}

// =============================================================================
// TESTS
// =============================================================================

describe('Clawsec Plugin', () => {
  // Reset plugin state between tests
  beforeEach(() => {
    if (isActive()) {
      deactivate();
    }
  });

  afterEach(() => {
    if (isActive()) {
      deactivate();
    }
    vi.clearAllMocks();
  });

  // ---------------------------------------------------------------------------
  // Constants & Exports
  // ---------------------------------------------------------------------------
  
  describe('Constants', () => {
    it('exports VERSION', () => {
      expect(VERSION).toBe('0.0.1');
    });

    it('exports PLUGIN_ID', () => {
      expect(PLUGIN_ID).toBe('clawsec');
    });

    it('exports PLUGIN_NAME', () => {
      expect(PLUGIN_NAME).toBe('Clawsec Security Plugin');
    });
  });

  describe('Default Export', () => {
    it('exports plugin metadata', () => {
      expect(defaultExport.id).toBe(PLUGIN_ID);
      expect(defaultExport.name).toBe(PLUGIN_NAME);
      expect(defaultExport.version).toBe(VERSION);
    });

    it('exports activate function', () => {
      expect(typeof defaultExport.activate).toBe('function');
    });

    it('exports deactivate function', () => {
      expect(typeof defaultExport.deactivate).toBe('function');
    });
  });

  // ---------------------------------------------------------------------------
  // Activation
  // ---------------------------------------------------------------------------

  describe('activate()', () => {
    it('activates the plugin successfully', () => {
      const api = createMockAPI();
      
      activate(api);
      
      expect(isActive()).toBe(true);
    });

    it('returns a cleanup function', () => {
      const api = createMockAPI();
      
      const cleanup = activate(api);
      
      expect(typeof cleanup).toBe('function');
    });

    it('retrieves configuration from API', () => {
      const api = createMockAPI();

      activate(api);

      const state = getState();
      expect(state.config).toEqual(api.config);
    });

    it('logs activation message', () => {
      const api = createMockAPI();
      
      activate(api);
      
      expect(api.log).toHaveBeenCalledWith(
        'info',
        '[clawsec] Activating Clawsec Security Plugin v0.0.1',
        undefined
      );
    });

    it('logs success message after hooks are registered', () => {
      const api = createMockAPI();
      
      activate(api);
      
      expect(api.log).toHaveBeenCalledWith(
        'info',
        '[clawsec] All hooks registered successfully',
        undefined
      );
    });

    it('registers before-tool-call hook', () => {
      const api = createMockAPI();
      
      activate(api);
      
      expect(api.on).toHaveBeenCalledWith(
        'before_tool_call',
        expect.any(Function),
        expect.objectContaining({
          priority: 100,
        })
      );
    });

    it('registers before-agent-start hook', () => {
      const api = createMockAPI();
      
      activate(api);
      
      expect(api.on).toHaveBeenCalledWith(
        'before_agent_start',
        expect.any(Function),
        expect.objectContaining({
          priority: 50,
        })
      );
    });

    it('registers tool-result-persist hook', () => {
      const api = createMockAPI();
      
      activate(api);
      
      expect(api.on).toHaveBeenCalledWith(
        'tool_result_persist',
        expect.any(Function),
        expect.objectContaining({
          priority: 100,
        })
      );
    });

    it('registers all three hooks', () => {
      const api = createMockAPI();
      
      activate(api);
      
      expect(api.on).toHaveBeenCalledTimes(3);
    });

    it('warns and skips if already activated', () => {
      const api = createMockAPI();
      
      activate(api);
      activate(api); // Second activation
      
      expect(api.log).toHaveBeenCalledWith(
        'warn',
        '[clawsec] Plugin already activated, skipping',
        undefined
      );
      // registerHook should only be called 3 times (not 6)
      expect(api.on).toHaveBeenCalledTimes(3);
    });

    it('does not register hooks when disabled via config', () => {
      const api = createMockAPI({ enabled: false });
      
      activate(api);
      
      expect(api.on).not.toHaveBeenCalled();
      expect(api.log).toHaveBeenCalledWith(
        'info',
        '[clawsec] Plugin is disabled via configuration',
        undefined
      );
    });

    it('still marks as initialized when disabled', () => {
      const api = createMockAPI({ enabled: false });
      
      activate(api);
      
      expect(isActive()).toBe(true);
    });

    it('cleanup function calls deactivate', () => {
      const api = createMockAPI();
      
      const cleanup = activate(api);
      expect(isActive()).toBe(true);
      
      cleanup();
      expect(isActive()).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Deactivation
  // ---------------------------------------------------------------------------

  describe('deactivate()', () => {
    it('deactivates the plugin', () => {
      const api = createMockAPI();
      activate(api);

      deactivate();

      expect(isActive()).toBe(false);
    });

    it('logs deactivation message', () => {
      const api = createMockAPI();
      activate(api);

      deactivate();

      expect(api.log).toHaveBeenCalledWith(
        'info',
        '[clawsec] Deactivating Clawsec Security Plugin',
        undefined
      );
    });

    it('resets plugin state', () => {
      const api = createMockAPI();
      activate(api);

      deactivate();

      const state = getState();
      expect(state.api).toBeNull();
      expect(state.config).toBeNull();
      expect(state.initialized).toBe(false);
    });

    it('does nothing if not active', () => {
      // Don't activate, just deactivate
      deactivate();

      expect(isActive()).toBe(false);
    });

    it('can be called multiple times safely', () => {
      const api = createMockAPI();
      activate(api);

      deactivate();
      deactivate();
      deactivate();

      expect(isActive()).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // State Management
  // ---------------------------------------------------------------------------

  describe('isActive()', () => {
    it('returns false initially', () => {
      expect(isActive()).toBe(false);
    });

    it('returns true after activation', () => {
      const api = createMockAPI();
      activate(api);
      
      expect(isActive()).toBe(true);
    });

    it('returns false after deactivation', () => {
      const api = createMockAPI();
      activate(api);
      deactivate();
      
      expect(isActive()).toBe(false);
    });
  });

  describe('getState()', () => {
    it('returns initial state', () => {
      const state = getState();
      
      expect(state.api).toBeNull();
      expect(state.config).toBeNull();
      expect(state.initialized).toBe(false);
    });

    it('returns populated state after activation', () => {
      const api = createMockAPI();
      activate(api);
      
      const state = getState();
      
      expect(state.api).not.toBeNull();
      expect(state.config).not.toBeNull();
      expect(state.initialized).toBe(true);
    });

    it('returns a copy of state (immutable)', () => {
      const api = createMockAPI();
      activate(api);
      
      const state1 = getState();
      const state2 = getState();
      
      expect(state1).not.toBe(state2);
      expect(state1).toEqual(state2);
    });
  });

  // ---------------------------------------------------------------------------
  // Hook Handlers (Placeholder Behavior)
  // ---------------------------------------------------------------------------

  describe('Hook Handlers', () => {
    describe('before-tool-call handler', () => {
      it('handler is registered and executable', async () => {
        const api = createMockAPI();
        activate(api);

        // Extract the registered handler
        const registerCall = vi.mocked(api.on).mock.calls.find(
          call => call[0] === 'before_tool_call'
        );
        expect(registerCall).toBeDefined();

        const handler = registerCall![1] as (context: ToolCallContext) => Promise<{ block?: boolean }>;
        const context = createToolCallContext();

        // Should execute without errors and return a result (modern API: block field)
        const result = await handler(context);
        expect(result).toBeDefined();
        expect(typeof result.block).toBe('boolean');
      });
    });

    describe('before-agent-start handler', () => {
      it('injects security context into system prompt', async () => {
        const api = createMockAPI();
        activate(api);

        const registerCall = vi.mocked(api.on).mock.calls.find(
          call => call[0] === 'before_agent_start'
        );
        expect(registerCall).toBeDefined();

        const handler = registerCall![1] as (context: AgentStartContext) => Promise<{ prependContext?: string }>;
        const context = createAgentStartContext();

        const result = await handler(context);

        // Handler should inject some security context (modern API: prependContext field)
        expect(result.prependContext).toBeDefined();
        expect(result.prependContext).toContain('CLAWSEC SECURITY CONTEXT');
      });

      it('handler executes successfully', async () => {
        const api = createMockAPI();
        activate(api);

        const registerCall = vi.mocked(api.on).mock.calls.find(
          call => call[0] === 'before_agent_start'
        );
        const handler = registerCall![1] as (context: AgentStartContext) => Promise<{ prependContext?: string }>;
        const context = createAgentStartContext();

        // Should not throw
        await expect(handler(context)).resolves.toBeDefined();
      });
    });

    describe('tool-result-persist handler', () => {
      it('handler is registered and executable', async () => {
        const api = createMockAPI();
        activate(api);

        const registerCall = vi.mocked(api.on).mock.calls.find(
          call => call[0] === 'tool_result_persist'
        );
        expect(registerCall).toBeDefined();

        const handler = registerCall![1] as (context: ToolResultContext) => Promise<{ message?: unknown }>;
        const context = createToolResultContext();

        // Should execute without errors and return a result (modern API: message field)
        const result = await handler(context);
        expect(result).toBeDefined();
        // Result may or may not have a message field depending on whether filtering occurred
      });
    });
  });

  // ---------------------------------------------------------------------------
  // Lifecycle Scenarios
  // ---------------------------------------------------------------------------

  describe('Lifecycle Scenarios', () => {
    it('handles activate -> deactivate -> activate cycle', () => {
      const api1 = createMockAPI();
      const api2 = createMockAPI();
      
      // First activation
      activate(api1);
      expect(isActive()).toBe(true);
      expect(api1.on).toHaveBeenCalledTimes(3);
      
      // Deactivation
      deactivate();
      expect(isActive()).toBe(false);
      
      // Second activation with different API
      activate(api2);
      expect(isActive()).toBe(true);
      expect(api2.on).toHaveBeenCalledTimes(3);
    });

    it('cleanup function works correctly', () => {
      const api = createMockAPI();
      
      const cleanup = activate(api);
      expect(isActive()).toBe(true);
      
      cleanup();
      expect(isActive()).toBe(false);
    });

    it('disabled plugin can be re-enabled after deactivation', () => {
      const disabledApi = createMockAPI({ enabled: false });
      const enabledApi = createMockAPI({ enabled: true });
      
      // Activate disabled
      activate(disabledApi);
      expect(isActive()).toBe(true);
      expect(disabledApi.on).not.toHaveBeenCalled();
      
      // Deactivate
      deactivate();
      
      // Activate enabled
      activate(enabledApi);
      expect(enabledApi.on).toHaveBeenCalledTimes(3);
    });
  });

  // ---------------------------------------------------------------------------
  // Edge Cases
  // ---------------------------------------------------------------------------

  describe('Edge Cases', () => {
    it('handles undefined config values gracefully', () => {
      const api = createMockAPI({
        configPath: undefined,
        enabled: undefined,
        logLevel: undefined,
      });
      
      // Should not throw
      expect(() => activate(api)).not.toThrow();
      expect(isActive()).toBe(true);
    });

    it('handles config with enabled explicitly set to true', () => {
      const api = createMockAPI({ enabled: true });
      
      activate(api);
      
      expect(api.on).toHaveBeenCalledTimes(3);
    });

    it('state remains consistent after multiple rapid activations', () => {
      const api = createMockAPI();
      
      activate(api);
      activate(api);
      activate(api);
      
      expect(isActive()).toBe(true);
      expect(api.on).toHaveBeenCalledTimes(3); // Only first activation
    });
  });
});
