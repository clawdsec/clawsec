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
  type HookOptions,
} from './index.js';
import defaultExport from './index.js';

// =============================================================================
// MOCK SETUP
// =============================================================================

/**
 * Creates a mock OpenClaw plugin API for testing
 */
function createMockAPI(configOverrides: Partial<PluginConfig> = {}): OpenClawPluginAPI {
  const registeredHooks = new Map<string, { handler: unknown; options?: HookOptions }>();
  
  return {
    registerHook: vi.fn((hookName: string, handler: unknown, options?: HookOptions) => {
      registeredHooks.set(hookName, { handler, options });
    }),
    unregisterHook: vi.fn((hookName: string, _handlerId: string) => {
      registeredHooks.delete(hookName);
    }),
    config: {
      configPath: './clawsec.yaml',
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
      expect(VERSION).toBe('1.0.0');
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
        'Activating Clawsec Security Plugin v1.0.0',
        undefined
      );
    });

    it('logs success message after hooks are registered', () => {
      const api = createMockAPI();
      
      activate(api);
      
      expect(api.log).toHaveBeenCalledWith(
        'info',
        'All hooks registered successfully',
        undefined
      );
    });

    it('registers before-tool-call hook', () => {
      const api = createMockAPI();
      
      activate(api);
      
      expect(api.registerHook).toHaveBeenCalledWith(
        'before-tool-call',
        expect.any(Function),
        expect.objectContaining({
          id: 'clawsec-before-tool-call',
          priority: 100,
          enabled: true,
        })
      );
    });

    it('registers before-agent-start hook', () => {
      const api = createMockAPI();
      
      activate(api);
      
      expect(api.registerHook).toHaveBeenCalledWith(
        'before-agent-start',
        expect.any(Function),
        expect.objectContaining({
          id: 'clawsec-before-agent-start',
          priority: 50,
          enabled: true,
        })
      );
    });

    it('registers tool-result-persist hook', () => {
      const api = createMockAPI();
      
      activate(api);
      
      expect(api.registerHook).toHaveBeenCalledWith(
        'tool-result-persist',
        expect.any(Function),
        expect.objectContaining({
          id: 'clawsec-tool-result-persist',
          priority: 100,
          enabled: true,
        })
      );
    });

    it('registers all three hooks', () => {
      const api = createMockAPI();
      
      activate(api);
      
      expect(api.registerHook).toHaveBeenCalledTimes(3);
    });

    it('warns and skips if already activated', () => {
      const api = createMockAPI();
      
      activate(api);
      activate(api); // Second activation
      
      expect(api.log).toHaveBeenCalledWith(
        'warn',
        'Plugin already activated, skipping',
        undefined
      );
      // registerHook should only be called 3 times (not 6)
      expect(api.registerHook).toHaveBeenCalledTimes(3);
    });

    it('does not register hooks when disabled via config', () => {
      const api = createMockAPI({ enabled: false });
      
      activate(api);
      
      expect(api.registerHook).not.toHaveBeenCalled();
      expect(api.log).toHaveBeenCalledWith(
        'info',
        'Plugin is disabled via configuration',
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

    it('unregisters all hooks', () => {
      const api = createMockAPI();
      activate(api);
      
      deactivate();
      
      expect(api.unregisterHook).toHaveBeenCalledWith(
        'before-tool-call',
        'clawsec-before-tool-call'
      );
      expect(api.unregisterHook).toHaveBeenCalledWith(
        'before-agent-start',
        'clawsec-before-agent-start'
      );
      expect(api.unregisterHook).toHaveBeenCalledWith(
        'tool-result-persist',
        'clawsec-tool-result-persist'
      );
    });

    it('logs deactivation messages', () => {
      const api = createMockAPI();
      activate(api);
      
      deactivate();
      
      expect(api.log).toHaveBeenCalledWith(
        'info',
        'Deactivating Clawsec Security Plugin',
        undefined
      );
      expect(api.log).toHaveBeenCalledWith(
        'info',
        'All hooks unregistered',
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
      expect(state.handlers.beforeToolCall).toBeNull();
      expect(state.handlers.beforeAgentStart).toBeNull();
      expect(state.handlers.toolResultPersist).toBeNull();
    });

    it('does nothing if not active', () => {
      const api = createMockAPI();
      
      // Don't activate, just deactivate
      deactivate();
      
      expect(api.unregisterHook).not.toHaveBeenCalled();
    });

    it('can be called multiple times safely', () => {
      const api = createMockAPI();
      activate(api);
      
      deactivate();
      deactivate();
      deactivate();
      
      // Should only unregister hooks once
      expect(api.unregisterHook).toHaveBeenCalledTimes(3);
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
      expect(state.handlers.beforeToolCall).not.toBeNull();
      expect(state.handlers.beforeAgentStart).not.toBeNull();
      expect(state.handlers.toolResultPersist).not.toBeNull();
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
      it('allows tool calls by default', async () => {
        const api = createMockAPI();
        activate(api);
        
        // Extract the registered handler
        const registerCall = vi.mocked(api.registerHook).mock.calls.find(
          call => call[0] === 'before-tool-call'
        );
        expect(registerCall).toBeDefined();
        
        const handler = registerCall![1] as (context: ToolCallContext) => Promise<{ allow: boolean }>;
        const context = createToolCallContext();
        
        const result = await handler(context);
        
        expect(result.allow).toBe(true);
      });

      it('logs in debug mode', async () => {
        const api = createMockAPI({ logLevel: 'debug' });
        activate(api);
        
        const registerCall = vi.mocked(api.registerHook).mock.calls.find(
          call => call[0] === 'before-tool-call'
        );
        const handler = registerCall![1] as (context: ToolCallContext) => Promise<{ allow: boolean }>;
        const context = createToolCallContext({ toolName: 'test-tool' });
        
        await handler(context);
        
        expect(api.log).toHaveBeenCalledWith(
          'debug',
          'before-tool-call: test-tool',
          expect.objectContaining({
            sessionId: context.sessionId,
          })
        );
      });
    });

    describe('before-agent-start handler', () => {
      it('injects security reminder into system prompt', async () => {
        const api = createMockAPI();
        activate(api);
        
        const registerCall = vi.mocked(api.registerHook).mock.calls.find(
          call => call[0] === 'before-agent-start'
        );
        expect(registerCall).toBeDefined();
        
        const handler = registerCall![1] as (context: AgentStartContext) => Promise<{ systemPromptAddition?: string }>;
        const context = createAgentStartContext();
        
        const result = await handler(context);
        
        expect(result.systemPromptAddition).toBeDefined();
        expect(result.systemPromptAddition).toContain('CLAWSEC SECURITY CONTEXT');
        expect(result.systemPromptAddition).toContain('Clawsec security plugin');
      });

      it('security reminder mentions key protections', async () => {
        const api = createMockAPI();
        activate(api);
        
        const registerCall = vi.mocked(api.registerHook).mock.calls.find(
          call => call[0] === 'before-agent-start'
        );
        const handler = registerCall![1] as (context: AgentStartContext) => Promise<{ systemPromptAddition?: string }>;
        const context = createAgentStartContext();
        
        const result = await handler(context);
        
        expect(result.systemPromptAddition).toContain('Purchases');
        expect(result.systemPromptAddition).toContain('Destructive commands');
        expect(result.systemPromptAddition).toContain('Sensitive data');
      });

      it('logs in debug mode', async () => {
        const api = createMockAPI({ logLevel: 'debug' });
        activate(api);
        
        const registerCall = vi.mocked(api.registerHook).mock.calls.find(
          call => call[0] === 'before-agent-start'
        );
        const handler = registerCall![1] as (context: AgentStartContext) => Promise<{ systemPromptAddition?: string }>;
        const context = createAgentStartContext();
        
        await handler(context);
        
        expect(api.log).toHaveBeenCalledWith(
          'debug',
          'before-agent-start',
          expect.objectContaining({
            sessionId: context.sessionId,
          })
        );
      });
    });

    describe('tool-result-persist handler', () => {
      it('allows results to persist by default', async () => {
        const api = createMockAPI();
        activate(api);
        
        const registerCall = vi.mocked(api.registerHook).mock.calls.find(
          call => call[0] === 'tool-result-persist'
        );
        expect(registerCall).toBeDefined();
        
        const handler = registerCall![1] as (context: ToolResultContext) => Promise<{ allow: boolean }>;
        const context = createToolResultContext();
        
        const result = await handler(context);
        
        expect(result.allow).toBe(true);
      });

      it('logs in debug mode', async () => {
        const api = createMockAPI({ logLevel: 'debug' });
        activate(api);
        
        const registerCall = vi.mocked(api.registerHook).mock.calls.find(
          call => call[0] === 'tool-result-persist'
        );
        const handler = registerCall![1] as (context: ToolResultContext) => Promise<{ allow: boolean }>;
        const context = createToolResultContext({ toolName: 'test-tool' });
        
        await handler(context);
        
        expect(api.log).toHaveBeenCalledWith(
          'debug',
          'tool-result-persist: test-tool',
          expect.objectContaining({
            sessionId: context.sessionId,
          })
        );
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
      expect(api1.registerHook).toHaveBeenCalledTimes(3);
      
      // Deactivation
      deactivate();
      expect(isActive()).toBe(false);
      expect(api1.unregisterHook).toHaveBeenCalledTimes(3);
      
      // Second activation with different API
      activate(api2);
      expect(isActive()).toBe(true);
      expect(api2.registerHook).toHaveBeenCalledTimes(3);
    });

    it('cleanup function works correctly', () => {
      const api = createMockAPI();
      
      const cleanup = activate(api);
      expect(isActive()).toBe(true);
      
      cleanup();
      expect(isActive()).toBe(false);
      expect(api.unregisterHook).toHaveBeenCalledTimes(3);
    });

    it('disabled plugin can be re-enabled after deactivation', () => {
      const disabledApi = createMockAPI({ enabled: false });
      const enabledApi = createMockAPI({ enabled: true });
      
      // Activate disabled
      activate(disabledApi);
      expect(isActive()).toBe(true);
      expect(disabledApi.registerHook).not.toHaveBeenCalled();
      
      // Deactivate
      deactivate();
      
      // Activate enabled
      activate(enabledApi);
      expect(enabledApi.registerHook).toHaveBeenCalledTimes(3);
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
      
      expect(api.registerHook).toHaveBeenCalledTimes(3);
    });

    it('state remains consistent after multiple rapid activations', () => {
      const api = createMockAPI();
      
      activate(api);
      activate(api);
      activate(api);
      
      expect(isActive()).toBe(true);
      expect(api.registerHook).toHaveBeenCalledTimes(3); // Only first activation
    });
  });
});
