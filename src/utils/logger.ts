/**
 * Logger utility for safe logging with fallback to console
 */

import type { OpenClawPluginAPI, PluginConfig } from '../index.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export interface Logger {
  debug: (message: string, data?: unknown) => void;
  info: (message: string, data?: unknown) => void;
  warn: (message: string, data?: unknown) => void;
  error: (message: string, data?: unknown) => void;
}

/**
 * Creates a safe logger that handles missing api.log gracefully
 *
 * @param api - The OpenClaw plugin API (nullable)
 * @param config - The plugin configuration (nullable)
 * @returns Logger instance with level-filtered logging
 */
export function createLogger(
  api: OpenClawPluginAPI | null,
  config: PluginConfig | null
): Logger {
  const configuredLevel = config?.logLevel || 'info';
  const minLevel = LOG_LEVELS[configuredLevel];

  function shouldLog(level: LogLevel): boolean {
    return LOG_LEVELS[level] >= minLevel;
  }

  function log(level: LogLevel, message: string, data?: unknown): void {
    if (!shouldLog(level)) {
      return;
    }

    // Try API logging first
    if (api && typeof api.log === 'function') {
      try {
        api.log(level, message, data);
        return;
      } catch {
        // API logging failed, fall through to console
      }
    }

    // Fallback to console
    // Map log levels to console methods (debug -> log for better spy compatibility)
    const consoleMapping: Record<LogLevel, typeof console.log> = {
      debug: console.log,
      info: console.info,
      warn: console.warn,
      error: console.error,
    };
    const consoleMethod = consoleMapping[level];
    if (data !== undefined) {
      consoleMethod(`[clawsec] ${message}`, data);
    } else {
      consoleMethod(`[clawsec] ${message}`);
    }
  }

  return {
    debug: (message: string, data?: unknown): void => log('debug', message, data),
    info: (message: string, data?: unknown): void => log('info', message, data),
    warn: (message: string, data?: unknown): void => log('warn', message, data),
    error: (message: string, data?: unknown): void => log('error', message, data),
  };
}

/**
 * Creates a no-op logger that discards all logs
 *
 * @returns Logger instance that does nothing
 */
export function createNoOpLogger(): Logger {
  const noop = (): void => {};
  return {
    debug: noop,
    info: noop,
    warn: noop,
    error: noop,
  };
}
