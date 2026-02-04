import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createLogger, createNoOpLogger, type Logger } from './logger.js';
import type { OpenClawPluginAPI, PluginConfig } from '../index.js';

describe('Logger Utility', () => {
  let consoleLogSpy: ReturnType<typeof vi.spyOn>;
  let consoleInfoSpy: ReturnType<typeof vi.spyOn>;
  let consoleWarnSpy: ReturnType<typeof vi.spyOn>;
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    consoleInfoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
    consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('createLogger with API', () => {
    it('uses api.log when available', () => {
      const mockAPI = {
        log: vi.fn(),
        registerHook: vi.fn(),
        unregisterHook: vi.fn(),
        config: {},
        requestApproval: vi.fn(),
      } as unknown as OpenClawPluginAPI;

      const config: PluginConfig = { logLevel: 'info' };
      const logger = createLogger(mockAPI, config);

      logger.info('test message', { data: 'value' });

      expect(mockAPI.log).toHaveBeenCalledWith('info', 'test message', { data: 'value' });
      expect(consoleInfoSpy).not.toHaveBeenCalled();
    });

    it('falls back to console when api.log is missing', () => {
      const mockAPI = {
        // log method is missing
        registerHook: vi.fn(),
        unregisterHook: vi.fn(),
        config: {},
        requestApproval: vi.fn(),
      } as unknown as OpenClawPluginAPI;

      const config: PluginConfig = { logLevel: 'info' };
      const logger = createLogger(mockAPI, config);

      logger.info('test message', { data: 'value' });

      expect(consoleInfoSpy).toHaveBeenCalledWith('[clawsec] test message', { data: 'value' });
    });

    it('falls back to console when api.log throws', () => {
      const mockAPI = {
        log: vi.fn().mockImplementation(() => {
          throw new Error('API error');
        }),
        registerHook: vi.fn(),
        unregisterHook: vi.fn(),
        config: {},
        requestApproval: vi.fn(),
      } as unknown as OpenClawPluginAPI;

      const config: PluginConfig = { logLevel: 'info' };
      const logger = createLogger(mockAPI, config);

      logger.info('test message');

      expect(consoleInfoSpy).toHaveBeenCalledWith('[clawsec] test message');
    });
  });

  describe('createLogger without API', () => {
    it('uses console when api is null', () => {
      const logger = createLogger(null, { logLevel: 'info' });

      logger.info('test message');

      expect(consoleInfoSpy).toHaveBeenCalledWith('[clawsec] test message');
    });
  });

  describe('Log level filtering', () => {
    it('respects debug level (logs everything)', () => {
      const logger = createLogger(null, { logLevel: 'debug' });

      logger.debug('debug msg');
      logger.info('info msg');
      logger.warn('warn msg');
      logger.error('error msg');

      expect(consoleLogSpy).toHaveBeenCalledWith('[clawsec] debug msg');
      expect(consoleInfoSpy).toHaveBeenCalledWith('[clawsec] info msg');
      expect(consoleWarnSpy).toHaveBeenCalledWith('[clawsec] warn msg');
      expect(consoleErrorSpy).toHaveBeenCalledWith('[clawsec] error msg');
    });

    it('respects info level (skips debug)', () => {
      const logger = createLogger(null, { logLevel: 'info' });

      logger.debug('debug msg');
      logger.info('info msg');
      logger.warn('warn msg');
      logger.error('error msg');

      expect(consoleLogSpy).not.toHaveBeenCalled();
      expect(consoleInfoSpy).toHaveBeenCalledWith('[clawsec] info msg');
      expect(consoleWarnSpy).toHaveBeenCalledWith('[clawsec] warn msg');
      expect(consoleErrorSpy).toHaveBeenCalledWith('[clawsec] error msg');
    });

    it('respects warn level', () => {
      const logger = createLogger(null, { logLevel: 'warn' });

      logger.debug('debug msg');
      logger.info('info msg');
      logger.warn('warn msg');
      logger.error('error msg');

      expect(consoleLogSpy).not.toHaveBeenCalled();
      expect(consoleInfoSpy).not.toHaveBeenCalled();
      expect(consoleWarnSpy).toHaveBeenCalledWith('[clawsec] warn msg');
      expect(consoleErrorSpy).toHaveBeenCalledWith('[clawsec] error msg');
    });

    it('respects error level (only errors)', () => {
      const logger = createLogger(null, { logLevel: 'error' });

      logger.debug('debug msg');
      logger.info('info msg');
      logger.warn('warn msg');
      logger.error('error msg');

      expect(consoleLogSpy).not.toHaveBeenCalled();
      expect(consoleInfoSpy).not.toHaveBeenCalled();
      expect(consoleWarnSpy).not.toHaveBeenCalled();
      expect(consoleErrorSpy).toHaveBeenCalledWith('[clawsec] error msg');
    });

    it('defaults to info level when config is null', () => {
      const logger = createLogger(null, null);

      logger.debug('debug msg');
      logger.info('info msg');

      expect(consoleLogSpy).not.toHaveBeenCalled();
      expect(consoleInfoSpy).toHaveBeenCalledWith('[clawsec] info msg');
    });
  });

  describe('createNoOpLogger', () => {
    it('discards all log calls', () => {
      const logger = createNoOpLogger();

      logger.debug('debug msg');
      logger.info('info msg');
      logger.warn('warn msg');
      logger.error('error msg');

      expect(consoleLogSpy).not.toHaveBeenCalled();
      expect(consoleInfoSpy).not.toHaveBeenCalled();
      expect(consoleWarnSpy).not.toHaveBeenCalled();
      expect(consoleErrorSpy).not.toHaveBeenCalled();
    });
  });

  describe('Message formatting', () => {
    it('handles messages without data', () => {
      const logger = createLogger(null, { logLevel: 'info' });

      logger.info('simple message');

      expect(consoleInfoSpy).toHaveBeenCalledWith('[clawsec] simple message');
    });

    it('handles messages with data', () => {
      const logger = createLogger(null, { logLevel: 'info' });

      logger.info('message with data', { key: 'value' });

      expect(consoleInfoSpy).toHaveBeenCalledWith('[clawsec] message with data', { key: 'value' });
    });
  });
});
