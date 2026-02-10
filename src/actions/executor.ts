/**
 * Action Executor
 * Main executor that routes to appropriate action handlers based on analysis results
 */

import type { ActionContext, ActionExecutor, ActionResult, ActionLogger, ActionHandler } from './types.js';
import { noOpLogger, createLogger } from './types.js';
import { createBlockHandler } from './block.js';
import { createConfirmHandler } from './confirm.js';
import { createWarnHandler } from './warn.js';
import { createLogHandler } from './log.js';
import { createLogger as createUtilLogger, type Logger } from '../utils/logger.js';

/**
 * Configuration for the action executor
 */
export interface ExecutorConfig {
  /** Logger to use for action logging */
  logger?: ActionLogger | Logger;
  /** Custom block handler */
  blockHandler?: ActionHandler;
  /** Custom confirm handler */
  confirmHandler?: ActionHandler;
  /** Custom warn handler */
  warnHandler?: ActionHandler;
  /** Custom log handler */
  logHandler?: ActionHandler;
}

/**
 * Default action executor implementation
 */
export class DefaultActionExecutor implements ActionExecutor {
  private logger: Logger;
  private actionLogger: ActionLogger;
  private blockHandler: ActionHandler;
  private confirmHandler: ActionHandler;
  private warnHandler: ActionHandler;
  private logHandler: ActionHandler;

  constructor(config: ExecutorConfig = {}) {
    // Accept both Logger and ActionLogger types
    const providedLogger = config.logger;

    // If logger is provided and has the Logger interface, use it for internal logging
    this.logger = providedLogger && 'debug' in providedLogger
      ? (providedLogger as Logger)
      : createUtilLogger(null, null);

    // For action handlers, adapt Logger to ActionLogger if needed
    if (providedLogger && 'debug' in providedLogger) {
      // It's a Logger - create ActionLogger adapter
      const logger = providedLogger as Logger;
      this.actionLogger = {
        debug: (msg: string, context?: Record<string, unknown>) => logger.debug(msg, context),
        warn: (msg: string, context?: Record<string, unknown>) => logger.warn(msg, context),
        info: (msg: string, context?: Record<string, unknown>) => logger.info(msg, context),
        error: (msg: string, context?: Record<string, unknown>) => logger.error(msg, context),
      };
    } else if (providedLogger) {
      // It's already an ActionLogger
      this.actionLogger = providedLogger as ActionLogger;
    } else {
      // No logger provided
      this.actionLogger = noOpLogger;
    }

    this.blockHandler = config.blockHandler ?? createBlockHandler(this.actionLogger);
    this.confirmHandler = config.confirmHandler ?? createConfirmHandler(this.actionLogger);
    this.warnHandler = config.warnHandler ?? createWarnHandler(this.actionLogger);
    this.logHandler = config.logHandler ?? createLogHandler(this.actionLogger);
  }

  /**
   * Execute the appropriate action based on analysis result
   */
  async execute(context: ActionContext): Promise<ActionResult> {
    const { analysis, config } = context;
    const action = analysis.action;

    this.logger.debug(`[Executor] Entry: action=${action}, detections=${analysis.detections.length}`);

    // Check if the plugin is disabled
    if (config.global?.enabled === false) {
      this.logger.debug('Plugin disabled, allowing action');
      this.logger.debug(`[Executor] Exit: plugin disabled, allowing`);
      return {
        allowed: true,
        logged: false,
      };
    }

    // Route to appropriate handler based on action
    this.logger.debug(`[Executor] Routing to ${action} handler`);
    
    let result: ActionResult;
    switch (action) {
      case 'allow':
        result = await this.handleAllow(context);
        break;
      case 'block':
        result = await this.handleBlock(context);
        break;
      case 'confirm':
        result = await this.handleConfirm(context);
        break;
      case 'warn':
        result = await this.handleWarn(context);
        break;
      case 'log':
        result = await this.handleLog(context);
        break;
      default:
        // Unknown action, log and allow as a safety measure
        this.logger.warn('Unknown action type, defaulting to allow', {
          action: action as string,
        });
        result = {
          allowed: true,
          message: `Unknown action type: ${action}`,
          logged: true,
        };
    }

    this.logger.debug(`[Executor] Exit: action=${action}, allowed=${result.allowed}`);
    return result;
  }

  /**
   * Handle allow action - no detection, pass through
   */
  private async handleAllow(context: ActionContext): Promise<ActionResult> {
    this.logger.debug('Action allowed', {
      toolName: context.toolCall.toolName,
    });

    return {
      allowed: true,
      logged: false,
    };
  }

  /**
   * Handle block action
   */
  private async handleBlock(context: ActionContext): Promise<ActionResult> {
    return this.blockHandler.execute(context);
  }

  /**
   * Handle confirm action
   */
  private async handleConfirm(context: ActionContext): Promise<ActionResult> {
    return this.confirmHandler.execute(context);
  }

  /**
   * Handle warn action
   */
  private async handleWarn(context: ActionContext): Promise<ActionResult> {
    return this.warnHandler.execute(context);
  }

  /**
   * Handle log action
   */
  private async handleLog(context: ActionContext): Promise<ActionResult> {
    return this.logHandler.execute(context);
  }
}

/**
 * Create an action executor with the given configuration
 */
export function createActionExecutor(config?: ExecutorConfig): ActionExecutor {
  return new DefaultActionExecutor(config);
}

/**
 * Create an action executor with default logger based on config log level
 */
export function createDefaultActionExecutor(logLevel: 'debug' | 'info' | 'warn' | 'error' = 'info'): ActionExecutor {
  const logger = createLogger(logLevel);
  return new DefaultActionExecutor({ logger });
}
