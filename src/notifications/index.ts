/**
 * Notifications Module
 * Unified notification system for security events
 */

export * from './types.js';
export { createSlackSender } from './slack.js';
export { createDiscordSender } from './discord.js';
export { createTelegramSender } from './telegram.js';

import type {
  NotificationConfig,
  SecurityEventPayload,
  NotificationResult,
  NotificationSender,
} from './types.js';
import { createSlackSender } from './slack.js';
import { createDiscordSender } from './discord.js';
import { createTelegramSender } from './telegram.js';

/**
 * Unified notification manager
 */
export interface NotificationManager {
  /** Send notification to all configured channels */
  notify(event: SecurityEventPayload): Promise<NotificationResult[]>;
  /** Test all configured channels */
  testAll(): Promise<NotificationResult[]>;
  /** Get list of enabled channels */
  getEnabledChannels(): string[];
}

/**
 * Create a notification manager from configuration
 */
export function createNotificationManager(
  config: NotificationConfig
): NotificationManager {
  const senders: NotificationSender[] = [];

  // Create Slack sender if configured
  if (config.slack?.enabled && config.slack.webhookUrl) {
    senders.push(createSlackSender(config.slack));
  }

  // Create Discord sender if configured
  if (config.discord?.enabled && config.discord.webhookUrl) {
    senders.push(createDiscordSender(config.discord));
  }

  // Create Telegram sender if configured
  if (config.telegram?.enabled && config.telegram.botToken && config.telegram.chatId) {
    senders.push(createTelegramSender(config.telegram));
  }

  return {
    async notify(event: SecurityEventPayload): Promise<NotificationResult[]> {
      if (senders.length === 0) {
        return [];
      }

      // Send to all channels concurrently
      const results = await Promise.all(
        senders.map((sender) => sender.send(event))
      );

      return results;
    },

    async testAll(): Promise<NotificationResult[]> {
      if (senders.length === 0) {
        return [];
      }

      // Test all channels concurrently
      const results = await Promise.all(
        senders.map((sender) => sender.test())
      );

      return results;
    },

    getEnabledChannels(): string[] {
      const channels: string[] = [];
      if (config.slack?.enabled) channels.push('slack');
      if (config.discord?.enabled) channels.push('discord');
      if (config.telegram?.enabled) channels.push('telegram');
      return channels;
    },
  };
}

/**
 * Create a security event payload
 */
export function createSecurityEvent(params: {
  category: SecurityEventPayload['category'];
  severity: SecurityEventPayload['severity'];
  toolName: string;
  reason: string;
  action: SecurityEventPayload['action'];
  sessionId?: string;
  metadata?: Record<string, unknown>;
}): SecurityEventPayload {
  return {
    eventId: crypto.randomUUID(),
    timestamp: Date.now(),
    ...params,
  };
}
