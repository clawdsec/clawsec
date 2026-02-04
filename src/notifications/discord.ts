/**
 * Discord Notification Integration
 * Sends security event notifications to Discord via webhooks
 */

import type {
  DiscordConfig,
  SecurityEventPayload,
  NotificationResult,
  NotificationSender,
  Severity,
} from './types.js';

/**
 * Discord embed color based on severity (decimal format)
 */
const SEVERITY_COLORS: Record<Severity, number> = {
  critical: 0xFF0000, // Red
  high: 0xFFA500,     // Orange
  medium: 0xFFFF00,   // Yellow
  low: 0x00FF00,      // Green
};

/**
 * Severity emoji for Discord
 */
const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🚨',
  high: '⚠️',
  medium: '🟡',
  low: 'ℹ️',
};

/**
 * Format a security event as a Discord webhook payload
 */
function formatDiscordMessage(
  event: SecurityEventPayload,
  config: DiscordConfig
): Record<string, unknown> {
  const timestamp = new Date(event.timestamp).toISOString();
  const emoji = SEVERITY_EMOJI[event.severity];
  const color = SEVERITY_COLORS[event.severity];

  const embed = {
    title: `${emoji} Security Alert: ${event.category.toUpperCase()}`,
    description: event.reason,
    color,
    fields: [
      {
        name: 'Severity',
        value: event.severity.toUpperCase(),
        inline: true,
      },
      {
        name: 'Action',
        value: event.action.toUpperCase(),
        inline: true,
      },
      {
        name: 'Tool',
        value: event.toolName,
        inline: true,
      },
      {
        name: 'Event ID',
        value: event.eventId,
        inline: true,
      },
    ],
    footer: {
      text: 'Clawsec Security Plugin',
    },
    timestamp,
  };

  if (event.sessionId) {
    embed.fields.push({
      name: 'Session',
      value: event.sessionId.substring(0, 8) + '...',
      inline: true,
    });
  }

  const message: Record<string, unknown> = {
    embeds: [embed],
  };

  if (config.username) {
    message.username = config.username;
  }
  if (config.avatarUrl) {
    message.avatar_url = config.avatarUrl;
  }

  return message;
}

/**
 * Format a test message for Discord
 */
function formatTestMessage(config: DiscordConfig): Record<string, unknown> {
  const message: Record<string, unknown> = {
    embeds: [
      {
        title: '✅ Clawsec Test Notification',
        description: 'Your Discord integration is working correctly.',
        color: 0x00FF00,
        footer: {
          text: 'Clawsec Security Plugin',
        },
        timestamp: new Date().toISOString(),
      },
    ],
  };

  if (config.username) {
    message.username = config.username;
  }
  if (config.avatarUrl) {
    message.avatar_url = config.avatarUrl;
  }

  return message;
}

/**
 * Check if event should trigger notification based on config
 */
function shouldNotify(
  event: SecurityEventPayload,
  config: DiscordConfig
): boolean {
  // Check minimum severity
  if (config.minSeverity) {
    const severityOrder: Severity[] = ['low', 'medium', 'high', 'critical'];
    const minIndex = severityOrder.indexOf(config.minSeverity);
    const eventIndex = severityOrder.indexOf(event.severity);
    if (eventIndex < minIndex) {
      return false;
    }
  }

  // Check category filter
  if (config.categories && config.categories.length > 0) {
    if (!config.categories.includes(event.category)) {
      return false;
    }
  }

  return true;
}

/**
 * Create a Discord notification sender
 */
export function createDiscordSender(config: DiscordConfig): NotificationSender {
  return {
    async send(event: SecurityEventPayload): Promise<NotificationResult> {
      if (!config.enabled) {
        return {
          success: false,
          channel: 'discord',
          error: 'Discord notifications are disabled',
        };
      }

      if (!shouldNotify(event, config)) {
        return {
          success: true,
          channel: 'discord',
          response: 'Skipped due to filter settings',
        };
      }

      try {
        const message = formatDiscordMessage(event, config);
        const response = await fetch(config.webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(message),
        });

        // Discord returns 204 No Content on success
        if (!response.ok && response.status !== 204) {
          const errorText = await response.text();
          return {
            success: false,
            channel: 'discord',
            error: `Discord API error: ${response.status} - ${errorText}`,
          };
        }

        return {
          success: true,
          channel: 'discord',
          response: 'Message sent successfully',
        };
      } catch (error) {
        return {
          success: false,
          channel: 'discord',
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    },

    async test(): Promise<NotificationResult> {
      if (!config.enabled) {
        return {
          success: false,
          channel: 'discord',
          error: 'Discord notifications are disabled',
        };
      }

      try {
        const message = formatTestMessage(config);
        const response = await fetch(config.webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(message),
        });

        if (!response.ok && response.status !== 204) {
          const errorText = await response.text();
          return {
            success: false,
            channel: 'discord',
            error: `Discord API error: ${response.status} - ${errorText}`,
          };
        }

        return {
          success: true,
          channel: 'discord',
          response: 'Test message sent successfully',
        };
      } catch (error) {
        return {
          success: false,
          channel: 'discord',
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    },
  };
}
