/**
 * Slack Notification Integration
 * Sends security event notifications to Slack via webhooks
 */

import type {
  SlackConfig,
  SecurityEventPayload,
  NotificationResult,
  NotificationSender,
  Severity,
} from './types.js';

/**
 * Slack message attachment color based on severity
 */
const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#FF0000', // Red
  high: '#FFA500',     // Orange
  medium: '#FFFF00',   // Yellow
  low: '#00FF00',      // Green
};

/**
 * Severity emoji for Slack
 */
const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: ':rotating_light:',
  high: ':warning:',
  medium: ':large_yellow_circle:',
  low: ':information_source:',
};

/**
 * Format a security event as a Slack message payload
 */
function formatSlackMessage(
  event: SecurityEventPayload,
  config: SlackConfig
): Record<string, unknown> {
  const emoji = SEVERITY_EMOJI[event.severity];
  const color = SEVERITY_COLORS[event.severity];

  const attachment = {
    color,
    title: `${emoji} Security Alert: ${event.category.toUpperCase()}`,
    text: event.reason,
    fields: [
      {
        title: 'Severity',
        value: event.severity.toUpperCase(),
        short: true,
      },
      {
        title: 'Action',
        value: event.action.toUpperCase(),
        short: true,
      },
      {
        title: 'Tool',
        value: event.toolName,
        short: true,
      },
      {
        title: 'Event ID',
        value: event.eventId,
        short: true,
      },
    ],
    footer: 'Clawsec Security Plugin',
    ts: Math.floor(event.timestamp / 1000),
  };

  if (event.sessionId) {
    attachment.fields.push({
      title: 'Session',
      value: event.sessionId.substring(0, 8) + '...',
      short: true,
    });
  }

  const message: Record<string, unknown> = {
    attachments: [attachment],
  };

  if (config.channel) {
    message.channel = config.channel;
  }
  if (config.username) {
    message.username = config.username;
  }
  if (config.iconEmoji) {
    message.icon_emoji = config.iconEmoji;
  }

  return message;
}

/**
 * Format a test message for Slack
 */
function formatTestMessage(config: SlackConfig): Record<string, unknown> {
  const message: Record<string, unknown> = {
    text: ':white_check_mark: Clawsec notification test successful!',
    attachments: [
      {
        color: '#00FF00',
        text: 'Your Slack integration is working correctly.',
        footer: 'Clawsec Security Plugin',
        ts: Math.floor(Date.now() / 1000),
      },
    ],
  };

  if (config.channel) {
    message.channel = config.channel;
  }
  if (config.username) {
    message.username = config.username;
  }
  if (config.iconEmoji) {
    message.icon_emoji = config.iconEmoji;
  }

  return message;
}

/**
 * Check if event should trigger notification based on config
 */
function shouldNotify(
  event: SecurityEventPayload,
  config: SlackConfig
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
 * Create a Slack notification sender
 */
export function createSlackSender(config: SlackConfig): NotificationSender {
  return {
    async send(event: SecurityEventPayload): Promise<NotificationResult> {
      if (!config.enabled) {
        return {
          success: false,
          channel: 'slack',
          error: 'Slack notifications are disabled',
        };
      }

      if (!shouldNotify(event, config)) {
        return {
          success: true,
          channel: 'slack',
          response: 'Skipped due to filter settings',
        };
      }

      try {
        const message = formatSlackMessage(event, config);
        const response = await fetch(config.webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(message),
        });

        if (!response.ok) {
          const errorText = await response.text();
          return {
            success: false,
            channel: 'slack',
            error: `Slack API error: ${response.status} - ${errorText}`,
          };
        }

        return {
          success: true,
          channel: 'slack',
          response: await response.text(),
        };
      } catch (error) {
        return {
          success: false,
          channel: 'slack',
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    },

    async test(): Promise<NotificationResult> {
      if (!config.enabled) {
        return {
          success: false,
          channel: 'slack',
          error: 'Slack notifications are disabled',
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

        if (!response.ok) {
          const errorText = await response.text();
          return {
            success: false,
            channel: 'slack',
            error: `Slack API error: ${response.status} - ${errorText}`,
          };
        }

        return {
          success: true,
          channel: 'slack',
          response: 'Test message sent successfully',
        };
      } catch (error) {
        return {
          success: false,
          channel: 'slack',
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    },
  };
}
