/**
 * Telegram Notification Integration
 * Sends security event notifications to Telegram via Bot API
 */

import type {
  TelegramConfig,
  SecurityEventPayload,
  NotificationResult,
  NotificationSender,
  Severity,
} from './types.js';

/**
 * Severity emoji for Telegram
 */
const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🚨',
  high: '⚠️',
  medium: '🟡',
  low: 'ℹ️',
};

/**
 * Escape special characters for Telegram MarkdownV2
 */
function escapeMarkdownV2(text: string): string {
  return text.replace(/[_*[\]()~`>#+=|{}.!-]/g, '\\$&');
}

/**
 * Escape special characters for Telegram HTML
 */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Format a security event as a Telegram message (HTML format)
 */
function formatTelegramMessageHtml(event: SecurityEventPayload): string {
  const emoji = SEVERITY_EMOJI[event.severity];
  const timestamp = new Date(event.timestamp).toISOString();

  return `${emoji} <b>Security Alert: ${escapeHtml(event.category.toUpperCase())}</b>

<b>Reason:</b> ${escapeHtml(event.reason)}

<b>Details:</b>
• Severity: ${escapeHtml(event.severity.toUpperCase())}
• Action: ${escapeHtml(event.action.toUpperCase())}
• Tool: ${escapeHtml(event.toolName)}
• Event ID: <code>${escapeHtml(event.eventId)}</code>
${event.sessionId ? `• Session: <code>${escapeHtml(event.sessionId.substring(0, 8))}...</code>` : ''}

<i>Clawsec Security Plugin • ${escapeHtml(timestamp)}</i>`;
}

/**
 * Format a security event as a Telegram message (Markdown format)
 */
function formatTelegramMessageMarkdown(event: SecurityEventPayload): string {
  const emoji = SEVERITY_EMOJI[event.severity];
  const timestamp = new Date(event.timestamp).toISOString();

  return `${emoji} *Security Alert: ${event.category.toUpperCase()}*

*Reason:* ${event.reason}

*Details:*
• Severity: ${event.severity.toUpperCase()}
• Action: ${event.action.toUpperCase()}
• Tool: ${event.toolName}
• Event ID: \`${event.eventId}\`
${event.sessionId ? `• Session: \`${event.sessionId.substring(0, 8)}...\`` : ''}

_Clawsec Security Plugin • ${timestamp}_`;
}

/**
 * Format a security event as a Telegram message (MarkdownV2 format)
 */
function formatTelegramMessageMarkdownV2(event: SecurityEventPayload): string {
  const emoji = SEVERITY_EMOJI[event.severity];
  const timestamp = new Date(event.timestamp).toISOString();

  return `${emoji} *Security Alert: ${escapeMarkdownV2(event.category.toUpperCase())}*

*Reason:* ${escapeMarkdownV2(event.reason)}

*Details:*
• Severity: ${escapeMarkdownV2(event.severity.toUpperCase())}
• Action: ${escapeMarkdownV2(event.action.toUpperCase())}
• Tool: ${escapeMarkdownV2(event.toolName)}
• Event ID: \`${escapeMarkdownV2(event.eventId)}\`
${event.sessionId ? `• Session: \`${escapeMarkdownV2(event.sessionId.substring(0, 8))}\\.\\.\\.\`` : ''}

_Clawsec Security Plugin • ${escapeMarkdownV2(timestamp)}_`;
}

/**
 * Format a security event as a Telegram message
 */
function formatTelegramMessage(
  event: SecurityEventPayload,
  parseMode?: 'HTML' | 'Markdown' | 'MarkdownV2'
): string {
  switch (parseMode) {
    case 'HTML':
      return formatTelegramMessageHtml(event);
    case 'MarkdownV2':
      return formatTelegramMessageMarkdownV2(event);
    case 'Markdown':
    default:
      return formatTelegramMessageMarkdown(event);
  }
}

/**
 * Format a test message for Telegram
 */
function formatTestMessage(parseMode?: 'HTML' | 'Markdown' | 'MarkdownV2'): string {
  switch (parseMode) {
    case 'HTML':
      return '✅ <b>Clawsec Test Notification</b>\n\nYour Telegram integration is working correctly.\n\n<i>Clawsec Security Plugin</i>';
    case 'MarkdownV2':
      return '✅ *Clawsec Test Notification*\n\nYour Telegram integration is working correctly\\.\n\n_Clawsec Security Plugin_';
    case 'Markdown':
    default:
      return '✅ *Clawsec Test Notification*\n\nYour Telegram integration is working correctly.\n\n_Clawsec Security Plugin_';
  }
}

/**
 * Check if event should trigger notification based on config
 */
function shouldNotify(
  event: SecurityEventPayload,
  config: TelegramConfig
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
 * Create a Telegram notification sender
 */
export function createTelegramSender(config: TelegramConfig): NotificationSender {
  const baseUrl = `https://api.telegram.org/bot${config.botToken}`;

  return {
    async send(event: SecurityEventPayload): Promise<NotificationResult> {
      if (!config.enabled) {
        return {
          success: false,
          channel: 'telegram',
          error: 'Telegram notifications are disabled',
        };
      }

      if (!shouldNotify(event, config)) {
        return {
          success: true,
          channel: 'telegram',
          response: 'Skipped due to filter settings',
        };
      }

      try {
        const text = formatTelegramMessage(event, config.parseMode);
        const payload: Record<string, unknown> = {
          chat_id: config.chatId,
          text,
        };

        if (config.parseMode) {
          payload.parse_mode = config.parseMode;
        }

        const response = await fetch(`${baseUrl}/sendMessage`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
        });

        const result = await response.json() as { ok: boolean; description?: string };

        if (!result.ok) {
          return {
            success: false,
            channel: 'telegram',
            error: `Telegram API error: ${result.description || 'Unknown error'}`,
          };
        }

        return {
          success: true,
          channel: 'telegram',
          response: result,
        };
      } catch (error) {
        return {
          success: false,
          channel: 'telegram',
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    },

    async test(): Promise<NotificationResult> {
      if (!config.enabled) {
        return {
          success: false,
          channel: 'telegram',
          error: 'Telegram notifications are disabled',
        };
      }

      try {
        const text = formatTestMessage(config.parseMode);
        const payload: Record<string, unknown> = {
          chat_id: config.chatId,
          text,
        };

        if (config.parseMode) {
          payload.parse_mode = config.parseMode;
        }

        const response = await fetch(`${baseUrl}/sendMessage`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
        });

        const result = await response.json() as { ok: boolean; description?: string };

        if (!result.ok) {
          return {
            success: false,
            channel: 'telegram',
            error: `Telegram API error: ${result.description || 'Unknown error'}`,
          };
        }

        return {
          success: true,
          channel: 'telegram',
          response: 'Test message sent successfully',
        };
      } catch (error) {
        return {
          success: false,
          channel: 'telegram',
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    },
  };
}
