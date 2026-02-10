/**
 * Notification Types
 * Type definitions for the notification system
 */

/**
 * Severity levels for security detections
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Categories of security threats
 */
export type ThreatCategory = 'purchase' | 'website' | 'destructive' | 'secrets' | 'exfiltration' | 'unknown';

/**
 * Supported notification channels
 */
export type NotificationChannel = 'slack' | 'discord' | 'telegram';

/**
 * Security event notification payload
 */
export interface SecurityEventPayload {
  /** Unique event ID */
  eventId: string;
  /** Event timestamp */
  timestamp: number;
  /** Threat category */
  category: ThreatCategory;
  /** Severity level */
  severity: Severity;
  /** Tool that triggered the event */
  toolName: string;
  /** Brief description of the threat */
  reason: string;
  /** Action taken */
  action: 'blocked' | 'confirmed' | 'warned' | 'logged';
  /** Session ID */
  sessionId?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Notification result
 */
export interface NotificationResult {
  /** Whether the notification was sent successfully */
  success: boolean;
  /** Channel used */
  channel: NotificationChannel;
  /** Error message if failed */
  error?: string;
  /** Response from the notification service */
  response?: unknown;
}

/**
 * Base notification configuration
 */
export interface BaseNotificationConfig {
  /** Whether this notification channel is enabled */
  enabled: boolean;
  /** Minimum severity to trigger notification */
  minSeverity?: Severity;
  /** Categories to notify for (empty = all) */
  categories?: ThreatCategory[];
}

/**
 * Slack notification configuration
 */
export interface SlackConfig extends BaseNotificationConfig {
  /** Slack webhook URL */
  webhookUrl: string;
  /** Channel to post to (optional, uses webhook default) */
  channel?: string;
  /** Username for the bot */
  username?: string;
  /** Icon emoji for the bot */
  iconEmoji?: string;
}

/**
 * Discord notification configuration
 */
export interface DiscordConfig extends BaseNotificationConfig {
  /** Discord webhook URL */
  webhookUrl: string;
  /** Username for the bot */
  username?: string;
  /** Avatar URL for the bot */
  avatarUrl?: string;
}

/**
 * Telegram notification configuration
 */
export interface TelegramConfig extends BaseNotificationConfig {
  /** Telegram bot token */
  botToken: string;
  /** Chat ID to send messages to */
  chatId: string;
  /** Parse mode for messages */
  parseMode?: 'HTML' | 'Markdown' | 'MarkdownV2';
}

/**
 * Complete notification configuration
 */
export interface NotificationConfig {
  /** Slack configuration */
  slack?: SlackConfig;
  /** Discord configuration */
  discord?: DiscordConfig;
  /** Telegram configuration */
  telegram?: TelegramConfig;
}

/**
 * Notification sender interface
 */
export interface NotificationSender {
  /** Send a security event notification */
  send(event: SecurityEventPayload): Promise<NotificationResult>;
  /** Test the notification configuration */
  test(): Promise<NotificationResult>;
}
