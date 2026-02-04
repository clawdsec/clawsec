/**
 * Tests for the notification system
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createSlackSender } from './slack.js';
import { createDiscordSender } from './discord.js';
import { createTelegramSender } from './telegram.js';
import {
  createNotificationManager,
  createSecurityEvent,
} from './index.js';
import type {
  SlackConfig,
  DiscordConfig,
  TelegramConfig,
  SecurityEventPayload,
} from './types.js';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Sample security event for testing
const sampleEvent: SecurityEventPayload = {
  eventId: 'test-event-123',
  timestamp: Date.now(),
  category: 'destructive',
  severity: 'critical',
  toolName: 'Bash',
  reason: 'Detected dangerous command: rm -rf /',
  action: 'blocked',
  sessionId: 'session-456',
};

describe('Slack Notification', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const config: SlackConfig = {
    enabled: true,
    webhookUrl: 'https://hooks.slack.com/services/xxx/yyy/zzz',
    channel: '#security-alerts',
    username: 'Clawsec Bot',
    iconEmoji: ':shield:',
  };

  it('should send notification successfully', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve('ok'),
    });

    const sender = createSlackSender(config);
    const result = await sender.send(sampleEvent);

    expect(result.success).toBe(true);
    expect(result.channel).toBe('slack');
    expect(mockFetch).toHaveBeenCalledWith(
      config.webhookUrl,
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
    );
  });

  it('should handle API errors', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      text: () => Promise.resolve('invalid_payload'),
    });

    const sender = createSlackSender(config);
    const result = await sender.send(sampleEvent);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Slack API error');
  });

  it('should handle network errors', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network error'));

    const sender = createSlackSender(config);
    const result = await sender.send(sampleEvent);

    expect(result.success).toBe(false);
    expect(result.error).toBe('Network error');
  });

  it('should return error when disabled', async () => {
    const disabledConfig = { ...config, enabled: false };
    const sender = createSlackSender(disabledConfig);
    const result = await sender.send(sampleEvent);

    expect(result.success).toBe(false);
    expect(result.error).toContain('disabled');
  });

  it('should filter by minimum severity', async () => {
    const severityConfig: SlackConfig = {
      ...config,
      minSeverity: 'critical',
    };
    const sender = createSlackSender(severityConfig);

    // Low severity event should be skipped
    const lowEvent = { ...sampleEvent, severity: 'low' as const };
    const result = await sender.send(lowEvent);

    expect(result.success).toBe(true);
    expect(result.response).toContain('Skipped');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('should filter by category', async () => {
    const categoryConfig: SlackConfig = {
      ...config,
      categories: ['purchase'],
    };
    const sender = createSlackSender(categoryConfig);

    const result = await sender.send(sampleEvent); // destructive category

    expect(result.success).toBe(true);
    expect(result.response).toContain('Skipped');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('should send test message successfully', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve('ok'),
    });

    const sender = createSlackSender(config);
    const result = await sender.test();

    expect(result.success).toBe(true);
    expect(result.response).toContain('Test message sent');
  });
});

describe('Discord Notification', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const config: DiscordConfig = {
    enabled: true,
    webhookUrl: 'https://discord.com/api/webhooks/xxx/yyy',
    username: 'Clawsec',
    avatarUrl: 'https://example.com/avatar.png',
  };

  it('should send notification successfully', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 204,
      text: () => Promise.resolve(''),
    });

    const sender = createDiscordSender(config);
    const result = await sender.send(sampleEvent);

    expect(result.success).toBe(true);
    expect(result.channel).toBe('discord');
    expect(mockFetch).toHaveBeenCalledWith(
      config.webhookUrl,
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
    );
  });

  it('should handle API errors', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      text: () => Promise.resolve('Bad Request'),
    });

    const sender = createDiscordSender(config);
    const result = await sender.send(sampleEvent);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Discord API error');
  });

  it('should handle network errors', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

    const sender = createDiscordSender(config);
    const result = await sender.send(sampleEvent);

    expect(result.success).toBe(false);
    expect(result.error).toBe('Connection refused');
  });

  it('should return error when disabled', async () => {
    const disabledConfig = { ...config, enabled: false };
    const sender = createDiscordSender(disabledConfig);
    const result = await sender.send(sampleEvent);

    expect(result.success).toBe(false);
    expect(result.error).toContain('disabled');
  });

  it('should filter by minimum severity', async () => {
    const severityConfig: DiscordConfig = {
      ...config,
      minSeverity: 'high',
    };
    const sender = createDiscordSender(severityConfig);

    const lowEvent = { ...sampleEvent, severity: 'low' as const };
    const result = await sender.send(lowEvent);

    expect(result.success).toBe(true);
    expect(result.response).toContain('Skipped');
  });

  it('should send test message successfully', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 204,
      text: () => Promise.resolve(''),
    });

    const sender = createDiscordSender(config);
    const result = await sender.test();

    expect(result.success).toBe(true);
  });
});

describe('Telegram Notification', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const config: TelegramConfig = {
    enabled: true,
    botToken: '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11',
    chatId: '-1001234567890',
    parseMode: 'HTML',
  };

  it('should send notification successfully', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ ok: true, result: {} }),
    });

    const sender = createTelegramSender(config);
    const result = await sender.send(sampleEvent);

    expect(result.success).toBe(true);
    expect(result.channel).toBe('telegram');
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/sendMessage'),
      expect.objectContaining({
        method: 'POST',
      })
    );
  });

  it('should handle API errors', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ ok: false, description: 'Bad Request' }),
    });

    const sender = createTelegramSender(config);
    const result = await sender.send(sampleEvent);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Telegram API error');
  });

  it('should handle network errors', async () => {
    mockFetch.mockRejectedValueOnce(new Error('DNS lookup failed'));

    const sender = createTelegramSender(config);
    const result = await sender.send(sampleEvent);

    expect(result.success).toBe(false);
    expect(result.error).toBe('DNS lookup failed');
  });

  it('should return error when disabled', async () => {
    const disabledConfig = { ...config, enabled: false };
    const sender = createTelegramSender(disabledConfig);
    const result = await sender.send(sampleEvent);

    expect(result.success).toBe(false);
    expect(result.error).toContain('disabled');
  });

  it('should filter by category', async () => {
    const categoryConfig: TelegramConfig = {
      ...config,
      categories: ['secrets'],
    };
    const sender = createTelegramSender(categoryConfig);

    const result = await sender.send(sampleEvent); // destructive category

    expect(result.success).toBe(true);
    expect(result.response).toContain('Skipped');
  });

  it('should send test message successfully', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ ok: true }),
    });

    const sender = createTelegramSender(config);
    const result = await sender.test();

    expect(result.success).toBe(true);
  });

  it('should format messages with different parse modes', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ ok: true }),
    });

    // Test HTML
    const htmlSender = createTelegramSender({ ...config, parseMode: 'HTML' });
    await htmlSender.send(sampleEvent);

    // Test Markdown
    const mdSender = createTelegramSender({ ...config, parseMode: 'Markdown' });
    await mdSender.send(sampleEvent);

    // Test MarkdownV2
    const mdv2Sender = createTelegramSender({ ...config, parseMode: 'MarkdownV2' });
    await mdv2Sender.send(sampleEvent);

    expect(mockFetch).toHaveBeenCalledTimes(3);
  });
});

describe('Notification Manager', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should send to all enabled channels', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      status: 204,
      text: () => Promise.resolve('ok'),
      json: () => Promise.resolve({ ok: true }),
    });

    const manager = createNotificationManager({
      slack: {
        enabled: true,
        webhookUrl: 'https://hooks.slack.com/xxx',
      },
      discord: {
        enabled: true,
        webhookUrl: 'https://discord.com/api/webhooks/xxx',
      },
    });

    const results = await manager.notify(sampleEvent);

    expect(results).toHaveLength(2);
    expect(results.every((r) => r.success)).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('should return empty array when no channels configured', async () => {
    const manager = createNotificationManager({});
    const results = await manager.notify(sampleEvent);

    expect(results).toHaveLength(0);
  });

  it('should test all channels', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      status: 204,
      text: () => Promise.resolve('ok'),
      json: () => Promise.resolve({ ok: true }),
    });

    const manager = createNotificationManager({
      slack: {
        enabled: true,
        webhookUrl: 'https://hooks.slack.com/xxx',
      },
      discord: {
        enabled: true,
        webhookUrl: 'https://discord.com/api/webhooks/xxx',
      },
      telegram: {
        enabled: true,
        botToken: '123:ABC',
        chatId: '123',
      },
    });

    const results = await manager.testAll();

    expect(results).toHaveLength(3);
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it('should return enabled channels', () => {
    const manager = createNotificationManager({
      slack: {
        enabled: true,
        webhookUrl: 'https://hooks.slack.com/xxx',
      },
      discord: {
        enabled: false,
        webhookUrl: 'https://discord.com/api/webhooks/xxx',
      },
      telegram: {
        enabled: true,
        botToken: '123:ABC',
        chatId: '123',
      },
    });

    const channels = manager.getEnabledChannels();

    expect(channels).toContain('slack');
    expect(channels).toContain('telegram');
    expect(channels).not.toContain('discord');
  });
});

describe('createSecurityEvent', () => {
  it('should create a valid security event', () => {
    const event = createSecurityEvent({
      category: 'purchase',
      severity: 'high',
      toolName: 'WebFetch',
      reason: 'Attempted purchase on amazon.com',
      action: 'blocked',
      sessionId: 'session-123',
    });

    expect(event.eventId).toBeDefined();
    expect(event.timestamp).toBeDefined();
    expect(event.category).toBe('purchase');
    expect(event.severity).toBe('high');
    expect(event.toolName).toBe('WebFetch');
    expect(event.reason).toBe('Attempted purchase on amazon.com');
    expect(event.action).toBe('blocked');
    expect(event.sessionId).toBe('session-123');
  });

  it('should generate unique event IDs', () => {
    const event1 = createSecurityEvent({
      category: 'secrets',
      severity: 'critical',
      toolName: 'Read',
      reason: 'API key detected',
      action: 'blocked',
    });

    const event2 = createSecurityEvent({
      category: 'secrets',
      severity: 'critical',
      toolName: 'Read',
      reason: 'API key detected',
      action: 'blocked',
    });

    expect(event1.eventId).not.toBe(event2.eventId);
  });
});
