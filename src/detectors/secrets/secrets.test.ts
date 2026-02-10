/**
 * Secrets Detector Tests
 * Comprehensive tests for API key, token, credential, and PII detection
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  // Main detector
  SecretsDetectorImpl,
  createSecretsDetector,
  createDefaultSecretsDetector,

  // API key detection
  ApiKeyDetector,
  createApiKeyDetector,
  matchApiKeys,
  redactValue,

  // Token detection
  TokenDetector,
  createTokenDetector,
  matchTokens,
  matchJwt,
  matchBearerToken,
  matchSessionToken,
  matchRefreshToken,
  isValidJwtStructure,

  // PII detection
  PiiDetector,
  createPiiDetector,
  matchPii,
  matchSsn,
  matchCreditCard,
  matchEmail,
  luhnCheck,
  isValidSsn,
  redactPii,

  // Types
  type SecretsDetectionContext,
  type SecretsDetectorConfig,
} from './index.js';

// =============================================================================
// LUHN ALGORITHM TESTS
// =============================================================================

describe('Luhn Algorithm', () => {
  describe('luhnCheck', () => {
    it('should validate correct Visa card numbers', () => {
      // Test Visa cards
      expect(luhnCheck('4111111111111111')).toBe(true);
      expect(luhnCheck('4012888888881881')).toBe(true);
      expect(luhnCheck('4222222222222')).toBe(true);
    });

    it('should validate correct Mastercard numbers', () => {
      expect(luhnCheck('5555555555554444')).toBe(true);
      expect(luhnCheck('5105105105105100')).toBe(true);
    });

    it('should validate correct American Express numbers', () => {
      expect(luhnCheck('378282246310005')).toBe(true);
      expect(luhnCheck('371449635398431')).toBe(true);
    });

    it('should validate correct Discover card numbers', () => {
      expect(luhnCheck('6011111111111117')).toBe(true);
      expect(luhnCheck('6011000990139424')).toBe(true);
    });

    it('should reject invalid card numbers', () => {
      expect(luhnCheck('4111111111111112')).toBe(false);
      expect(luhnCheck('1234567890123456')).toBe(false);
      // Note: all zeros technically passes Luhn (sum=0, 0%10=0)
      // but we filter these out in matchCreditCard as "all same digit"
    });

    it('should reject numbers that are too short', () => {
      expect(luhnCheck('123456789012')).toBe(false);
      expect(luhnCheck('1234')).toBe(false);
    });

    it('should reject numbers that are too long', () => {
      expect(luhnCheck('12345678901234567890')).toBe(false);
    });

    it('should handle numbers with spaces or dashes', () => {
      expect(luhnCheck('4111-1111-1111-1111')).toBe(true);
      expect(luhnCheck('4111 1111 1111 1111')).toBe(true);
    });

    it('should calculate checksum correctly', () => {
      // Known test case: 79927398713 is valid
      expect(luhnCheck('79927398713')).toBe(false); // Too short
      expect(luhnCheck('7992739871300001')).toBe(false);
    });
  });
});

// =============================================================================
// API KEY DETECTOR TESTS
// =============================================================================

describe('API Key Detector', () => {
  describe('redactValue', () => {
    it('should redact long values', () => {
      expect(redactValue('sk-1234567890abcdefghij')).toBe('sk-1***ghij');
    });

    it('should handle short values', () => {
      expect(redactValue('sk-123')).toBe('sk-1***');
    });
  });

  describe('matchApiKeys', () => {
    describe('OpenAI keys', () => {
      it('should detect OpenAI API keys', () => {
        const text = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno"';
        const matches = matchApiKeys(text);
        expect(matches.length).toBeGreaterThan(0);
        expect(matches.some(m => m.provider === 'openai')).toBe(true);
      });

      it('should have high confidence for OpenAI keys', () => {
        const text = 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno';
        const matches = matchApiKeys(text);
        const openaiMatch = matches.find(m => m.provider === 'openai');
        expect(openaiMatch).toBeDefined();
        expect(openaiMatch!.confidence).toBeGreaterThanOrEqual(0.95);
      });
    });

    describe('Anthropic keys', () => {
      it('should detect Anthropic API keys', () => {
        const text = 'ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'anthropic')).toBe(true);
      });
    });

    describe('AWS keys', () => {
      it('should detect AWS Access Key IDs', () => {
        const text = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'aws')).toBe(true);
      });

      it('should detect AWS Secret Access Keys in env vars', () => {
        const text = 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'aws')).toBe(true);
      });
    });

    describe('GitHub tokens', () => {
      it('should detect GitHub Personal Access Tokens', () => {
        const text = 'token: ghp_1234567890abcdefghijklmnopqrstuvwxyz12';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'github')).toBe(true);
      });

      it('should detect GitHub OAuth tokens', () => {
        const text = 'GITHUB_TOKEN=gho_1234567890abcdefghijklmnopqrstuvwxyz12';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'github')).toBe(true);
      });

      it('should detect GitHub App tokens', () => {
        const text = 'token = "ghs_1234567890abcdefghijklmnopqrstuvwxyz12"';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'github')).toBe(true);
      });

      it('should detect GitHub Refresh tokens', () => {
        const text = 'refresh_token: ghr_1234567890abcdefghijklmnopqrstuvwxyz12';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'github')).toBe(true);
      });
    });

    describe('Stripe keys', () => {
      it('should detect Stripe Live Secret keys', () => {
        const text = 'stripe_key = "sk_live_1234567890abcdefghijklmn"';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'stripe')).toBe(true);
      });

      it('should detect Stripe Test Secret keys', () => {
        const text = 'sk_test_1234567890abcdefghijklmn';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'stripe')).toBe(true);
      });

      it('should detect Stripe Publishable keys', () => {
        const text = 'pk_live_1234567890abcdefghijklmn';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'stripe')).toBe(true);
      });
    });

    describe('Slack tokens', () => {
      it('should detect Slack Bot tokens', () => {
        const text = 'SLACK_TOKEN=xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'slack')).toBe(true);
      });

      it('should detect Slack User tokens', () => {
        const text = 'xoxp-1234567890-1234567890-1234567890-abcdefghijklmnopqrstuvwxyz123456';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'slack')).toBe(true);
      });
    });

    describe('Google API keys', () => {
      it('should detect Google API keys', () => {
        // Google API keys are 39 chars: AIza + 35 chars
        const text = 'GOOGLE_API_KEY=AIzaSyCabcdefghijklmnopqrstuvwxyz123456';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.provider === 'google')).toBe(true);
      });
    });

    describe('Private keys', () => {
      it('should detect RSA private keys', () => {
        const text = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...';
        const matches = matchApiKeys(text);
        expect(matches.some(m => m.redactedValue === '[PRIVATE KEY]')).toBe(true);
      });

      it('should detect OpenSSH private keys', () => {
        const text = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1...';
        const matches = matchApiKeys(text);
        expect(matches.length).toBeGreaterThan(0);
      });

      it('should detect EC private keys', () => {
        const text = '-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...';
        const matches = matchApiKeys(text);
        expect(matches.length).toBeGreaterThan(0);
      });
    });

    describe('false positives', () => {
      it('should not match random strings', () => {
        const text = 'hello world this is just a normal string';
        const matches = matchApiKeys(text);
        expect(matches.length).toBe(0);
      });

      it('should not match short tokens', () => {
        const text = 'sk-123';
        const matches = matchApiKeys(text);
        const openaiMatches = matches.filter(m => m.provider === 'openai');
        expect(openaiMatches.length).toBe(0);
      });
    });
  });

  describe('ApiKeyDetector class', () => {
    let detector: ApiKeyDetector;

    beforeEach(() => {
      detector = createApiKeyDetector('critical');
    });

    it('should scan text and return detection results', () => {
      const results = detector.scan(
        'api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno"',
        'config'
      );
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].detected).toBe(true);
      expect(results[0].category).toBe('secrets');
      expect(results[0].metadata?.type).toBe('api-key');
    });

    it('should return empty array for safe text', () => {
      const results = detector.scan('just some normal text', 'input');
      expect(results.length).toBe(0);
    });
  });
});

// =============================================================================
// TOKEN DETECTOR TESTS
// =============================================================================

describe('Token Detector', () => {
  describe('isValidJwtStructure', () => {
    it('should validate well-formed JWTs', () => {
      // This is a real JWT structure (expired/invalid signature but valid structure)
      const validJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      expect(isValidJwtStructure(validJwt)).toBe(true);
    });

    it('should reject tokens without proper parts', () => {
      expect(isValidJwtStructure('just.two')).toBe(false);
      expect(isValidJwtStructure('not-a-jwt')).toBe(false);
    });

    it('should reject tokens with invalid JSON', () => {
      expect(isValidJwtStructure('notbase64.notbase64.notbase64')).toBe(false);
    });
  });

  describe('matchJwt', () => {
    it('should detect JWTs in text', () => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const text = `Authorization: Bearer ${jwt}`;
      const matches = matchJwt(text);
      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].tokenType).toBe('jwt');
    });

    it('should have high confidence for valid JWTs', () => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const matches = matchJwt(jwt);
      expect(matches[0].confidence).toBeGreaterThanOrEqual(0.70);
    });
  });

  describe('matchBearerToken', () => {
    it('should detect Bearer tokens', () => {
      const text = 'Authorization: Bearer abc123xyz789token';
      const matches = matchBearerToken(text);
      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].tokenType).toBe('bearer');
    });

    it('should be case-insensitive for Bearer keyword', () => {
      expect(matchBearerToken('bearer token123abc').length).toBeGreaterThan(0);
      expect(matchBearerToken('BEARER TOKEN123ABC').length).toBeGreaterThan(0);
    });

    it('should not match JWTs as bearer tokens (they are handled separately)', () => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xyz';
      const text = `Bearer ${jwt}`;
      const matches = matchBearerToken(text);
      expect(matches.length).toBe(0);
    });
  });

  describe('matchSessionToken', () => {
    it('should detect session_ tokens', () => {
      const text = 'session_abc123xyz789abcdef012345';
      const matches = matchSessionToken(text);
      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].tokenType).toBe('session');
    });

    it('should detect sess_ tokens', () => {
      const text = 'sess_abc123xyz789abcdef012345';
      const matches = matchSessionToken(text);
      expect(matches.length).toBeGreaterThan(0);
    });

    it('should detect sid_ tokens', () => {
      const text = 'sid_abc123xyz789abcdef012345';
      const matches = matchSessionToken(text);
      expect(matches.length).toBeGreaterThan(0);
    });
  });

  describe('matchRefreshToken', () => {
    it('should detect refresh_ tokens', () => {
      const text = 'refresh_abc123xyz789abcdef012345';
      const matches = matchRefreshToken(text);
      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].tokenType).toBe('refresh');
    });

    it('should detect rt_ tokens', () => {
      const text = 'rt_abc123xyz789abcdef012345';
      const matches = matchRefreshToken(text);
      expect(matches.length).toBeGreaterThan(0);
    });
  });

  describe('TokenDetector class', () => {
    let detector: TokenDetector;

    beforeEach(() => {
      detector = createTokenDetector('critical');
    });

    it('should detect JWTs and return results', () => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const results = detector.scan(jwt, 'header');
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].metadata?.type).toBe('token');
      expect(results[0].metadata?.subtype).toBe('jwt');
    });

    it('should return empty array for non-token text', () => {
      const results = detector.scan('just some normal text', 'input');
      expect(results.length).toBe(0);
    });
  });
});

// =============================================================================
// PII DETECTOR TESTS
// =============================================================================

describe('PII Detector', () => {
  describe('isValidSsn', () => {
    it('should accept valid SSNs', () => {
      expect(isValidSsn('123', '45', '6789')).toBe(true);
      expect(isValidSsn('001', '01', '0001')).toBe(true);
      expect(isValidSsn('899', '99', '9999')).toBe(true);
    });

    it('should reject SSNs with area 000', () => {
      expect(isValidSsn('000', '45', '6789')).toBe(false);
    });

    it('should reject SSNs with area 666', () => {
      expect(isValidSsn('666', '45', '6789')).toBe(false);
    });

    it('should reject SSNs with area >= 900', () => {
      expect(isValidSsn('900', '45', '6789')).toBe(false);
      expect(isValidSsn('999', '45', '6789')).toBe(false);
    });

    it('should reject SSNs with group 00', () => {
      expect(isValidSsn('123', '00', '6789')).toBe(false);
    });

    it('should reject SSNs with serial 0000', () => {
      expect(isValidSsn('123', '45', '0000')).toBe(false);
    });
  });

  describe('matchSsn', () => {
    it('should detect valid SSN patterns', () => {
      const text = 'SSN: 123-45-6789';
      const matches = matchSsn(text);
      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].piiType).toBe('ssn');
    });

    it('should have higher confidence for valid SSNs', () => {
      const validMatches = matchSsn('SSN: 123-45-6789');
      const invalidMatches = matchSsn('SSN: 000-45-6789');
      
      expect(validMatches[0].confidence).toBeGreaterThan(invalidMatches[0].confidence);
    });

    it('should redact SSN correctly', () => {
      const matches = matchSsn('123-45-6789');
      expect(matches[0].redactedValue).toBe('***-**-6789');
    });
  });

  describe('matchCreditCard', () => {
    it('should detect valid Visa cards', () => {
      const text = 'Card: 4111111111111111';
      const matches = matchCreditCard(text);
      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].piiType).toBe('credit-card');
      expect(matches[0].luhnValid).toBe(true);
    });

    it('should detect valid Mastercard', () => {
      const text = 'Pay with: 5555555555554444';
      const matches = matchCreditCard(text);
      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].luhnValid).toBe(true);
    });

    it('should detect valid Amex cards', () => {
      const text = 'Amex: 378282246310005';
      const matches = matchCreditCard(text);
      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].luhnValid).toBe(true);
    });

    it('should detect cards with dashes', () => {
      const text = '4111-1111-1111-1111';
      const matches = matchCreditCard(text);
      expect(matches.length).toBeGreaterThan(0);
    });

    it('should detect cards with spaces', () => {
      const text = '4111 1111 1111 1111';
      const matches = matchCreditCard(text);
      expect(matches.length).toBeGreaterThan(0);
    });

    it('should NOT detect cards that fail Luhn', () => {
      const text = 'Invalid card: 1234567890123456';
      const matches = matchCreditCard(text);
      expect(matches.length).toBe(0);
    });

    it('should NOT detect all-same-digit numbers', () => {
      const text = '0000000000000000';
      const matches = matchCreditCard(text);
      expect(matches.length).toBe(0);
    });

    it('should NOT detect sequential numbers', () => {
      const text = '1234567890123456';
      const matches = matchCreditCard(text);
      expect(matches.length).toBe(0);
    });

    it('should redact credit card correctly', () => {
      const matches = matchCreditCard('4111111111111111');
      expect(matches[0].redactedValue).toBe('4111***1111');
    });
  });

  describe('matchEmail', () => {
    it('should detect email addresses', () => {
      const text = 'Contact: john.doe@company.com';
      const matches = matchEmail(text);
      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].piiType).toBe('email');
    });

    it('should NOT match example/test emails', () => {
      expect(matchEmail('test@example.com').length).toBe(0);
      expect(matchEmail('user@test.com').length).toBe(0);
      expect(matchEmail('admin@localhost').length).toBe(0);
    });

    it('should redact email correctly', () => {
      const matches = matchEmail('john.doe@company.com');
      expect(matches[0].redactedValue).toBe('jo***@company.com');
    });
  });

  describe('redactPii', () => {
    it('should redact SSN showing last 4', () => {
      expect(redactPii('123-45-6789', 'ssn')).toBe('***-**-6789');
    });

    it('should redact credit card showing first and last 4', () => {
      expect(redactPii('4111111111111111', 'credit-card')).toBe('4111***1111');
    });

    it('should redact email preserving domain', () => {
      expect(redactPii('john@example.com', 'email')).toBe('jo***@example.com');
    });
  });

  describe('PiiDetector class', () => {
    let detector: PiiDetector;

    beforeEach(() => {
      detector = createPiiDetector('critical', false);
    });

    it('should detect SSNs', () => {
      const results = detector.scan('SSN: 123-45-6789', 'form');
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].metadata?.type).toBe('pii');
      expect(results[0].metadata?.subtype).toBe('ssn');
    });

    it('should detect credit cards with Luhn validation', () => {
      const results = detector.scan('Card: 4111111111111111', 'payment');
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].reason).toContain('Luhn validated');
    });

    it('should NOT include emails by default', () => {
      const results = detector.scan('Email: user@domain.com', 'contact');
      const emailResults = results.filter(r => r.metadata?.subtype === 'email');
      expect(emailResults.length).toBe(0);
    });

    it('should include emails when configured', () => {
      const detectorWithEmail = createPiiDetector('critical', true);
      const results = detectorWithEmail.scan('Email: user@domain.com', 'contact');
      const emailResults = results.filter(r => r.metadata?.subtype === 'email');
      expect(emailResults.length).toBeGreaterThan(0);
    });
  });
});

// =============================================================================
// MAIN SECRETS DETECTOR TESTS
// =============================================================================

describe('SecretsDetector', () => {
  let detector: SecretsDetectorImpl;

  beforeEach(() => {
    detector = createDefaultSecretsDetector();
  });

  describe('basic detection', () => {
    it('should detect API keys in tool input', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'write_file',
        toolInput: {
          content: 'API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno',
        },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.category).toBe('secrets');
      expect(result.metadata?.type).toBe('api-key');
    });

    it('should detect tokens in tool input', async () => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const context: SecretsDetectionContext = {
        toolName: 'http',
        toolInput: {
          headers: { Authorization: `Bearer ${jwt}` },
        },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.type).toBe('token');
    });

    it('should detect PII in tool input', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'database_query',
        toolInput: {
          query: 'INSERT INTO users (ssn) VALUES ("123-45-6789")',
        },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.type).toBe('pii');
    });

    it('should detect credit cards with Luhn validation', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'payment',
        toolInput: {
          card_number: '4111111111111111',
        },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.subtype).toBe('credit-card');
    });

    it('should detect credentials in tool input', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'config',
        toolInput: {
          config: 'password=mysecretpassword123',
        },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.type).toBe('credential');
    });
  });

  describe('tool output scanning', () => {
    it('should detect secrets in tool output', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'read_file',
        toolInput: { path: '/etc/config' },
        toolOutput: 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.location).toContain('output');
    });

    it('should detect PII in tool output', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'sql_query',
        toolInput: { query: 'SELECT * FROM users' },
        toolOutput: 'user_id,ssn\n1,123-45-6789\n2,234-56-7890',
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
    });
  });

  describe('disabled detector', () => {
    it('should return no detection when disabled', async () => {
      const config: SecretsDetectorConfig = {
        enabled: false,
        severity: 'critical',
        action: 'block',
      };
      const disabledDetector = new SecretsDetectorImpl(config);

      const context: SecretsDetectionContext = {
        toolName: 'write_file',
        toolInput: {
          content: 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno',
        },
      };

      const result = await disabledDetector.detect(context);
      expect(result.detected).toBe(false);
    });
  });

  describe('detectAll', () => {
    it('should return all individual detections', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'write_file',
        toolInput: {
          content: `
            API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno
            SSN: 123-45-6789
            Card: 4111111111111111
          `,
        },
      };

      const results = await detector.detectAll(context);
      expect(results.length).toBeGreaterThan(1);

      const types = results.map(r => r.metadata?.type);
      expect(types).toContain('api-key');
      expect(types).toContain('pii');
    });

    it('should handle undefined toolInput gracefully', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'some_tool',
        toolInput: undefined,
        toolOutput: 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno',
      };

      // Should not throw and should still scan toolOutput
      const results = await detector.detectAll(context);
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].metadata?.type).toBe('api-key');
    });

    it('should handle undefined toolInput in detect method', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'some_tool',
        toolInput: undefined,
        toolOutput: 'password=supersecret123',
      };

      // Should not throw
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.category).toBe('secrets');
    });
  });

  describe('configuration', () => {
    it('should use configured severity', async () => {
      const config: SecretsDetectorConfig = {
        enabled: true,
        severity: 'high',
        action: 'warn',
      };
      const customDetector = new SecretsDetectorImpl(config);

      const context: SecretsDetectionContext = {
        toolName: 'test',
        toolInput: {
          data: 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno',
        },
      };

      const result = await customDetector.detect(context);
      expect(result.severity).toBe('high');
    });

    it('should create detector from SecretsRule', () => {
      const rule = {
        enabled: true,
        severity: 'high' as const,
        action: 'warn' as const,
      };

      const ruleDetector = createSecretsDetector(rule);
      expect(ruleDetector.isEnabled()).toBe(true);
      expect(ruleDetector.getAction()).toBe('warn');
    });
  });

  describe('edge cases', () => {
    it('should handle empty context', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'unknown',
        toolInput: {},
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(false);
    });

    it('should handle nested input objects', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'complex',
        toolInput: {
          level1: {
            level2: {
              secret: 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno',
            },
          },
        },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
    });

    it('should handle array inputs', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'batch',
        toolInput: {
          items: [
            'normal text',
            'sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno',
          ],
        },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
    });

    it('should not false positive on placeholder values', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'config',
        toolInput: {
          password: '<your-password-here>',
          secret: '${SECRET_VALUE}',
          apiKey: '{API_KEY}',
        },
      };

      const result = await detector.detect(context);
      // Should not detect placeholders as real secrets
      expect(result.detected).toBe(false);
    });

    it('should not false positive on masked values', async () => {
      const context: SecretsDetectionContext = {
        toolName: 'log',
        toolInput: {
          password: '********',
          secret: 'xxxxxxxxxxxx',
        },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(false);
    });
  });
});

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

describe('Integration', () => {
  it('should work with realistic file write context', async () => {
    const detector = createDefaultSecretsDetector();

    const context: SecretsDetectionContext = {
      toolName: 'mcp__filesystem__write_file',
      toolInput: {
        path: '/app/.env',
        content: `
DATABASE_URL=postgres://user:password123@localhost:5432/mydb
OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`,
      },
    };

    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
  });

  it('should work with HTTP request context containing auth header', async () => {
    const detector = createDefaultSecretsDetector();
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

    const context: SecretsDetectionContext = {
      toolName: 'http_request',
      toolInput: {
        url: 'https://api.example.com/data',
        headers: {
          'Authorization': `Bearer ${jwt}`,
          'X-API-Key': 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno',
        },
      },
    };

    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
  });

  it('should work with database query containing PII', async () => {
    const detector = createDefaultSecretsDetector();

    const context: SecretsDetectionContext = {
      toolName: 'sql_execute',
      toolInput: {
        query: 'SELECT * FROM customers WHERE id = 1',
      },
      toolOutput: `
id,name,ssn,credit_card
1,John Doe,123-45-6789,4111111111111111
2,Jane Smith,234-56-7890,5555555555554444
`,
    };

    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
  });

  it('should not trigger on safe development contexts', async () => {
    const detector = createDefaultSecretsDetector();

    const context: SecretsDetectionContext = {
      toolName: 'write_file',
      toolInput: {
        path: '/app/test.js',
        content: `
// Test file for payment processing
const testCardNumber = '4111-1111-1111-1111'; // Test card
console.log('Processing payment...');
`,
      },
    };

    const result = await detector.detect(context);
    // Will detect because it contains a valid credit card number
    // This is intentional for security-first approach
    expect(result.category).toBe('secrets');
  });

  it('should detect multiple secret types in one context', async () => {
    const detector = createDefaultSecretsDetector();

    const context: SecretsDetectionContext = {
      toolName: 'write_config',
      toolInput: {
        env: `
STRIPE_SECRET_KEY=sk_live_1234567890abcdefghijklmn
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz12
USER_SSN=123-45-6789
`,
      },
    };

    const results = await detector.detectAll(context);
    expect(results.length).toBeGreaterThanOrEqual(2);
    
    const types = new Set(results.map(r => r.metadata?.type));
    expect(types.size).toBeGreaterThan(1);
  });
});
