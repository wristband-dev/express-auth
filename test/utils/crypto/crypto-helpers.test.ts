import { createHash } from 'crypto';

import { createCodeChallenge, generateRandomString } from '../../../src/utils/crypto';

describe('Crypto Helpers', () => {
  describe('generateRandomString', () => {
    test('Generates string of correct length', () => {
      const result = generateRandomString(32);

      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
    });

    test('Generates different strings on multiple calls', () => {
      const result1 = generateRandomString(32);
      const result2 = generateRandomString(32);

      expect(result1).not.toBe(result2);
    });

    test('Does not contain URL-unsafe characters', () => {
      const result = generateRandomString(64);

      expect(result).not.toMatch(/[+/=]/);
    });

    test('Generates empty string for length 0', () => {
      const result = generateRandomString(0);

      expect(result).toBe('');
    });
  });

  describe('createCodeChallenge', () => {
    test('Matches the code challenge from the PKCE specification example (RFC 7636, Appendix B)', async () => {
      const result = await createCodeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');

      expect(result).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    });

    test('Matches the base64url-encoded SHA-256 hash from Node crypto', async () => {
      const codeVerifier = 'test-code-verifier';

      const result = await createCodeChallenge(codeVerifier);

      expect(result).toBe(createHash('sha256').update(codeVerifier).digest('base64url'));
    });

    test('Does not contain URL-unsafe characters', async () => {
      // The SHA-256 hash of "test-code-verifier" contains "/" and "=" in standard base64.
      const result = await createCodeChallenge('test-code-verifier');

      expect(result).not.toMatch(/[+/=]/);
    });

    test('Returns the same code challenge for the same code verifier', async () => {
      const result1 = await createCodeChallenge('same-verifier');
      const result2 = await createCodeChallenge('same-verifier');

      expect(result1).toBe(result2);
    });

    test('Returns different code challenges for different code verifiers', async () => {
      const result1 = await createCodeChallenge('verifier-1');
      const result2 = await createCodeChallenge('verifier-2');

      expect(result1).not.toBe(result2);
    });
  });
});
