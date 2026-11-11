/* eslint-disable import/no-extraneous-dependencies */

import httpMocks from 'node-mocks-http';
import {
  createLoginState,
  encryptLoginState,
  decryptLoginState,
  getLoginStateCookie,
  clearOldestLoginStateCookie,
  createLoginStateCookie,
} from '../../src/utils/login-state';
import { CookieCrypto } from '../../src/utils/crypto';
import { CryptoError } from '../../src/error/crypto-error';
import { LoginState, LoginStateMapConfig } from '../../src/types';

describe('Login State Utils', () => {
  describe('createLoginState', () => {
    const redirectUri = 'https://example.com/callback';

    test('Creates basic login state', () => {
      const result = createLoginState(redirectUri);

      expect(result.state).toBeDefined();
      expect(result.codeVerifier).toBeDefined();
      expect(result.redirectUri).toBe(redirectUri);
      expect(result.returnUrl).toBeUndefined();
      expect(result.customState).toBeUndefined();
    });

    test('Does not include returnUrl or customState keys when not provided', () => {
      const result = createLoginState(redirectUri, {});

      expect(Object.keys(result).sort()).toEqual(['codeVerifier', 'redirectUri', 'state']);
    });

    test('Generates a different state and codeVerifier on each call', () => {
      const result1 = createLoginState(redirectUri);
      const result2 = createLoginState(redirectUri);

      expect(result1.state).not.toBe(result2.state);
      expect(result1.codeVerifier).not.toBe(result2.codeVerifier);
    });

    test('Includes return URL from config', () => {
      const config: LoginStateMapConfig = { returnUrl: 'https://example.com/dashboard' };

      const result = createLoginState(redirectUri, config);

      expect(result.returnUrl).toBe('https://example.com/dashboard');
    });

    test('Excludes return URL when it is an empty string', () => {
      const config: LoginStateMapConfig = { returnUrl: '' };

      const result = createLoginState(redirectUri, config);

      expect(result).not.toHaveProperty('returnUrl');
    });

    test('Includes custom state from config', () => {
      const customState = { userId: '123', feature: 'test' };
      const config: LoginStateMapConfig = { customState };

      const result = createLoginState(redirectUri, config);

      expect(result.customState).toEqual(customState);
    });

    test('Excludes empty custom state object', () => {
      const config: LoginStateMapConfig = { customState: {} };

      const result = createLoginState(redirectUri, config);

      expect(result).not.toHaveProperty('customState');
    });

    test('Includes both return URL and custom state', () => {
      const customState = { userId: '123' };
      const config: LoginStateMapConfig = {
        returnUrl: 'https://example.com/dashboard',
        customState,
      };

      const result = createLoginState(redirectUri, config);

      expect(result.returnUrl).toBe('https://example.com/dashboard');
      expect(result.customState).toEqual(customState);
    });
  });

  describe('encryptLoginState and decryptLoginState', () => {
    const loginStateSecret = '12345678901234567890123456789012'; // 32 chars

    test('Encrypts and decrypts login state successfully', async () => {
      const loginState: LoginState = {
        state: 'test-state',
        codeVerifier: 'test-verifier',
        redirectUri: 'https://example.com/callback',
      };

      const encrypted = await encryptLoginState(loginState, loginStateSecret);
      const decrypted = await decryptLoginState(encrypted, loginStateSecret);

      expect(decrypted).toEqual(loginState);
    });

    test('Encrypts and decrypts login state with custom state', async () => {
      const loginState: LoginState = {
        state: 'test-state',
        codeVerifier: 'test-verifier',
        redirectUri: 'https://example.com/callback',
        customState: { userId: '123', feature: 'test' },
      };

      const encrypted = await encryptLoginState(loginState, loginStateSecret);
      const decrypted = await decryptLoginState(encrypted, loginStateSecret);

      expect(decrypted).toEqual(loginState);
    });

    test('Encrypts and decrypts login state with return URL', async () => {
      const loginState: LoginState = {
        state: 'test-state',
        codeVerifier: 'test-verifier',
        redirectUri: 'https://example.com/callback',
        returnUrl: 'https://example.com/dashboard',
      };

      const encrypted = await encryptLoginState(loginState, loginStateSecret);
      const decrypted = await decryptLoginState(encrypted, loginStateSecret);

      expect(decrypted).toEqual(loginState);
    });

    test('Encrypts and decrypts login state with domain', async () => {
      const loginState: LoginState = {
        state: 'test-state',
        codeVerifier: 'test-verifier',
        redirectUri: 'https://example.com/callback',
      };

      const encrypted = await encryptLoginState(loginState, loginStateSecret);
      const decrypted = await decryptLoginState(encrypted, loginStateSecret);

      expect(decrypted).toEqual(loginState);
    });

    test('Throws error when encrypted state exceeds 4kB', async () => {
      const largeCustomState = {
        data: 'x'.repeat(5000), // Large data to exceed 4kB
      };

      const loginState: LoginState = {
        state: 'test-state',
        codeVerifier: 'test-verifier',
        redirectUri: 'https://example.com/callback',
        customState: largeCustomState,
      };

      await expect(encryptLoginState(loginState, loginStateSecret)).rejects.toThrow(
        'Login state cookie exceeds 4kB in size'
      );
    });

    test('Throws TypeError when customState is not JSON-serializable', async () => {
      const loginState: LoginState = {
        state: 'test-state',
        codeVerifier: 'test-verifier',
        redirectUri: 'https://example.com/callback',
        customState: { id: BigInt(1) },
      };

      await expect(encryptLoginState(loginState, loginStateSecret)).rejects.toThrow(TypeError);
      await expect(encryptLoginState(loginState, loginStateSecret)).rejects.toThrow(
        'The [customState] value must be JSON-serializable.'
      );
    });

    test('Passes through other crypto errors from encryption unchanged', async () => {
      const loginState: LoginState = {
        state: 'test-state',
        codeVerifier: 'test-verifier',
        redirectUri: 'https://example.com/callback',
      };

      await expect(encryptLoginState(loginState, 'too-short-secret')).rejects.toThrow(CryptoError);
      await expect(encryptLoginState(loginState, 'too-short-secret')).rejects.toMatchObject({
        code: 'INVALID_SECRET',
      });
    });

    test('Returns null when decrypting with the wrong secret', async () => {
      const loginState: LoginState = {
        state: 'test-state',
        codeVerifier: 'test-verifier',
        redirectUri: 'https://example.com/callback',
      };
      const encrypted = await encryptLoginState(loginState, loginStateSecret);

      await expect(decryptLoginState(encrypted, 'x'.repeat(32))).resolves.toBeNull();
    });

    test('Decrypts a login state cookie that is still within its 1 hour max age', async () => {
      const loginState: LoginState = {
        state: 'test-state',
        codeVerifier: 'test-verifier',
        redirectUri: 'https://example.com/callback',
      };
      const startTime = Date.now();
      const encrypted = await encryptLoginState(loginState, loginStateSecret);

      jest.spyOn(Date, 'now').mockReturnValue(startTime + 3600 * 1000);
      try {
        await expect(decryptLoginState(encrypted, loginStateSecret)).resolves.toEqual(loginState);
      } finally {
        jest.restoreAllMocks();
      }
    });

    test('Returns null when the login state cookie is older than its 1 hour max age', async () => {
      const loginState: LoginState = {
        state: 'test-state',
        codeVerifier: 'test-verifier',
        redirectUri: 'https://example.com/callback',
      };
      const startTime = Date.now();
      const encrypted = await encryptLoginState(loginState, loginStateSecret);

      // 1 hour max age plus the 60-second clock skew tolerance, plus 1 second
      jest.spyOn(Date, 'now').mockReturnValue(startTime + (3600 + 60 + 1) * 1000);
      try {
        await expect(decryptLoginState(encrypted, loginStateSecret)).resolves.toBeNull();
      } finally {
        jest.restoreAllMocks();
      }
    });

    test('Returns null when the login state cookie is malformed', async () => {
      await expect(decryptLoginState('not-a-valid-cookie', loginStateSecret)).resolves.toBeNull();
    });

    test('Rethrows non-crypto errors from decryption unchanged', async () => {
      const unexpectedError = new Error('Unexpected failure');
      jest.spyOn(CookieCrypto, 'decrypt').mockRejectedValue(unexpectedError);
      try {
        await expect(decryptLoginState('any-cookie-value', loginStateSecret)).rejects.toBe(unexpectedError);
      } finally {
        jest.restoreAllMocks();
      }
    });
  });
  describe('getLoginStateCookie', () => {
    test('Finds matching login state cookie by name and value, without clearing it', () => {
      const state = 'test-state-123';
      const req = httpMocks.createRequest({
        query: { state },
        headers: {
          cookie: `login#${state}#1234567890=encrypted-value; other=cookie`,
        },
      }) as any;

      const result = getLoginStateCookie(req);

      expect(result.cookieName).toBe(`login#${state}#1234567890`);
      expect(result.loginStateCookie).toBe('encrypted-value');
    });

    test('Returns empty cookieName and loginStateCookie when no matching cookie found', () => {
      const req = httpMocks.createRequest({
        query: { state: 'non-existent-state' },
        headers: {
          cookie: 'login#different-state#1234567890=encrypted-value',
        },
      }) as any;

      const result = getLoginStateCookie(req);

      expect(result.cookieName).toBe('');
      expect(result.loginStateCookie).toBe('');
    });

    test('Returns empty cookieName and loginStateCookie when no state in query', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: 'login#some-state#1234567890=encrypted-value',
        },
      }) as any;

      const result = getLoginStateCookie(req);

      expect(result.cookieName).toBe('');
      expect(result.loginStateCookie).toBe('');
    });

    test('Returns empty cookieName and loginStateCookie when no cookies are present at all', () => {
      const req = httpMocks.createRequest({
        query: { state: 'test-state' },
      }) as any;

      const result = getLoginStateCookie(req);

      expect(result.cookieName).toBe('');
      expect(result.loginStateCookie).toBe('');
    });

    test('Handles array state query parameter', () => {
      const req = httpMocks.createRequest({
        query: { state: ['state1', 'state2'] },
        headers: {
          cookie: 'login#state1,state2#1234567890=encrypted-value',
        },
      }) as any;

      const result = getLoginStateCookie(req);

      expect(result.cookieName).toBe('login#state1,state2#1234567890');
      expect(result.loginStateCookie).toBe('encrypted-value');
    });

    test('Never calls any cookie-clearing behavior (no Set-Cookie header involved)', () => {
      // getLoginStateCookie is lookup-only now; clearing the cookie is the caller's
      // responsibility (done separately via clearCookie once the domain is known).
      const state = 'test-state';
      const req = httpMocks.createRequest({
        query: { state },
        headers: {
          cookie: `login#${state}#1234567890=encrypted-value`,
        },
      }) as any;

      // No Response object is even needed/accepted by this function anymore.
      const result = getLoginStateCookie(req);

      expect(result.loginStateCookie).toBe('encrypted-value');
    });
  });
  describe('clearOldestLoginStateCookie', () => {
    test('Clears oldest cookie when 3 or more login cookies exist', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: [
            'login#state1#1000000000=value1',
            'login#state2#2000000000=value2',
            'login#state3#3000000000=value3',
            'other#cookie=value',
          ].join('; '),
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      clearOldestLoginStateCookie(req, res, false);

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      // Should clear the oldest cookie (state1 with timestamp 1000000000)
      expect(setCookieHeaders).toContain('login#state1#1000000000=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure');
      // Should not clear the newer cookies
      expect(setCookieHeaders).not.toContain(
        'login#state2#2000000000=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure'
      );
      expect(setCookieHeaders).not.toContain(
        'login#state3#3000000000=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure'
      );
    });

    test('Does nothing when fewer than 3 login cookies exist', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: ['login#state1#1000000000=value1', 'login#state2#2000000000=value2', 'other#cookie=value'].join('; '),
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      clearOldestLoginStateCookie(req, res, false);

      const setCookieHeaders = res.getHeader('Set-Cookie');
      expect(setCookieHeaders).toBeUndefined();
    });

    test('Uses dangerouslyDisableSecureCookies flag when clearing', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: [
            'login#state1#1000000000=value1',
            'login#state2#2000000000=value2',
            'login#state3#3000000000=value3',
          ].join('; '),
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      clearOldestLoginStateCookie(req, res, true);

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      expect(setCookieHeaders).toContain('login#state1#1000000000=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
    });

    test('Handles exactly 3 cookies by clearing the oldest', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: [
            'login#state1#1000000000=value1',
            'login#state2#2000000000=value2',
            'login#state3#3000000000=value3',
          ].join('; '),
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      clearOldestLoginStateCookie(req, res, false);

      const setCookieHeaders = res.getHeader('Set-Cookie') as string | string[];
      // Should be a single cookie header string, not an array
      expect(typeof setCookieHeaders).toBe('string');
      expect(setCookieHeaders).toContain('login#state1#1000000000=');
    });

    test('Handles more than 3 cookies by clearing multiple old ones', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: [
            'login#state1#1000000000=value1',
            'login#state2#2000000000=value2',
            'login#state3#3000000000=value3',
            'login#state4#4000000000=value4',
            'login#state5#5000000000=value5',
          ].join('; '),
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      clearOldestLoginStateCookie(req, res, false);

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      // Should clear the 3 oldest cookies, keeping only the 2 newest
      expect(setCookieHeaders).toHaveLength(3);
      expect(
        setCookieHeaders.some((h) => {
          return h.includes('login#state1#1000000000=');
        })
      ).toBe(true);
      expect(
        setCookieHeaders.some((h) => {
          return h.includes('login#state2#2000000000=');
        })
      ).toBe(true);
      expect(
        setCookieHeaders.some((h) => {
          return h.includes('login#state3#3000000000=');
        })
      ).toBe(true);
    });

    test('Passes domain through when clearing the oldest cookie', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: [
            'login#state1#1000000000=value1',
            'login#state2#2000000000=value2',
            'login#state3#3000000000=value3',
          ].join('; '),
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      clearOldestLoginStateCookie(req, res, false, '.example.com');

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      expect(setCookieHeaders).toContain(
        'login#state1#1000000000=; HttpOnly; Domain=.example.com; Path=/; Max-Age=0; SameSite=Lax; Secure'
      );
    });
  });
  describe('createLoginStateCookie', () => {
    test('Creates login state cookie with correct format', () => {
      const res = httpMocks.createResponse() as any;
      const state = 'test-state';
      const encryptedValue = 'encrypted-login-state';

      // Mock Date.now to get predictable timestamp
      const mockTimestamp = 1234567890000;
      jest.spyOn(Date, 'now').mockReturnValue(mockTimestamp);

      createLoginStateCookie(res, state, encryptedValue, false);

      const setCookieHeader = res.getHeader('Set-Cookie') as string;
      expect(setCookieHeader).toBe(
        `login#${state}#${mockTimestamp}=${encryptedValue}; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax; Secure`
      );

      jest.restoreAllMocks();
    });

    test('Creates cookie without Secure flag when dangerouslyDisableSecureCookies is true', () => {
      const res = httpMocks.createResponse() as any;
      const state = 'test-state';
      const encryptedValue = 'encrypted-login-state';

      const mockTimestamp = 1234567890000;
      jest.spyOn(Date, 'now').mockReturnValue(mockTimestamp);

      createLoginStateCookie(res, state, encryptedValue, true);

      const setCookieHeader = res.getHeader('Set-Cookie') as string;
      expect(setCookieHeader).toBe(
        `login#${state}#${mockTimestamp}=${encryptedValue}; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax`
      );

      jest.restoreAllMocks();
    });

    test('Passes domain through to the login state cookie when provided', () => {
      const res = httpMocks.createResponse() as any;
      const state = 'test-state';
      const encryptedValue = 'encrypted-login-state';

      const mockTimestamp = 1234567890000;
      jest.spyOn(Date, 'now').mockReturnValue(mockTimestamp);

      createLoginStateCookie(res, state, encryptedValue, false, 'example.com');

      const setCookieHeader = res.getHeader('Set-Cookie') as string;
      expect(setCookieHeader).toBe(
        `login#${state}#${mockTimestamp}=${encryptedValue}; HttpOnly; Domain=example.com; Path=/; Max-Age=3600; SameSite=Lax; Secure`
      );

      jest.restoreAllMocks();
    });

    test('Passes domain through along with dangerouslyDisableSecureCookies', () => {
      const res = httpMocks.createResponse() as any;
      const state = 'test-state';
      const encryptedValue = 'encrypted-login-state';

      const mockTimestamp = 1234567890000;
      jest.spyOn(Date, 'now').mockReturnValue(mockTimestamp);

      createLoginStateCookie(res, state, encryptedValue, true, '.example.com');

      const setCookieHeader = res.getHeader('Set-Cookie') as string;
      expect(setCookieHeader).toBe(
        `login#${state}#${mockTimestamp}=${encryptedValue}; HttpOnly; Domain=.example.com; Path=/; Max-Age=3600; SameSite=Lax`
      );

      jest.restoreAllMocks();
    });
  });
});
