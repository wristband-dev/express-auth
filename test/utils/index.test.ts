/* eslint-disable import/no-extraneous-dependencies */

import httpMocks from 'node-mocks-http';
import {
  parseTenantSubdomain,
  generateRandomString,
  base64URLEncode,
  encryptLoginState,
  decryptLoginState,
  getLoginStateCookie,
  resolveTenantCustomDomainParam,
  resolveTenantName,
  resolveRedirectUrl,
  createLoginState,
  clearOldestLoginStateCookie,
  createLoginStateCookie,
  encodeBase64,
  getAuthorizationUrlParams,
  getTenantLevelAuthorizationUrl,
  getAppLevelLoginUrl,
  getAppLevelAuthorizationUrl,
  isExpired,
  validateReturnUrl,
  deriveFallbackLoginUrl,
  deriveTenantRootDomain,
  isTenantPlaceholderPositionValid,
} from '../../src/utils';
import { LoginState, LoginStateMapConfig } from '../../src/types';
import { STATE_PARAM_MAX_CHAR_LENGTH } from '../../src/utils/constants';

describe('Auth Utils', () => {
  describe('parseTenantSubdomain', () => {
    test('Extracts tenant subdomain when host matches root domain', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'tenant.business.example.com' },
      }) as any;

      const result = parseTenantSubdomain(req, 'business.example.com');

      expect(result).toBe('tenant');
    });

    test('Returns empty string when host does not match root domain', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'different.domain.com' },
      }) as any;

      const result = parseTenantSubdomain(req, 'business.example.com');

      expect(result).toBe('');
    });

    test('Returns empty string when host is root domain itself', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'business.example.com' },
      }) as any;

      const result = parseTenantSubdomain(req, 'business.example.com');

      expect(result).toBe('');
    });

    test('Handles complex subdomain extraction', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'multi-word-tenant.business.example.com' },
      }) as any;

      const result = parseTenantSubdomain(req, 'business.example.com');

      expect(result).toBe('multi-word-tenant');
    });

    test('Strips port from host before extracting subdomain', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'tenant.business.example.com:3000' },
      }) as any;

      const result = parseTenantSubdomain(req, 'business.example.com');

      expect(result).toBe('tenant');
    });

    test('Handles root domain with port', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'business.example.com:8080' },
      }) as any;

      const result = parseTenantSubdomain(req, 'business.example.com');

      expect(result).toBe('');
    });

    test('Handles standard HTTP port (80)', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'tenant.business.example.com:80' },
      }) as any;

      const result = parseTenantSubdomain(req, 'business.example.com');

      expect(result).toBe('tenant');
    });

    test('Handles localhost with port', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'tenant.localhost:6001' },
      }) as any;

      const result = parseTenantSubdomain(req, 'localhost');

      expect(result).toBe('tenant');
    });

    test('Returns empty string for non-matching domain with port', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'different.domain.com:3000' },
      }) as any;

      const result = parseTenantSubdomain(req, 'business.example.com');

      expect(result).toBe('');
    });

    test('Handles complex subdomain with port', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'multi-word-tenant.business.example.com:9000' },
      }) as any;

      const result = parseTenantSubdomain(req, 'business.example.com');

      expect(result).toBe('multi-word-tenant');
    });

    it('should return empty string when host is missing', () => {
      const mockReq = { headers: {} } as any;
      const result = parseTenantSubdomain(mockReq, 'example.com');
      expect(result).toBe('');
    });
  });

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

  describe('base64URLEncode', () => {
    test('Replaces URL-unsafe characters', () => {
      const input = 'hello+world/test=';
      const result = base64URLEncode(input);

      expect(result).toBe('hello-world_test');
    });

    test('Leaves safe characters unchanged', () => {
      const input = 'abcABC123_-';
      const result = base64URLEncode(input);

      expect(result).toBe('abcABC123_-');
    });

    test('Handles empty string', () => {
      const result = base64URLEncode('');

      expect(result).toBe('');
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

  describe('resolveTenantName', () => {
    test('Returns subdomain when parseTenantFromRootDomain is provided', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'tenant.business.example.com' },
      }) as any;

      const result = resolveTenantName(req, 'business.example.com');

      expect(result).toBe('tenant');
    });

    test('Returns tenant_name query param when no parseTenantFromRootDomain', () => {
      const req = httpMocks.createRequest({
        query: { tenant_name: 'test-tenant' },
      }) as any;

      const result = resolveTenantName(req, '');

      expect(result).toBe('test-tenant');
    });

    test('Returns empty string when no tenant resolution possible', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'different.domain.com' },
      }) as any;

      const result = resolveTenantName(req, 'business.example.com');

      expect(result).toBe('');
    });

    test('Throws error for multiple tenant_name query parameters', () => {
      const req = httpMocks.createRequest({
        query: { tenant_name: ['tenant1', 'tenant2'] },
      }) as any;

      expect(() => {
        return resolveTenantName(req, '');
      }).toThrow('More than one [tenant_name] query parameter was encountered');
    });

    test('Returns empty string when tenant_name is undefined', () => {
      const req = httpMocks.createRequest({
        query: {},
      }) as any;

      const result = resolveTenantName(req, '');

      expect(result).toBe('');
    });
  });

  describe('resolveTenantCustomDomainParam', () => {
    test('Returns tenant_custom_domain query parameter', () => {
      const req = httpMocks.createRequest({
        query: { tenant_custom_domain: 'custom.domain.com' },
      }) as any;

      const result = resolveTenantCustomDomainParam(req);

      expect(result).toBe('custom.domain.com');
    });

    test('Returns empty string when no tenant_custom_domain parameter', () => {
      const req = httpMocks.createRequest({
        query: {},
      }) as any;

      const result = resolveTenantCustomDomainParam(req);

      expect(result).toBe('');
    });

    test('Throws error for multiple tenant_custom_domain query parameters', () => {
      const req = httpMocks.createRequest({
        query: { tenant_custom_domain: ['domain1.com', 'domain2.com'] },
      }) as any;

      expect(() => {
        return resolveTenantCustomDomainParam(req);
      }).toThrow('More than one [tenant_custom_domain] query parameter was encountered');
    });
  });

  describe('resolveRedirectUrl', () => {
    test('Returns undefined when no return URL is provided anywhere', () => {
      const req = httpMocks.createRequest() as any;

      expect(resolveRedirectUrl(req)).toBeUndefined();
    });

    test('Returns the return_url query parameter when no config is provided', () => {
      const req = httpMocks.createRequest({
        query: { return_url: 'https://example.com/dashboard' },
      }) as any;

      expect(resolveRedirectUrl(req)).toBe('https://example.com/dashboard');
    });

    test('Returns LoginConfig.returnUrl when no query parameter is present', () => {
      const req = httpMocks.createRequest() as any;

      expect(resolveRedirectUrl(req, { returnUrl: 'https://example.com/config' })).toBe('https://example.com/config');
    });

    test('LoginConfig.returnUrl takes precedence over the return_url query parameter', () => {
      const req = httpMocks.createRequest({
        query: { return_url: 'https://example.com/query' },
      }) as any;

      expect(resolveRedirectUrl(req, { returnUrl: 'https://example.com/config' })).toBe('https://example.com/config');
    });

    test('Falls back to the query parameter when LoginConfig.returnUrl is an empty string', () => {
      const req = httpMocks.createRequest({
        query: { return_url: 'https://example.com/query' },
      }) as any;

      expect(resolveRedirectUrl(req, { returnUrl: '' })).toBe('https://example.com/query');
    });

    test('Returns undefined when the return_url query parameter is an empty string', () => {
      const req = httpMocks.createRequest({
        query: { return_url: '' },
      }) as any;

      expect(resolveRedirectUrl(req)).toBeUndefined();
    });

    test('Throws error for multiple return_url query parameters', () => {
      const req = httpMocks.createRequest({
        query: { return_url: ['url1', 'url2'] },
      }) as any;

      expect(() => {
        return resolveRedirectUrl(req);
      }).toThrow('More than one [return_url] query parameter was encountered');
    });

    test('Does not throw for multiple return_url query parameters when LoginConfig.returnUrl is set', () => {
      const req = httpMocks.createRequest({
        query: { return_url: ['url1', 'url2'] },
      }) as any;

      expect(resolveRedirectUrl(req, { returnUrl: 'https://example.com/config' })).toBe('https://example.com/config');
    });
  });

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

  describe('getAppLevelLoginUrl', () => {
    const wristbandApplicationVanityDomain = 'auth.example.com';
    const clientId = 'test-client-id';

    test('Returns Wristband-hosted app login URL when no options are provided', () => {
      const result = getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId);

      expect(result).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${clientId}`);
    });

    test('Returns Wristband-hosted app login URL when an empty options object is provided', () => {
      const result = getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, {});

      expect(result).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${clientId}`);
    });

    test('Returns custom application login page URL with client_id appended when provided', () => {
      const result = getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, {
        customApplicationLoginPageUrl: 'https://custom.example.com/login',
      });

      expect(result).toBe(`https://custom.example.com/login?client_id=${clientId}`);
    });

    test('Appends the return URL as the state query parameter', () => {
      const result = getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, {
        returnUrl: '/settings',
      });

      expect(result).toBe(
        `https://${wristbandApplicationVanityDomain}/login?client_id=${clientId}&state=${encodeURIComponent('/settings')}`
      );
    });

    test('URL-encodes the return URL so its own query params do not leak into the login URL', () => {
      const returnUrl = 'https://app.example.com/settings?tab=billing&x=1#top';
      const result = getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, { returnUrl });

      const { searchParams } = new URL(result);
      expect(searchParams.get('client_id')).toBe(clientId);
      expect(searchParams.get('state')).toBe(returnUrl);
      expect(searchParams.has('tab')).toBe(false);
      expect(searchParams.has('x')).toBe(false);
      expect(result).toContain(`&state=${encodeURIComponent(returnUrl)}`);
    });

    test('Appends the return URL to the custom application login page URL', () => {
      const result = getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, {
        customApplicationLoginPageUrl: 'https://custom.example.com/login',
        returnUrl: '/dashboard',
      });

      expect(result).toBe(
        `https://custom.example.com/login?client_id=${clientId}&state=${encodeURIComponent('/dashboard')}`
      );
    });

    test('Includes the return URL when it is exactly the max state length', () => {
      const returnUrl = `/${'a'.repeat(STATE_PARAM_MAX_CHAR_LENGTH - 1)}`;
      expect(returnUrl).toHaveLength(STATE_PARAM_MAX_CHAR_LENGTH);

      const result = getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, { returnUrl });

      expect(new URL(result).searchParams.get('state')).toBe(returnUrl);
    });

    test('Drops the return URL when it exceeds the max state length', () => {
      const returnUrl = `/${'a'.repeat(STATE_PARAM_MAX_CHAR_LENGTH)}`;
      expect(returnUrl).toHaveLength(STATE_PARAM_MAX_CHAR_LENGTH + 1);

      const result = getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, { returnUrl });

      expect(result).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${clientId}`);
    });

    test('Does not append state when the return URL is an empty string', () => {
      const result = getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, { returnUrl: '' });

      expect(result).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${clientId}`);
    });

    test('Throws error when wristbandApplicationVanityDomain is missing', () => {
      expect(() => {
        return getAppLevelLoginUrl('', clientId);
      }).toThrow('wristbandApplicationVanityDomain cannot be null or undefined');
    });

    test('Throws error when clientId is missing', () => {
      expect(() => {
        return getAppLevelLoginUrl(wristbandApplicationVanityDomain, '');
      }).toThrow('clientId cannot be null or undefined');
    });
  });

  describe('getAuthorizationUrlParams', () => {
    const baseParamsConfig = {
      clientId: 'test-client-id',
      codeVerifier: 'test-code-verifier',
      redirectUri: 'https://example.com/callback',
      scopes: ['openid', 'offline_access', 'email'],
      state: 'test-state',
    };

    test('Includes all required OAuth parameters', () => {
      const req = httpMocks.createRequest() as any;
      const result = getAuthorizationUrlParams(req, baseParamsConfig);

      expect(result.get('client_id')).toBe('test-client-id');
      expect(result.get('redirect_uri')).toBe('https://example.com/callback');
      expect(result.get('response_type')).toBe('code');
      expect(result.get('state')).toBe('test-state');
      expect(result.get('scope')).toBe('openid offline_access email');
      expect(result.get('code_challenge')).toBeTruthy();
      expect(result.get('code_challenge_method')).toBe('S256');
      expect(result.get('nonce')).toBeTruthy();
    });

    test('Does not include idp_hint or login_hint when absent from query', () => {
      const req = httpMocks.createRequest() as any;
      const result = getAuthorizationUrlParams(req, baseParamsConfig);

      expect(result.has('idp_hint')).toBe(false);
      expect(result.has('login_hint')).toBe(false);
    });

    test('Includes login hint when provided in query', () => {
      const req = httpMocks.createRequest({ query: { login_hint: 'user@example.com' } }) as any;
      const result = getAuthorizationUrlParams(req, baseParamsConfig);

      expect(result.get('login_hint')).toBe('user@example.com');
    });

    test('Throws error for multiple login_hint query parameters', () => {
      const req = httpMocks.createRequest({ query: { login_hint: ['hint1', 'hint2'] } }) as any;

      expect(() => {
        return getAuthorizationUrlParams(req, baseParamsConfig);
      }).toThrow('More than one [login_hint] query parameter was encountered');
    });

    test('Includes idp hint when provided in query', () => {
      const req = httpMocks.createRequest({ query: { idp_hint: 'google' } }) as any;
      const result = getAuthorizationUrlParams(req, baseParamsConfig);

      expect(result.get('idp_hint')).toBe('google');
    });

    test('Throws error for multiple idp_hint query parameters', () => {
      const req = httpMocks.createRequest({ query: { idp_hint: ['google', 'github'] } }) as any;

      expect(() => {
        return getAuthorizationUrlParams(req, baseParamsConfig);
      }).toThrow('More than one [idp_hint] query parameter was encountered');
    });

    test('Generates different code_challenge and nonce on multiple calls', () => {
      const req = httpMocks.createRequest() as any;
      const result1 = getAuthorizationUrlParams(req, { ...baseParamsConfig, codeVerifier: 'verifier-1' });
      const result2 = getAuthorizationUrlParams(req, { ...baseParamsConfig, codeVerifier: 'verifier-2' });

      expect(result1.get('code_challenge')).not.toBe(result2.get('code_challenge'));
      expect(result1.get('nonce')).not.toBe(result2.get('nonce'));
    });
  });

  describe('getAppLevelAuthorizationUrl', () => {
    const wristbandApplicationVanityDomain = 'auth.example.com';

    const buildParams = () => {
      return new URLSearchParams({
        client_id: 'test-client-id',
        redirect_uri: 'https://example.com/callback',
        response_type: 'code',
        state: 'test-state',
        scope: 'openid offline_access email',
        code_challenge: 'test-challenge',
        code_challenge_method: 'S256',
        nonce: 'test-nonce',
      });
    };

    test('Creates app-level authorize URL with the vanity domain', () => {
      const params = buildParams();
      const result = getAppLevelAuthorizationUrl(wristbandApplicationVanityDomain, params);

      expect(result).toBe(`https://${wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?${params.toString()}`);
    });

    test('Includes all provided authorization params in the query string', () => {
      const params = buildParams();
      const result = getAppLevelAuthorizationUrl(wristbandApplicationVanityDomain, params);

      expect(result).toContain('client_id=test-client-id');
      expect(result).toContain('redirect_uri=https%3A%2F%2Fexample.com%2Fcallback');
      expect(result).toContain('response_type=code');
      expect(result).toContain('state=test-state');
      expect(result).toContain('code_challenge=test-challenge');
      expect(result).toContain('code_challenge_method=S256');
      expect(result).toContain('nonce=test-nonce');
    });

    test('Throws error when wristbandApplicationVanityDomain is missing', () => {
      const params = buildParams();

      expect(() => {
        return getAppLevelAuthorizationUrl('', params);
      }).toThrow('wristbandApplicationVanityDomain cannot be null or undefined');
    });

    test('Throws error when authorizationParams is empty', () => {
      const emptyParams = new URLSearchParams();

      expect(() => {
        return getAppLevelAuthorizationUrl(wristbandApplicationVanityDomain, emptyParams);
      }).toThrow('authorizationParams cannot be null or empty');
    });
  });

  describe('getTenantLevelAuthorizationUrl', () => {
    const wristbandApplicationVanityDomain = 'auth.example.com';

    const buildParams = (overrides: Record<string, string> = {}) => {
      return new URLSearchParams({
        client_id: 'test-client-id',
        redirect_uri: 'https://example.com/callback',
        response_type: 'code',
        state: 'test-state',
        scope: 'openid offline_access email',
        code_challenge: 'test-challenge',
        code_challenge_method: 'S256',
        nonce: 'test-nonce',
        ...overrides,
      });
    };

    test('Throws error when wristbandApplicationVanityDomain is missing', () => {
      const params = buildParams();
      const config = { tenantName: 'tenant' };

      expect(() => {
        return getTenantLevelAuthorizationUrl('', params, config);
      }).toThrow('wristbandApplicationVanityDomain cannot be null or undefined');
    });

    test('Throws error when no tenant name or tenant custom domain is provided', () => {
      const params = buildParams();

      expect(() => {
        return getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, params, {});
      }).toThrow('No tenant name or tenant custom domain was provided');
    });

    test('Creates authorize URL with tenant custom domain', () => {
      const params = buildParams();
      const config = { tenantCustomDomain: 'tenant.custom.com' };
      const result = getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, params, config);

      expect(result).toContain('https://tenant.custom.com/api/v1/oauth2/authorize');
      expect(result).toContain('client_id=test-client-id');
      expect(result).toContain('state=test-state');
      expect(result).toContain('scope=openid+offline_access+email');
    });

    test('Creates authorize URL with tenant name (hyphen separator)', () => {
      const params = buildParams();
      const config = { tenantName: 'tenant', isApplicationCustomDomainActive: false };
      const result = getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, params, config);

      expect(result).toContain(`https://tenant-${wristbandApplicationVanityDomain}/api/v1/oauth2/authorize`);
    });

    test('Creates authorize URL with tenant name (dot separator)', () => {
      const params = buildParams();
      const config = { tenantName: 'tenant', isApplicationCustomDomainActive: true };
      const result = getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, params, config);

      expect(result).toContain(`https://tenant.${wristbandApplicationVanityDomain}/api/v1/oauth2/authorize`);
    });

    test('Creates authorize URL with default tenant custom domain', () => {
      const params = buildParams();
      const config = { defaultTenantCustomDomain: 'default.custom.com' };
      const result = getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, params, config);

      expect(result).toContain('https://default.custom.com/api/v1/oauth2/authorize');
    });

    test('Creates authorize URL with default tenant name', () => {
      const params = buildParams();
      const config = { defaultTenantName: 'default-tenant', isApplicationCustomDomainActive: false };
      const result = getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, params, config);

      expect(result).toContain(`https://default-tenant-${wristbandApplicationVanityDomain}/api/v1/oauth2/authorize`);
    });

    test('Includes all provided authorization params in the query string', () => {
      const params = buildParams();
      const config = { tenantCustomDomain: 'tenant.custom.com' };
      const result = getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, params, config);

      expect(result).toContain('redirect_uri=https%3A%2F%2Fexample.com%2Fcallback');
      expect(result).toContain('response_type=code');
      expect(result).toContain('code_challenge=test-challenge');
      expect(result).toContain('code_challenge_method=S256');
      expect(result).toContain('nonce=test-nonce');
    });

    test('Domain priority: tenant custom domain takes precedence', () => {
      const params = buildParams();
      const config = {
        tenantCustomDomain: 'priority.custom.com',
        tenantName: 'tenant',
        defaultTenantCustomDomain: 'default.custom.com',
        defaultTenantName: 'default-tenant',
      };
      const result = getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, params, config);

      expect(result).toContain('https://priority.custom.com/api/v1/oauth2/authorize');
    });

    test('Domain priority: tenant name takes precedence over defaults', () => {
      const params = buildParams();
      const config = {
        tenantName: 'tenant',
        defaultTenantCustomDomain: 'default.custom.com',
        defaultTenantName: 'default-tenant',
        isApplicationCustomDomainActive: false,
      };
      const result = getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, params, config);

      expect(result).toContain(`https://tenant-${wristbandApplicationVanityDomain}/api/v1/oauth2/authorize`);
    });

    test('Domain priority: default tenant custom domain takes precedence over default tenant name', () => {
      const params = buildParams();
      const config = { defaultTenantCustomDomain: 'default.custom.com', defaultTenantName: 'default-tenant' };
      const result = getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, params, config);

      expect(result).toContain('https://default.custom.com/api/v1/oauth2/authorize');
    });

    test('Throws error when authorizationParams is empty', () => {
      const emptyParams = new URLSearchParams();
      const config = { tenantCustomDomain: 'tenant.custom.com' };

      expect(() => {
        return getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, emptyParams, config);
      }).toThrow();
    });
  });

  describe('isExpired', () => {
    test('Returns true when current time is after expiration', () => {
      const pastTime = Date.now() - 1000; // 1 second ago

      const result = isExpired(pastTime);

      expect(result).toBe(true);
    });

    test('Returns false when current time is before expiration', () => {
      const futureTime = Date.now() + 1000; // 1 second from now

      const result = isExpired(futureTime);

      expect(result).toBe(false);
    });

    test('Returns true when current time equals expiration time', () => {
      const currentTime = Date.now();

      // Mock Date.now to return consistent value
      jest.spyOn(Date, 'now').mockReturnValue(currentTime);

      const result = isExpired(currentTime);

      expect(result).toBe(true);

      jest.restoreAllMocks();
    });

    test('Handles edge case with 0 expiration time', () => {
      const result = isExpired(0);

      expect(result).toBe(true);
    });
  });

  describe('encodeBase64', () => {
    test('Encodes a simple ASCII string', () => {
      expect(encodeBase64('hello')).toBe(btoa('hello'));
    });

    test('Encodes clientId:clientSecret format correctly', () => {
      const input = 'myClientId:myClientSecret';
      expect(encodeBase64(input)).toBe(btoa(input));
    });

    test('Encodes empty string', () => {
      expect(encodeBase64('')).toBe('');
    });

    test('Produces valid base64 output', () => {
      const result = encodeBase64('test-input');
      expect(result).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });
  });

  describe('validateReturnUrl', () => {
    // Minimal request mock exposing only what validateReturnUrl reads.
    const buildReq = (host: string, protocol: string = 'https') => {
      return {
        protocol,
        hostname: host.split(':')[0],
        get: (name: string) => {
          return name.toLowerCase() === 'host' ? host : undefined;
        },
      } as any;
    };

    const rootDomain = 'myapp.com';
    const tenantName = 'acme';

    describe('Input guards', () => {
      test('Throws when tenantName is empty', () => {
        const req = buildReq('acme.myapp.com');

        expect(() => {
          return validateReturnUrl(req, '/settings', '', true, rootDomain);
        }).toThrow('Tenant name is required to validate returnUrl');
      });

      test('Throws when tenantName is empty even if returnUrl is missing', () => {
        const req = buildReq('acme.myapp.com');

        expect(() => {
          return validateReturnUrl(req, undefined, '', true, rootDomain);
        }).toThrow('Tenant name is required to validate returnUrl');
      });

      test('Returns undefined when returnUrl is undefined', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, undefined, tenantName, true, rootDomain)).toBeUndefined();
      });

      test('Returns undefined when returnUrl is an empty string', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, '', tenantName, true, rootDomain)).toBeUndefined();
      });
    });

    describe('Allowed hosts', () => {
      test('Allows a relative path and returns it unchanged', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, '/settings?tab=1#top', tenantName, true, rootDomain)).toBe('/settings?tab=1#top');
      });

      test('Allows an absolute URL on the same host as the request', () => {
        const req = buildReq('acme.myapp.com');
        const returnUrl = 'https://acme.myapp.com/dashboard';

        expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
      });

      test('Ignores port when comparing hostnames', () => {
        const req = buildReq('acme.myapp.com');
        const returnUrl = 'https://acme.myapp.com:9999/dashboard';

        expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
      });

      test('Allows same-host URLs when parseTenantFromRootDomain is not set', () => {
        const req = buildReq('app.example.com');
        const returnUrl = 'https://app.example.com/home';

        expect(validateReturnUrl(req, returnUrl, tenantName, false)).toBe(returnUrl);
      });
    });

    describe('Rejected hosts', () => {
      test('Rejects a different domain', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, 'https://evil.com/phish', tenantName, true, rootDomain)).toBeUndefined();
      });

      test('Rejects a different tenant subdomain', () => {
        const req = buildReq('acme.myapp.com');

        expect(
          validateReturnUrl(req, 'https://other.myapp.com/dashboard', tenantName, true, rootDomain)
        ).toBeUndefined();
      });

      test('Rejects a protocol-relative URL to another host', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, '//evil.com/phish', tenantName, true, rootDomain)).toBeUndefined();
      });

      test('Rejects a backslash-prefixed URL to another host', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, '/\\evil.com/phish', tenantName, true, rootDomain)).toBeUndefined();
      });

      test('Rejects a lookalike domain that starts with the root domain', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, 'https://myapp.com.evil.com/', tenantName, true, rootDomain)).toBeUndefined();
      });

      test('Rejects a URL using userinfo to disguise the real host', () => {
        const req = buildReq('acme.myapp.com');

        expect(
          validateReturnUrl(req, 'https://acme.myapp.com@evil.com/', tenantName, true, rootDomain)
        ).toBeUndefined();
      });

      test('Rejects a javascript: URL', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, 'javascript:alert(1)', tenantName, true, rootDomain)).toBeUndefined();
      });

      test('Rejects the root domain when parseTenantFromRootDomain is not set', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, 'https://myapp.com/dashboard', tenantName, true)).toBeUndefined();
      });

      test('Returns undefined for a malformed URL', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, 'https://', tenantName, true, rootDomain)).toBeUndefined();
      });
    });

    describe('Root domain tenant rewrite', () => {
      test('Prepends the tenant subdomain to a root domain URL', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, 'https://myapp.com/dashboard?x=1#top', tenantName, true, rootDomain)).toBe(
          'https://acme.myapp.com/dashboard?x=1#top'
        );
      });

      test('Preserves the port when rewriting', () => {
        const req = buildReq('acme.localhost:6001', 'http');

        expect(validateReturnUrl(req, 'http://localhost:6001/home', tenantName, true, 'localhost')).toBe(
          'http://acme.localhost:6001/home'
        );
      });

      test('Does not rewrite when applicationAuthorizationRequestsEnabled is false', () => {
        const req = buildReq('acme.myapp.com');
        const returnUrl = 'https://myapp.com/dashboard';

        expect(validateReturnUrl(req, returnUrl, tenantName, false, rootDomain)).toBe(returnUrl);
      });

      test('Does not rewrite a relative path even when rewrite is enabled', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, '/dashboard', tenantName, true, rootDomain)).toBe('/dashboard');
      });
    });

    describe('Protocol matching', () => {
      test('Rejects an http returnUrl when the request is https', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, 'http://acme.myapp.com/dashboard', tenantName, true, rootDomain)).toBeUndefined();
      });

      test('Rejects an https returnUrl when the request is http', () => {
        const req = buildReq('acme.localhost:6001', 'http');

        expect(
          validateReturnUrl(req, 'https://acme.localhost:6001/home', tenantName, true, 'localhost')
        ).toBeUndefined();
      });

      test('Rejects a root domain returnUrl with a mismatched protocol instead of rewriting it', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, 'http://myapp.com/dashboard', tenantName, true, rootDomain)).toBeUndefined();
      });

      test('Rejects a non-http protocol on an allowed host', () => {
        const req = buildReq('acme.myapp.com');

        expect(validateReturnUrl(req, 'ftp://acme.myapp.com/file', tenantName, true, rootDomain)).toBeUndefined();
      });

      test('Allows a relative path on an http request', () => {
        const req = buildReq('acme.localhost:6001', 'http');

        expect(validateReturnUrl(req, '/home', tenantName, true, 'localhost')).toBe('/home');
      });
    });
  });

  describe('deriveFallbackLoginUrl', () => {
    test('Removes the leading placeholder from the login URL', () => {
      expect(deriveFallbackLoginUrl('https://{tenant_name}.myapp.com/api/auth/login')).toBe(
        'https://myapp.com/api/auth/login'
      );
    });

    test('Keeps the port, path, and query string', () => {
      expect(deriveFallbackLoginUrl('http://{tenant_name}.localhost:6001/api/auth/login?x=1')).toBe(
        'http://localhost:6001/api/auth/login?x=1'
      );
    });

    test('Handles a nested root domain', () => {
      expect(deriveFallbackLoginUrl('https://{tenant_name}.business.myapp.com/login')).toBe(
        'https://business.myapp.com/login'
      );
    });

    test('Returns an empty string when the login URL has no placeholder', () => {
      expect(deriveFallbackLoginUrl('https://myapp.com/api/auth/login')).toBe('');
    });

    test('Returns an empty string when the login URL is empty', () => {
      expect(deriveFallbackLoginUrl('')).toBe('');
    });
  });

  describe('deriveTenantRootDomain', () => {
    test('Returns the hostname without the leading placeholder', () => {
      expect(deriveTenantRootDomain('https://{tenant_name}.myapp.com/api/auth/login')).toBe('myapp.com');
    });

    test('Excludes the port', () => {
      expect(deriveTenantRootDomain('http://{tenant_name}.localhost:6001/api/auth/login')).toBe('localhost');
    });

    test('Handles a nested root domain', () => {
      expect(deriveTenantRootDomain('https://{tenant_name}.business.myapp.com/login')).toBe('business.myapp.com');
    });

    test('Returns an empty string when the login URL has no placeholder', () => {
      expect(deriveTenantRootDomain('https://myapp.com/api/auth/login')).toBe('');
    });

    test('Returns an empty string when the login URL is empty', () => {
      expect(deriveTenantRootDomain('')).toBe('');
    });
  });

  describe('isTenantPlaceholderPositionValid', () => {
    test('Returns true when the URL has no placeholder', () => {
      expect(isTenantPlaceholderPositionValid('https://myapp.com/api/auth/login')).toBe(true);
    });

    test('Returns true when the placeholder is the leftmost part of the hostname (https)', () => {
      expect(isTenantPlaceholderPositionValid('https://{tenant_name}.myapp.com/api/auth/login')).toBe(true);
    });

    test('Returns true when the placeholder is the leftmost part of the hostname (http)', () => {
      expect(isTenantPlaceholderPositionValid('http://{tenant_name}.localhost:6001/api/auth/login')).toBe(true);
    });

    test('Returns false when the placeholder is not the leftmost part of the hostname', () => {
      expect(isTenantPlaceholderPositionValid('https://app.{tenant_name}.myapp.com/api/auth/login')).toBe(false);
    });

    test('Returns false when the placeholder is in the path', () => {
      expect(isTenantPlaceholderPositionValid('https://myapp.com/{tenant_name}/api/auth/login')).toBe(false);
    });

    test('Returns false when the placeholder is the entire hostname', () => {
      expect(isTenantPlaceholderPositionValid('https://{tenant_name}/api/auth/login')).toBe(false);
    });

    test('Returns false when the placeholder appears more than once', () => {
      expect(isTenantPlaceholderPositionValid('https://{tenant_name}.myapp.com/{tenant_name}/login')).toBe(false);
    });
  });
});
