/* eslint-disable import/no-extraneous-dependencies */

import httpMocks from 'node-mocks-http';
import {
  parseTenantSubdomain,
  generateRandomString,
  base64URLEncode,
  encryptLoginState,
  decryptLoginState,
  getAndClearLoginStateCookie,
  resolveTenantCustomDomainParam,
  resolveTenantName,
  createLoginState,
  clearOldestLoginStateCookie,
  createLoginStateCookie,
  getOAuthAuthorizeUrl,
  isExpired,
} from '../../src/utils';
import { LoginState, LoginStateMapConfig } from '../../src/types';

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

  describe('getAndClearLoginStateCookie', () => {
    test('Finds and clears matching login state cookie', () => {
      const state = 'test-state-123';
      const req = httpMocks.createRequest({
        query: { state },
        headers: {
          cookie: `login#${state}#1234567890=encrypted-value; other=cookie`,
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      const result = getAndClearLoginStateCookie(req, res, false);

      expect(result).toBe('encrypted-value');
      // Check that clear cookie was called
      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      expect(setCookieHeaders).toContain(
        `login#${state}#1234567890=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure`
      );
    });

    test('Returns empty string when no matching cookie found', () => {
      const req = httpMocks.createRequest({
        query: { state: 'non-existent-state' },
        headers: {
          cookie: 'login#different-state#1234567890=encrypted-value',
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      const result = getAndClearLoginStateCookie(req, res, false);

      expect(result).toBe('');
    });

    test('Returns empty string when no state in query', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: 'login#some-state#1234567890=encrypted-value',
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      const result = getAndClearLoginStateCookie(req, res, false);

      expect(result).toBe('');
    });

    test('Uses dangerouslyDisableSecureCookies flag when clearing', () => {
      const state = 'test-state';
      const req = httpMocks.createRequest({
        query: { state },
        headers: {
          cookie: `login#${state}#1234567890=encrypted-value`,
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      getAndClearLoginStateCookie(req, res, true);

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      expect(setCookieHeaders).toContain(`login#${state}#1234567890=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax`);
    });

    test('Handles array state query parameter', () => {
      const req = httpMocks.createRequest({
        query: { state: ['state1', 'state2'] },
        headers: {
          cookie: 'login#state1,state2#1234567890=encrypted-value',
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      const result = getAndClearLoginStateCookie(req, res, false);

      expect(result).toBe('encrypted-value');
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

  describe('createLoginState', () => {
    const redirectUri = 'https://example.com/callback';

    test('Creates basic login state', () => {
      const req = httpMocks.createRequest() as any;

      const result = createLoginState(req, redirectUri);

      expect(result.state).toBeDefined();
      expect(result.codeVerifier).toBeDefined();
      expect(result.redirectUri).toBe(redirectUri);
      expect(result.returnUrl).toBeUndefined();
      expect(result.customState).toBeUndefined();
    });

    test('Includes return URL from query parameter', () => {
      const req = httpMocks.createRequest({
        query: { return_url: 'https://example.com/dashboard' },
      }) as any;

      const result = createLoginState(req, redirectUri);

      expect(result.returnUrl).toBe('https://example.com/dashboard');
    });

    test('Includes return URL from config (takes precedence over query)', () => {
      const req = httpMocks.createRequest({
        query: { return_url: 'https://example.com/query' },
      }) as any;

      const config: LoginStateMapConfig = {
        returnUrl: 'https://example.com/config',
      };

      const result = createLoginState(req, redirectUri, config);

      expect(result.returnUrl).toBe('https://example.com/config');
    });

    test('Includes custom state from config', () => {
      const req = httpMocks.createRequest() as any;

      const customState = { userId: '123', feature: 'test' };
      const config: LoginStateMapConfig = { customState };

      const result = createLoginState(req, redirectUri, config);

      expect(result.customState).toEqual(customState);
    });

    test('Throws error for multiple return_url query parameters', () => {
      const req = httpMocks.createRequest({
        query: { return_url: ['url1', 'url2'] },
      }) as any;

      expect(() => {
        return createLoginState(req, redirectUri);
      }).toThrow('More than one [return_url] query parameter was encountered');
    });

    test('Includes empty custom state object', () => {
      const req = httpMocks.createRequest() as any;

      const config: LoginStateMapConfig = { customState: {} };

      const result = createLoginState(req, redirectUri, config);

      // Based on the actual implementation, empty object is still included
      expect(result.customState).toEqual({});
    });

    test('Includes both return URL and custom state', () => {
      const req = httpMocks.createRequest() as any;

      const customState = { userId: '123' };
      const config: LoginStateMapConfig = {
        returnUrl: 'https://example.com/dashboard',
        customState,
      };

      const result = createLoginState(req, redirectUri, config);

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
      expect(setCookieHeaders).toContain('login#state1#1000000000=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure');
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
      expect(setCookieHeaders).toContain('login#state1#1000000000=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax');
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
  });

  describe('getOAuthAuthorizeUrl', () => {
    const baseConfig = {
      clientId: 'test-client-id',
      codeVerifier: 'test-code-verifier',
      redirectUri: 'https://example.com/callback',
      scopes: ['openid', 'offline_access', 'email'],
      state: 'test-state',
      wristbandApplicationVanityDomain: 'auth.example.com',
    };

    test('Creates authorize URL with tenant custom domain', () => {
      const req = httpMocks.createRequest() as any;

      const config = {
        ...baseConfig,
        tenantCustomDomain: 'tenant.custom.com',
      };

      const result = getOAuthAuthorizeUrl(req, config);

      expect(result).toContain('https://tenant.custom.com/api/v1/oauth2/authorize');
      expect(result).toContain('client_id=test-client-id');
      expect(result).toContain('state=test-state');
      expect(result).toContain('scope=openid+offline_access+email');
    });

    test('Creates authorize URL with tenant name (hyphen separator)', () => {
      const req = httpMocks.createRequest() as any;

      const config = {
        ...baseConfig,
        tenantName: 'tenant',
        isApplicationCustomDomainActive: false,
      };

      const result = getOAuthAuthorizeUrl(req, config);

      expect(result).toContain(`https://tenant-${baseConfig.wristbandApplicationVanityDomain}/api/v1/oauth2/authorize`);
    });

    test('Creates authorize URL with tenant name (dot separator)', () => {
      const req = httpMocks.createRequest() as any;

      const config = {
        ...baseConfig,
        tenantName: 'tenant',
        isApplicationCustomDomainActive: true,
      };

      const result = getOAuthAuthorizeUrl(req, config);

      expect(result).toContain(`https://tenant.${baseConfig.wristbandApplicationVanityDomain}/api/v1/oauth2/authorize`);
    });

    test('Creates authorize URL with default tenant custom domain', () => {
      const req = httpMocks.createRequest() as any;

      const config = {
        ...baseConfig,
        defaultTenantCustomDomain: 'default.custom.com',
      };

      const result = getOAuthAuthorizeUrl(req, config);

      expect(result).toContain('https://default.custom.com/api/v1/oauth2/authorize');
    });

    test('Creates authorize URL with default tenant name', () => {
      const req = httpMocks.createRequest() as any;

      const config = {
        ...baseConfig,
        defaultTenantName: 'default-tenant',
        isApplicationCustomDomainActive: false,
      };

      const result = getOAuthAuthorizeUrl(req, config);

      expect(result).toContain(
        `https://default-tenant-${baseConfig.wristbandApplicationVanityDomain}/api/v1/oauth2/authorize`
      );
    });

    test('Includes login hint when provided in query', () => {
      const req = httpMocks.createRequest({
        query: { login_hint: 'user@example.com' },
      }) as any;

      const config = {
        ...baseConfig,
        tenantCustomDomain: 'tenant.custom.com',
      };

      const result = getOAuthAuthorizeUrl(req, config);

      expect(result).toContain('login_hint=user%40example.com');
    });

    test('Throws error for multiple login_hint query parameters', () => {
      const req = httpMocks.createRequest({
        query: { login_hint: ['hint1', 'hint2'] },
      }) as any;

      const config = {
        ...baseConfig,
        tenantCustomDomain: 'tenant.custom.com',
      };

      expect(() => {
        return getOAuthAuthorizeUrl(req, config);
      }).toThrow('More than one [login_hint] query parameter was encountered');
    });

    test('Includes all required OAuth parameters', () => {
      const req = httpMocks.createRequest() as any;

      const config = {
        ...baseConfig,
        tenantCustomDomain: 'tenant.custom.com',
      };

      const result = getOAuthAuthorizeUrl(req, config);

      expect(result).toContain('client_id=test-client-id');
      expect(result).toContain('redirect_uri=https%3A%2F%2Fexample.com%2Fcallback');
      expect(result).toContain('response_type=code');
      expect(result).toContain('state=test-state');
      expect(result).toContain('scope=openid+offline_access+email');
      expect(result).toContain('code_challenge=');
      expect(result).toContain('code_challenge_method=S256');
      expect(result).toContain('nonce=');
    });

    test('Domain priority: tenant custom domain takes precedence', () => {
      const req = httpMocks.createRequest() as any;
      const config = {
        ...baseConfig,
        tenantCustomDomain: 'priority.custom.com',
        tenantName: 'tenant',
        defaultTenantCustomDomain: 'default.custom.com',
        defaultTenantName: 'default-tenant',
      };
      const result = getOAuthAuthorizeUrl(req, config);
      expect(result).toContain('https://priority.custom.com/api/v1/oauth2/authorize');
    });

    test('Domain priority: tenant name takes precedence over defaults', () => {
      const req = httpMocks.createRequest() as any;

      const config = {
        ...baseConfig,
        tenantName: 'tenant',
        defaultTenantCustomDomain: 'default.custom.com',
        defaultTenantName: 'default-tenant',
        isApplicationCustomDomainActive: false,
      };

      const result = getOAuthAuthorizeUrl(req, config);

      expect(result).toContain(`https://tenant-${baseConfig.wristbandApplicationVanityDomain}/api/v1/oauth2/authorize`);
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
});
