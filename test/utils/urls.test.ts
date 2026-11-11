/* eslint-disable import/no-extraneous-dependencies */

import { createHash } from 'crypto';
import httpMocks from 'node-mocks-http';
import {
  toSafeTenantName,
  toSafeDomainName,
  stripPort,
  getRequestHost,
  parseTenantSubdomain,
  resolveTenantCustomDomainParam,
  resolveTenantName,
  resolveReturnUrl,
  getAuthorizationUrlParams,
  getTenantLevelAuthorizationUrl,
  getAppLevelLoginUrl,
  getAppLevelAuthorizationUrl,
  validateReturnUrl,
  deriveFallbackLoginUrl,
  deriveTenantRootDomain,
  isTenantPlaceholderPositionValid,
} from '../../src/utils/urls';
import { STATE_PARAM_MAX_CHAR_LENGTH } from '../../src/utils/constants';

describe('Auth Utils', () => {
  describe('toSafeTenantName', () => {
    test.each([
      ['a lowercase name', 'acme'],
      ['a mixed-case name with a hyphen', 'Acme-Corp'],
      ['a name that starts with a digit', '1tenant'],
      ['a single character', 'a'],
      ['a 63-character name', 'a'.repeat(63)],
    ])('Returns %s unchanged', (_label, value) => {
      expect(toSafeTenantName(value)).toBe(value);
    });

    test.each([
      ['an open redirect value', 'evil.com#'],
      ['a name with a dot', 'acme.com'],
      ['a name that starts with a hyphen', '-acme'],
      ['a name that ends with a hyphen', 'acme-'],
      ['a 64-character name', 'a'.repeat(64)],
      ['a name with a trailing newline', 'acme\n'],
      ['a name with a space', 'acme '],
      ['a name with an underscore', 'ac_me'],
      ['a name with a non-ASCII letter', 'acmé'],
      ['a name with the Kelvin sign', '\u212Acme'],
    ])('Returns an empty string for %s', (_label, value) => {
      expect(toSafeTenantName(value)).toBe('');
    });

    test('Returns an empty string for an empty or missing value', () => {
      expect(toSafeTenantName('')).toBe('');
      expect(toSafeTenantName(undefined)).toBe('');
    });
  });

  describe('toSafeDomainName', () => {
    test.each([
      ['a two-label domain', 'acme.com'],
      ['a three-label domain', 'auth.acme.com'],
      ['a mixed-case domain with hyphens', 'Auth-1.Acme-Corp.com'],
    ])('Returns %s unchanged', (_label, value) => {
      expect(toSafeDomainName(value)).toBe(value);
    });

    test.each([
      ['an open redirect value', 'evil.com#'],
      ['an open redirect value disguised as a subdomain', 'evil.com#.acme.com'],
      ['a single label', 'localhost'],
      ['a domain with a port', 'acme.com:443'],
      ['a domain with a path', 'acme.com/path'],
      ['a domain with credentials', 'user@acme.com'],
      ['a domain with a trailing dot', 'acme.com.'],
      ['a domain with an empty label', 'a..com'],
      ['a domain with a label that starts with a hyphen', '-a.com'],
      ['a domain with a trailing newline', 'acme.com\n'],
    ])('Returns an empty string for %s', (_label, value) => {
      expect(toSafeDomainName(value)).toBe('');
    });

    test('Returns an empty string for an empty or missing value', () => {
      expect(toSafeDomainName('')).toBe('');
      expect(toSafeDomainName(undefined)).toBe('');
    });
  });

  describe('stripPort', () => {
    test('Removes the port from a host', () => {
      expect(stripPort('acme.myapp.com:3000')).toBe('acme.myapp.com');
    });

    test('Returns a host without a port unchanged', () => {
      expect(stripPort('acme.myapp.com')).toBe('acme.myapp.com');
    });

    test('Removes the port from a bracketed IPv6 host', () => {
      expect(stripPort('[::1]:3000')).toBe('[::1]');
    });

    test('Returns a bracketed IPv6 host without a port unchanged', () => {
      expect(stripPort('[::1]')).toBe('[::1]');
    });
  });

  describe('getRequestHost', () => {
    // Setting "hostname" explicitly simulates Express resolving req.hostname from
    // X-Forwarded-Host, which only happens when the app's "trust proxy" setting trusts the sender.

    test('Returns the Host header with its port when no proxy headers are present', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'acme.myapp.com:3000' },
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com:3000');
    });

    test('Returns X-Forwarded-Host when Express resolved the hostname from it', () => {
      const req = httpMocks.createRequest({
        hostname: 'acme.myapp.com',
        headers: { host: 'localhost:3000', 'x-forwarded-host': 'acme.myapp.com' },
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com');
    });

    test('Keeps the port from X-Forwarded-Host', () => {
      const req = httpMocks.createRequest({
        hostname: 'acme.myapp.com',
        headers: { host: 'localhost:3000', 'x-forwarded-host': 'acme.myapp.com:8443' },
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com:8443');
    });

    test('Uses the first value when X-Forwarded-Host contains a comma-separated list', () => {
      const req = httpMocks.createRequest({
        hostname: 'acme.myapp.com',
        headers: { host: 'localhost:3000', 'x-forwarded-host': 'acme.myapp.com, other.com' },
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com');
    });

    test('Ignores X-Forwarded-Host when Express resolved the hostname from the Host header', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'acme.myapp.com:3000', 'x-forwarded-host': 'evil.com' },
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com:3000');
    });

    test('Prefers the Host header when both headers share the same hostname', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'acme.myapp.com:3000', 'x-forwarded-host': 'acme.myapp.com:9999' },
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com:3000');
    });

    test('Falls back to the hostname when neither header matches it', () => {
      const req = httpMocks.createRequest({
        hostname: 'acme.myapp.com',
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com');
    });

    test('Returns an empty string when the hostname is missing', () => {
      const req = { headers: {} } as any;

      expect(getRequestHost(req)).toBe('');
    });
  });

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

    test('Extracts tenant subdomain from X-Forwarded-Host when Express resolved the hostname from it', () => {
      const req = httpMocks.createRequest({
        hostname: 'tenant.business.example.com',
        headers: { host: 'localhost:3000', 'x-forwarded-host': 'tenant.business.example.com:8443' },
      }) as any;

      const result = parseTenantSubdomain(req, 'business.example.com');

      expect(result).toBe('tenant');
    });

    test('Ignores X-Forwarded-Host when Express resolved the hostname from the Host header', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'localhost:3000', 'x-forwarded-host': 'tenant.business.example.com' },
      }) as any;

      const result = parseTenantSubdomain(req, 'business.example.com');

      expect(result).toBe('');
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

    test('Returns empty string when the tenant_name query param is not a valid tenant name', () => {
      const req = httpMocks.createRequest({
        query: { tenant_name: 'evil.com#' },
      }) as any;

      const result = resolveTenantName(req, '');

      expect(result).toBe('');
    });

    test('Returns empty string when the tenant subdomain is not a valid tenant name', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'ac_me.business.example.com' },
      }) as any;

      const result = resolveTenantName(req, 'business.example.com');

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

  describe('resolveReturnUrl', () => {
    test('Returns undefined when no return URL is provided anywhere', () => {
      const req = httpMocks.createRequest() as any;

      expect(resolveReturnUrl(req)).toBeUndefined();
    });

    test('Returns the return_url query parameter when no config is provided', () => {
      const req = httpMocks.createRequest({
        query: { return_url: 'https://example.com/dashboard' },
      }) as any;

      expect(resolveReturnUrl(req)).toBe('https://example.com/dashboard');
    });

    test('Returns LoginConfig.returnUrl when no query parameter is present', () => {
      const req = httpMocks.createRequest() as any;

      expect(resolveReturnUrl(req, { returnUrl: 'https://example.com/config' })).toBe('https://example.com/config');
    });

    test('LoginConfig.returnUrl takes precedence over the return_url query parameter', () => {
      const req = httpMocks.createRequest({
        query: { return_url: 'https://example.com/query' },
      }) as any;

      expect(resolveReturnUrl(req, { returnUrl: 'https://example.com/config' })).toBe('https://example.com/config');
    });

    test('Falls back to the query parameter when LoginConfig.returnUrl is an empty string', () => {
      const req = httpMocks.createRequest({
        query: { return_url: 'https://example.com/query' },
      }) as any;

      expect(resolveReturnUrl(req, { returnUrl: '' })).toBe('https://example.com/query');
    });

    test('Returns undefined when the return_url query parameter is an empty string', () => {
      const req = httpMocks.createRequest({
        query: { return_url: '' },
      }) as any;

      expect(resolveReturnUrl(req)).toBeUndefined();
    });

    test('Throws error for multiple return_url query parameters', () => {
      const req = httpMocks.createRequest({
        query: { return_url: ['url1', 'url2'] },
      }) as any;

      expect(() => {
        return resolveReturnUrl(req);
      }).toThrow('More than one [return_url] query parameter was encountered');
    });

    test('Does not throw for multiple return_url query parameters when LoginConfig.returnUrl is set', () => {
      const req = httpMocks.createRequest({
        query: { return_url: ['url1', 'url2'] },
      }) as any;

      expect(resolveReturnUrl(req, { returnUrl: 'https://example.com/config' })).toBe('https://example.com/config');
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

    test('Includes all required OAuth parameters', async () => {
      const req = httpMocks.createRequest() as any;
      const result = await getAuthorizationUrlParams(req, baseParamsConfig);

      expect(result.get('client_id')).toBe('test-client-id');
      expect(result.get('redirect_uri')).toBe('https://example.com/callback');
      expect(result.get('response_type')).toBe('code');
      expect(result.get('state')).toBe('test-state');
      expect(result.get('scope')).toBe('openid offline_access email');
      expect(result.get('code_challenge')).toBeTruthy();
      expect(result.get('code_challenge_method')).toBe('S256');
      expect(result.get('nonce')).toBeTruthy();
    });

    test('Does not include idp_hint or login_hint when absent from query', async () => {
      const req = httpMocks.createRequest() as any;
      const result = await getAuthorizationUrlParams(req, baseParamsConfig);

      expect(result.has('idp_hint')).toBe(false);
      expect(result.has('login_hint')).toBe(false);
    });

    test('Includes login hint when provided in query', async () => {
      const req = httpMocks.createRequest({ query: { login_hint: 'user@example.com' } }) as any;
      const result = await getAuthorizationUrlParams(req, baseParamsConfig);

      expect(result.get('login_hint')).toBe('user@example.com');
    });

    test('Throws error for multiple login_hint query parameters', async () => {
      const req = httpMocks.createRequest({ query: { login_hint: ['hint1', 'hint2'] } }) as any;

      await expect(getAuthorizationUrlParams(req, baseParamsConfig)).rejects.toThrow(
        'More than one [login_hint] query parameter was encountered'
      );
    });

    test('Includes idp hint when provided in query', async () => {
      const req = httpMocks.createRequest({ query: { idp_hint: 'google' } }) as any;
      const result = await getAuthorizationUrlParams(req, baseParamsConfig);

      expect(result.get('idp_hint')).toBe('google');
    });

    test('Throws error for multiple idp_hint query parameters', async () => {
      const req = httpMocks.createRequest({ query: { idp_hint: ['google', 'github'] } }) as any;

      await expect(getAuthorizationUrlParams(req, baseParamsConfig)).rejects.toThrow(
        'More than one [idp_hint] query parameter was encountered'
      );
    });

    test('Uses the base64url-encoded SHA-256 hash of the code verifier as the code_challenge', async () => {
      const req = httpMocks.createRequest() as any;
      const result = await getAuthorizationUrlParams(req, baseParamsConfig);

      // The SHA-256 hash of "test-code-verifier" contains "/" and "=" in standard base64,
      // so this also confirms the URL-safe alphabet without padding is used.
      const expectedChallenge = createHash('sha256').update(baseParamsConfig.codeVerifier).digest('base64url');
      expect(result.get('code_challenge')).toBe(expectedChallenge);
      expect(result.get('code_challenge')).not.toMatch(/[+/=]/);
    });

    test('Generates different code_challenge and nonce on multiple calls', async () => {
      const req = httpMocks.createRequest() as any;
      const result1 = await getAuthorizationUrlParams(req, { ...baseParamsConfig, codeVerifier: 'verifier-1' });
      const result2 = await getAuthorizationUrlParams(req, { ...baseParamsConfig, codeVerifier: 'verifier-2' });

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

      test('Returns undefined when the request host cannot be determined', () => {
        const req = { headers: {} } as any;

        expect(validateReturnUrl(req, '/settings', tenantName, true, rootDomain)).toBeUndefined();
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

    describe('Proxy headers', () => {
      // Setting "hostname" explicitly simulates Express resolving req.hostname from
      // X-Forwarded-Host, which only happens when the app's "trust proxy" setting trusts the sender.

      test('Allows a relative path when Express resolved the hostname from X-Forwarded-Host', () => {
        const req = httpMocks.createRequest({
          protocol: 'https',
          hostname: 'acme.myapp.com',
          headers: { host: 'localhost:3000', 'x-forwarded-host': 'acme.myapp.com' },
        }) as any;

        expect(validateReturnUrl(req, '/settings', tenantName, true, rootDomain)).toBe('/settings');
      });

      test('Allows an absolute URL on the X-Forwarded-Host when Express resolved the hostname from it', () => {
        const req = httpMocks.createRequest({
          protocol: 'https',
          hostname: 'acme.myapp.com',
          headers: { host: 'localhost:3000', 'x-forwarded-host': 'acme.myapp.com' },
        }) as any;
        const returnUrl = 'https://acme.myapp.com/dashboard';

        expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
      });

      test('Keeps the X-Forwarded-Host port when rewriting a relative path on the root domain', () => {
        const req = httpMocks.createRequest({
          protocol: 'https',
          hostname: 'myapp.com',
          headers: { host: 'localhost:3000', 'x-forwarded-host': 'myapp.com:8443' },
        }) as any;

        expect(validateReturnUrl(req, '/home', tenantName, true, rootDomain)).toBe('https://acme.myapp.com:8443/home');
      });

      test('Rejects a URL on the X-Forwarded-Host when Express resolved the hostname from the Host header', () => {
        const req = httpMocks.createRequest({
          protocol: 'https',
          headers: { host: 'localhost:3000', 'x-forwarded-host': 'acme.myapp.com' },
        }) as any;

        expect(
          validateReturnUrl(req, 'https://acme.myapp.com/dashboard', tenantName, true, rootDomain)
        ).toBeUndefined();
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
