/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-underscore-dangle */

import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { decryptLoginState, encryptLoginState } from '../../src/utils';
import { LoginState } from '../../src/types';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

function extractCookiesFromHeaders(headers: Record<string, any>): Array<{
  name: string;
  value: string;
  attributes: {
    httpOnly: boolean;
    maxAge: number | undefined;
    path: string | undefined;
    sameSite: string | undefined;
    secure: boolean;
  };
}> {
  const setCookieHeader = headers['set-cookie'];
  if (!setCookieHeader) {
    return [];
  }

  // Convert to array if it's a single string
  const cookieStrings = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];

  return cookieStrings.map((cookieString) => {
    // Extract name and value
    const [nameValue, ...attributeParts] = cookieString.split('; ');
    const nameValueParts = nameValue.split('=');
    const name = nameValueParts[0];
    const value = nameValueParts.slice(1).join('=');

    // Parse attributes
    const attributes = {
      httpOnly: false,
      secure: false,
      path: undefined as string | undefined,
      maxAge: undefined as number | undefined,
      sameSite: undefined as string | undefined,
    };

    attributeParts.forEach((attr: string) => {
      if (attr === 'HttpOnly') {
        attributes.httpOnly = true;
      } else if (attr === 'Secure') {
        attributes.secure = true;
      } else if (attr.startsWith('Path=')) {
        attributes.path = attr.substring(5);
      } else if (attr.startsWith('Max-Age=')) {
        attributes.maxAge = parseInt(attr.substring(8), 10);
      } else if (attr.startsWith('SameSite=')) {
        attributes.sameSite = attr.substring(9).toLowerCase();
      }
    });

    return { name, value, attributes };
  });
}

describe('Multi Tenant Login', () => {
  let wristbandAuth: WristbandAuth;
  let parseTenantFromRootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    parseTenantFromRootDomain = 'localhost:6001';
    loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
    redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
    wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
  });

  describe('Successful Redirect to Authorize Endpoint', () => {
    test('Default Configuration', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${parseTenantFromRootDomain}` },
        query: { tenant_domain: 'devs4you' },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(3);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_uri')).toEqual(redirectUri);
      expect(searchParams.get('response_type')).toEqual('code');
      expect(searchParams.get('state')).toBeTruthy();
      expect(searchParams.get('scope')).toEqual('openid offline_access email');
      expect(searchParams.get('code_challenge')).toBeTruthy();
      expect(searchParams.get('code_challenge_method')).toEqual('S256');
      expect(searchParams.get('nonce')).toBeTruthy();
      expect(searchParams.get('login_hint')).toBeFalsy();

      // Extract and validate cookies
      const cookies = extractCookiesFromHeaders(headers);
      expect(cookies.length).toBe(1);
      const loginCookie = cookies[0];

      // Validate login state cookie key
      const keyParts: string[] = loginCookie.name.split(LOGIN_STATE_COOKIE_SEPARATOR);
      expect(keyParts).toHaveLength(3);
      expect(keyParts[0]).toEqual('login');
      expect(keyParts[1]).toBeTruthy();
      expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

      // Validate login state cookie attributes
      expect(loginCookie.attributes.httpOnly).toBe(true);
      expect(loginCookie.attributes.maxAge).toBe(3600);
      expect(loginCookie.attributes.path).toBe('/');
      expect(loginCookie.attributes.sameSite).toBe('lax');
      expect(loginCookie.attributes.secure).toBe(true);

      // Validate login state
      const loginState: LoginState = await decryptLoginState(loginCookie.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
      expect(loginState.codeVerifier).toBeTruthy();
      expect(loginState.redirectUri).toBe(redirectUri);
      expect(loginState.customState).toBeUndefined();
      expect(loginState.returnUrl).toBeUndefined();
    });

    test('Dangerously Disable Secure Cookies Configuration', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        dangerouslyDisableSecureCookies: true,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${parseTenantFromRootDomain}` },
        query: { tenant_domain: 'devs4you' },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(3);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_uri')).toEqual(redirectUri);
      expect(searchParams.get('response_type')).toEqual('code');
      expect(searchParams.get('state')).toBeTruthy();
      expect(searchParams.get('scope')).toEqual('openid offline_access email');
      expect(searchParams.get('code_challenge')).toBeTruthy();
      expect(searchParams.get('code_challenge_method')).toEqual('S256');
      expect(searchParams.get('nonce')).toBeTruthy();
      expect(searchParams.get('login_hint')).toBeFalsy();

      // Extract and validate cookies
      const cookies = extractCookiesFromHeaders(headers);
      expect(cookies.length).toBe(1);
      const loginCookie = cookies[0];

      // Validate login state cookie key
      const keyParts: string[] = loginCookie.name.split(LOGIN_STATE_COOKIE_SEPARATOR);
      expect(keyParts).toHaveLength(3);
      expect(keyParts[0]).toEqual('login');
      expect(keyParts[1]).toBeTruthy();
      expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

      // Validate login state cookie attributes
      expect(loginCookie.attributes.httpOnly).toBe(true);
      expect(loginCookie.attributes.maxAge).toBe(3600);
      expect(loginCookie.attributes.path).toBe('/');
      expect(loginCookie.attributes.sameSite).toBe('lax');
      expect(loginCookie.attributes.secure).toBe(false);

      // Validate login state
      const loginState: LoginState = await decryptLoginState(loginCookie.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
      expect(loginState.codeVerifier).toBeTruthy();
      expect(loginState.redirectUri).toBe(redirectUri);
      expect(loginState.customState).toBeUndefined();
      expect(loginState.returnUrl).toBeUndefined();
    });

    test('Tenant Subdomains Configuration', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      const headers = mockExpressRes._getHeaders();
      const cookies = extractCookiesFromHeaders(headers);
      expect(cookies.length).toBe(1);
      const loginCookie = cookies[0];

      // Validate login state cookie key
      const keyParts: string[] = loginCookie.name.split(LOGIN_STATE_COOKIE_SEPARATOR);

      // Validate login state
      const loginState: LoginState = await decryptLoginState(loginCookie.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
    });

    test('Custom Domains and Tenant Subdomains Configuration', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      const headers = mockExpressRes._getHeaders();
      const cookies = extractCookiesFromHeaders(headers);
      expect(cookies.length).toBe(1);
      const loginCookie = cookies[0];

      // Validate login state cookie key
      const keyParts: string[] = loginCookie.name.split(LOGIN_STATE_COOKIE_SEPARATOR);

      // Validate login state
      const loginState: LoginState = await decryptLoginState(loginCookie.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
    });

    test('Custom Domains with Tenant Custom Domain', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        query: { tenant_custom_domain: 'tenant.custom.com' },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      const headers = mockExpressRes._getHeaders();
      const cookies = extractCookiesFromHeaders(headers);
      expect(cookies.length).toBe(1);
      const loginCookie = cookies[0];

      // Validate login state cookie key
      const keyParts: string[] = loginCookie.name.split(LOGIN_STATE_COOKIE_SEPARATOR);

      // Validate login state
      const loginState: LoginState = await decryptLoginState(loginCookie.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
    });

    test('Custom Domains with All Domain Params', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${parseTenantFromRootDomain}` },
        query: { tenant_domain: 'devs4you', tenant_custom_domain: 'tenant.custom.com' },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      const headers = mockExpressRes._getHeaders();
      const cookies = extractCookiesFromHeaders(headers);
      expect(cookies.length).toBe(1);
      const loginCookie = cookies[0];

      // Validate login state cookie key
      const keyParts: string[] = loginCookie.name.split(LOGIN_STATE_COOKIE_SEPARATOR);

      // Validate login state
      const loginState: LoginState = await decryptLoginState(loginCookie.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
    });

    test('With login_hint and return_url query params', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        query: {
          login_hint: 'test@wristband.dev',
          return_url: `https://devs4you.${parseTenantFromRootDomain}/settings`,
        },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate query params of Authorize URL
      expect(searchParams.get('login_hint')).toBe('test@wristband.dev');

      // Validate login state cookie
      const headers = mockExpressRes._getHeaders();
      const cookies = extractCookiesFromHeaders(headers);
      expect(cookies.length).toBe(1);
      const loginCookie = cookies[0];

      // Validate login state cookie key
      const keyParts: string[] = loginCookie.name.split(LOGIN_STATE_COOKIE_SEPARATOR);

      // Validate login state
      const loginState: LoginState = await decryptLoginState(loginCookie.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.returnUrl).toBe(`https://devs4you.${parseTenantFromRootDomain}/settings`);
    });

    test('With returnUrl in LoginConfig', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${parseTenantFromRootDomain}` },
        query: { tenant_domain: 'devs4you' },
      });
      const mockExpressRes = httpMocks.createResponse();

      const loginConfig = {
        returnUrl: 'https://example.com/dashboard',
      };

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes, loginConfig));

      // Validate login state cookie contains return URL from config
      const headers = mockExpressRes._getHeaders();
      const cookies = extractCookiesFromHeaders(headers);
      const loginCookie = cookies[0];
      const loginState: LoginState = await decryptLoginState(loginCookie.value, LOGIN_STATE_COOKIE_SECRET);

      expect(loginState.returnUrl).toBe('https://example.com/dashboard');
    });

    test('LoginConfig returnUrl takes precedence over query parameter return_url', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${parseTenantFromRootDomain}` },
        query: {
          tenant_domain: 'devs4you',
          return_url: 'https://example.com/from-query', // This should be overridden
        },
      });
      const mockExpressRes = httpMocks.createResponse();

      const loginConfig = {
        returnUrl: 'https://example.com/from-config', // This should take precedence
      };

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes, loginConfig));

      // Validate login state cookie contains return URL from config, not query
      const headers = mockExpressRes._getHeaders();
      const cookies = extractCookiesFromHeaders(headers);
      const loginCookie = cookies[0];
      const loginState: LoginState = await decryptLoginState(loginCookie.value, LOGIN_STATE_COOKIE_SECRET);

      expect(loginState.returnUrl).toBe('https://example.com/from-config');
    });

    test('With both returnUrl and customState in LoginConfig', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${parseTenantFromRootDomain}` },
        query: { tenant_domain: 'devs4you' },
      });
      const mockExpressRes = httpMocks.createResponse();

      const loginConfig = {
        returnUrl: 'https://example.com/dashboard',
        customState: { userId: '123', feature: 'premium' },
      };

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes, loginConfig));

      // Validate login state cookie contains both return URL and custom state
      const headers = mockExpressRes._getHeaders();
      const cookies = extractCookiesFromHeaders(headers);
      const loginCookie = cookies[0];
      const loginState: LoginState = await decryptLoginState(loginCookie.value, LOGIN_STATE_COOKIE_SECRET);

      expect(loginState.returnUrl).toBe('https://example.com/dashboard');
      expect(loginState.customState).toEqual({ userId: '123', feature: 'premium' });
    });

    test('Empty returnUrl in LoginConfig is ignored (no returnUrl in state)', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${parseTenantFromRootDomain}` },
        query: {
          tenant_domain: 'devs4you',
          return_url: 'https://example.com/from-query',
        },
      });
      const mockExpressRes = httpMocks.createResponse();

      const loginConfig = {
        returnUrl: '', // Empty string gets filtered out by !!returnUrl check
      };

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes, loginConfig));

      // Validate login state cookie has no returnUrl (empty string was filtered out)
      const headers = mockExpressRes._getHeaders();
      const cookies = extractCookiesFromHeaders(headers);
      const loginCookie = cookies[0];
      const loginState: LoginState = await decryptLoginState(loginCookie.value, LOGIN_STATE_COOKIE_SECRET);

      expect(loginState.returnUrl).toBeUndefined();
    });

    test('Clear old login state cookie', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Mock login states
      const loginState01: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: '++state01' };
      const loginState02: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state02' };
      const loginState03: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state03' };
      const encryptedLoginState01: string = await encryptLoginState(loginState01, LOGIN_STATE_COOKIE_SECRET);
      const encryptedLoginState02: string = await encryptLoginState(loginState02, LOGIN_STATE_COOKIE_SECRET);
      const encryptedLoginState03: string = await encryptLoginState(loginState03, LOGIN_STATE_COOKIE_SECRET);

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        headers: {
          host: `devs4you.${parseTenantFromRootDomain}`,
          cookie: [
            `login#++state01#1111111111=${encryptedLoginState01}`,
            `login#state02#2222222222=${encryptedLoginState02}`,
            `login#state03#3333333333=${encryptedLoginState03}`,
          ].join('; '),
        },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Get all Set-Cookie headers
      const headers = mockExpressRes._getHeaders();
      const setCookieHeaders = headers['set-cookie'];
      expect(setCookieHeaders).toBeTruthy();
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect(setCookieHeaders?.length).toBe(2);

      // Validate old login state cookie is getting cleared
      const oldCookieHeader = setCookieHeaders?.find((header) => {
        return header.startsWith('login#++state01#1111111111=');
      });
      expect(oldCookieHeader).toBeTruthy();
      expect(oldCookieHeader?.startsWith(`login#++state01#1111111111=;`)).toBe(true);
      expect(oldCookieHeader).toContain('Max-Age=0');
      expect(oldCookieHeader).toContain('Path=/');
      expect(oldCookieHeader).toContain('HttpOnly');

      // Validate new login state cookie
      const newCookieHeader = setCookieHeaders?.find((header) => {
        return !header.startsWith('login#++state01#1111111111=');
      });
      expect(newCookieHeader).toBeTruthy();
      const newCookieMatch = newCookieHeader?.match(/^([^=]+)=([^;]+)/);
      expect(newCookieMatch).toBeTruthy();
      const newCookieName = newCookieMatch ? newCookieMatch[1] : '';
      const newCookieValue = newCookieMatch ? newCookieMatch[2] : '';
      const keyParts: string[] = newCookieName.split(LOGIN_STATE_COOKIE_SEPARATOR);
      expect(keyParts.length).toBeGreaterThanOrEqual(2);
      expect(keyParts[0]).toEqual('login');
      const loginState: LoginState = await decryptLoginState(newCookieValue, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
    });
  });

  describe('Redirect to Application-level Login/Tenant Discovery', () => {
    test('Unresolved tenant_domain and tenant_custom_domain query params', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // tenant_domain and tenant_custom_domain query param is missing, which should redirect to app-level login.
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Unresolved tenant subdomain', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Subdomain is missing from host, which should redirect to app-level login.
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Custom application login URL redirect', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        customApplicationLoginPageUrl: 'https://google.com',
        autoConfigureEnabled: false,
      });

      // Subdomain is missing from host, which should redirect to app-level login.
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      expect(location).toBe(`https://google.com?client_id=${CLIENT_ID}`);
    });
  });
});
