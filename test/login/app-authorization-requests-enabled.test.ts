/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-underscore-dangle */

import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { decryptLoginState, encryptLoginState } from '../../src/utils';
import { LoginState } from '../../src/types';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';
import { mockWristbandFetch } from '../helpers/mock-fetch';

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
    domain: string | undefined;
  };
}> {
  const setCookieHeader = headers['set-cookie'];
  if (!setCookieHeader) {
    return [];
  }

  const cookieStrings = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];

  return cookieStrings.map((cookieString) => {
    const [nameValue, ...attributeParts] = cookieString.split('; ');
    const nameValueParts = nameValue.split('=');
    const name = nameValueParts[0];
    const value = nameValueParts.slice(1).join('=');

    const attributes = {
      httpOnly: false,
      secure: false,
      path: undefined as string | undefined,
      maxAge: undefined as number | undefined,
      sameSite: undefined as string | undefined,
      domain: undefined as string | undefined,
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
      } else if (attr.startsWith('Domain=')) {
        attributes.domain = attr.substring(7);
      }
    });

    return { name, value, attributes };
  });
}

describe('Login - App-Level Authorization Requests', () => {
  let wristbandAuth: WristbandAuth;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
    mockWristbandFetch();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Fixed host configuration (no tenant subdomains)', () => {
    const loginUrl = 'https://localhost:6001/api/auth/login';
    const redirectUri = 'https://localhost:6001/api/auth/callback';

    test('Redirects to app-level Authorize Endpoint when tenant cannot be resolved', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: 'localhost:6001' },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate no-cache headers still present
      const headers = mockExpressRes._getHeaders();
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

      // A login state cookie SHOULD be set now (unlike the applicationAuthorizationRequestsEnabled: false case)
      const cookies = extractCookiesFromHeaders(headers);
      expect(cookies.length).toBe(1);
      const loginCookie = cookies[0];

      const keyParts: string[] = loginCookie.name.split(LOGIN_STATE_COOKIE_SEPARATOR);
      expect(keyParts[0]).toEqual('login');

      // No parseTenantFromRootDomain configured, so no Domain attribute should be set
      expect(loginCookie.attributes.domain).toBeUndefined();
      expect(loginCookie.attributes.httpOnly).toBe(true);
      expect(loginCookie.attributes.maxAge).toBe(3600);
      expect(loginCookie.attributes.secure).toBe(true);

      const loginState: LoginState = await decryptLoginState(loginCookie.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
    });

    test('Ignores customApplicationLoginPageUrl when applicationAuthorizationRequestsEnabled is true', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        customApplicationLoginPageUrl: 'https://custom-login.example.com',
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: 'localhost:6001' },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const location = await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Should go to the app-level Authorize Endpoint, NOT the custom login page
      expect(new URL(location).origin).toEqual(`https://${wristbandApplicationVanityDomain}`);
      expect(new URL(location).pathname).toEqual('/api/v1/oauth2/authorize');
    });

    test('Uses dangerouslyDisableSecureCookies flag on the app-level login state cookie', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        dangerouslyDisableSecureCookies: true,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: 'localhost:6001' },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      const headers = mockExpressRes._getHeaders();
      const cookies = extractCookiesFromHeaders(headers);
      expect(cookies[0].attributes.secure).toBe(false);
    });

    test('Includes idp_hint and login_hint query params on the app-level Authorize URL', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: 'localhost:6001' },
        query: { idp_hint: 'google', login_hint: 'user@example.com' },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const location = await wristbandAuth.login(mockExpressReq, mockExpressRes);
      const searchParams = new URL(location).searchParams;

      expect(searchParams.get('idp_hint')).toBe('google');
      expect(searchParams.get('login_hint')).toBe('user@example.com');
    });

    test('Clears stale login state cookies before setting the new one', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        autoConfigureEnabled: false,
      });

      const loginState01: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: '++state01' };
      const loginState02: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state02' };
      const loginState03: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state03' };
      const encryptedLoginState01 = await encryptLoginState(loginState01, LOGIN_STATE_COOKIE_SECRET);
      const encryptedLoginState02 = await encryptLoginState(loginState02, LOGIN_STATE_COOKIE_SECRET);
      const encryptedLoginState03 = await encryptLoginState(loginState03, LOGIN_STATE_COOKIE_SECRET);

      const mockExpressReq = httpMocks.createRequest({
        headers: {
          host: 'localhost:6001',
          cookie: [
            `login#++state01#1111111111=${encryptedLoginState01}`,
            `login#state02#2222222222=${encryptedLoginState02}`,
            `login#state03#3333333333=${encryptedLoginState03}`,
          ].join('; '),
        },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      const setCookieHeaders = mockExpressRes._getHeaders()['set-cookie'];
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect(setCookieHeaders.length).toBe(2);

      const oldCookieHeader = setCookieHeaders.find((h: string) => {
        return h.startsWith('login#++state01#1111111111=');
      });
      expect(oldCookieHeader).toBeTruthy();
      expect(oldCookieHeader).toContain('Max-Age=0');
    });
  });

  describe('Tenant subdomain configuration (parseTenantFromRootDomain set)', () => {
    const parseTenantFromRootDomain = 'business.invotastic.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

    test('Sets the login state cookie with a Domain attribute scoped to parseTenantFromRootDomain', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        fallbackLoginUrl: `https://${wristbandApplicationVanityDomain}/login`,
        autoConfigureEnabled: false,
      });

      // No subdomain present on the host, so tenant cannot be resolved
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const location = await wristbandAuth.login(mockExpressReq, mockExpressRes);

      expect(new URL(location).origin).toEqual(`https://${wristbandApplicationVanityDomain}`);
      expect(new URL(location).pathname).toEqual('/api/v1/oauth2/authorize');

      const headers = mockExpressRes._getHeaders();
      const cookies = extractCookiesFromHeaders(headers);
      expect(cookies.length).toBe(1);
      expect(cookies[0].attributes.domain).toBe(`.${parseTenantFromRootDomain}`);
    });

    test('Clears stale login state cookies with the matching Domain attribute', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        fallbackLoginUrl: `https://${wristbandApplicationVanityDomain}/login`,
        autoConfigureEnabled: false,
      });

      const loginState01: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: '++state01' };
      const loginState02: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state02' };
      const loginState03: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state03' };
      const encryptedLoginState01 = await encryptLoginState(loginState01, LOGIN_STATE_COOKIE_SECRET);
      const encryptedLoginState02 = await encryptLoginState(loginState02, LOGIN_STATE_COOKIE_SECRET);
      const encryptedLoginState03 = await encryptLoginState(loginState03, LOGIN_STATE_COOKIE_SECRET);

      // No subdomain present, so tenant cannot be resolved and this hits the app-level branch
      const mockExpressReq = httpMocks.createRequest({
        headers: {
          host: parseTenantFromRootDomain,
          cookie: [
            `login#++state01#1111111111=${encryptedLoginState01}`,
            `login#state02#2222222222=${encryptedLoginState02}`,
            `login#state03#3333333333=${encryptedLoginState03}`,
          ].join('; '),
        },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      const setCookieHeaders = mockExpressRes._getHeaders()['set-cookie'];
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect(setCookieHeaders.length).toBe(2);

      const oldCookieHeader = setCookieHeaders.find((h: string) => {
        return h.startsWith('login#++state01#1111111111=');
      });
      expect(oldCookieHeader).toBeTruthy();
      expect(oldCookieHeader).toContain('Max-Age=0');
      expect(oldCookieHeader).toContain(`Domain=.${parseTenantFromRootDomain}`);

      const newCookieHeader = setCookieHeaders.find((h: string) => {
        return !h.startsWith('login#++state01#1111111111=');
      });
      expect(newCookieHeader).toContain(`Domain=.${parseTenantFromRootDomain}`);
    });
  });

  describe('Tenant resolvable - applicationAuthorizationRequestsEnabled has no effect', () => {
    test('Uses the normal tenant-level flow when a tenant_name is resolvable, even with the flag enabled', async () => {
      const parseTenantFromRootDomain = 'business.invotastic.com';
      const loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      const redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
        query: { tenant_name: 'devs4you' },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const location = await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Should hit the tenant-level Authorize Endpoint (hyphen-separated), not the app-level one
      expect(new URL(location).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
    });
  });
});
