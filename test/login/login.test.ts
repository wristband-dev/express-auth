/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-underscore-dangle */

import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { decryptLoginState, encryptLoginState } from '../../src/utils';
import { LoginState } from '../../src/types';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

describe('Multi Tenant Login', () => {
  let wristbandAuth: WristbandAuth;
  let rootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationDomain: string;

  beforeEach(() => {
    rootDomain = 'localhost:6001';
    loginUrl = `https://${rootDomain}/api/auth/login`;
    redirectUri = `https://${rootDomain}/api/auth/callback`;
    wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
  });

  describe('Successful Redirect to Authorize Endpoint', () => {
    test('Default Configuration', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_domain: 'devs4you' },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you-${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(2);
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

      // Validate login state cookie key
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const cookieKey: string = loginStateCookie[0];
      const keyParts: string[] = cookieKey.split(':');
      expect(keyParts).toHaveLength(3);
      expect(keyParts[0]).toEqual('login');
      expect(keyParts[1]).toBeTruthy();
      expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

      // Validate login state cookie value
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const { options, value } = cookieValue;

      expect(options.httpOnly).toBe(true);
      expect(options.maxAge).toBe(3600000);
      expect(options.path).toBe('/');
      expect(options.sameSite).toBe('lax');
      expect(options.secure).toBe(true);

      const loginState: LoginState = await decryptLoginState(value, LOGIN_STATE_COOKIE_SECRET);
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
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_domain: 'devs4you' },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you-${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(2);
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

      // Validate login state cookie key
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const cookieKey: string = loginStateCookie[0];
      const keyParts: string[] = cookieKey.split(':');
      expect(keyParts).toHaveLength(3);
      expect(keyParts[0]).toEqual('login');
      expect(keyParts[1]).toBeTruthy();
      expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

      // Validate login state cookie value
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const { options, value } = cookieValue;

      expect(options.httpOnly).toBe(true);
      expect(options.maxAge).toBe(3600000);
      expect(options.path).toBe('/');
      expect(options.sameSite).toBe('lax');
      expect(options.secure).toBe(false);

      const loginState: LoginState = await decryptLoginState(value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
      expect(loginState.codeVerifier).toBeTruthy();
      expect(loginState.redirectUri).toBe(redirectUri);
      expect(loginState.customState).toBeUndefined();
      expect(loginState.returnUrl).toBeUndefined();
    });

    test('Tenant Subdomains Configuration', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you-${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const loginState: LoginState = await decryptLoginState(loginStateCookie[1].value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
    });

    test('Custom Domains and Tenant Subdomains Configuration', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const loginState: LoginState = await decryptLoginState(loginStateCookie[1].value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
    });

    test('Custom Domains with Tenant Custom Domain', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
        query: { tenant_custom_domain: 'tenant.custom.com' },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const loginState: LoginState = await decryptLoginState(loginStateCookie[1].value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
    });

    test('Custom Domains with All Domain Params', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_domain: 'devs4you', tenant_custom_domain: 'tenant.custom.com' },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const loginState: LoginState = await decryptLoginState(loginStateCookie[1].value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
    });

    test('With login_hint and return_url query params', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
        query: {
          login_hint: 'test@wristband.dev',
          return_url: `https://devs4you.${rootDomain}/settings`,
        },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate query params of Authorize URL
      expect(searchParams.get('login_hint')).toBe('test@wristband.dev');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const loginState: LoginState = await decryptLoginState(loginStateCookie[1].value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.returnUrl).toBe(`https://devs4you.${rootDomain}/settings`);
    });

    test('Clear old login state cookie', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
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
        cookies: {
          'login:++state01:1111111111': encryptedLoginState01,
          'login:state02:2222222222': encryptedLoginState02,
          'login:state03:3333333333': encryptedLoginState03,
        },
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate old login state cookie is getting cleared
      expect(Object.keys(cookies)).toHaveLength(2);
      const oldLoginStateCookie = Object.entries(cookies)[0];
      const oldCookieName = oldLoginStateCookie[0];
      expect(oldCookieName).toBe('login:++state01:1111111111');
      const oldCookieValue = oldLoginStateCookie[1];
      expect(Object.keys(oldCookieValue)).toHaveLength(2);
      expect(oldCookieValue.options.expires?.valueOf()).toBeLessThan(Date.now().valueOf());
      expect(oldCookieValue.options.path).toBe('/');
      expect(oldCookieValue.value).toBeFalsy();

      // Validate new login state cookie
      const loginStateCookie = Object.entries(cookies)[1];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const { value } = cookieValue;

      const loginState: LoginState = await decryptLoginState(value, LOGIN_STATE_COOKIE_SECRET);
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
        wristbandApplicationDomain,
      });

      // tenant_domain and tenant_custom_domain query param is missing, which should redirect to app-level login.
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: rootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      expect(location).toBe(`https://${wristbandApplicationDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Unresolved tenant subdomain', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      // Subdomain is missing from host, which should redirect to app-level login.
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: rootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      expect(location).toBe(`https://${wristbandApplicationDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Custom application login URL redirect', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
        customApplicationLoginPageUrl: 'https://google.com',
      });

      // Subdomain is missing from host, which should redirect to app-level login.
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: rootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      expect(location).toBe(`https://google.com?client_id=${CLIENT_ID}`);
    });
  });
});
