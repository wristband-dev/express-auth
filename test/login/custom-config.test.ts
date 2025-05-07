/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-underscore-dangle */

import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { decryptLoginState } from '../../src/utils';
import { LoginState } from '../../src/types';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const CUSTOM_SCOPES = ['openid', 'roles'];
const CUSTOM_STATE = { test: 'abc' };
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

describe('Custom Login Configurations', () => {
  let wristbandAuth: WristbandAuth;
  let rootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    rootDomain = 'business.invotastic.com';
    wristbandApplicationVanityDomain = 'auth.invotastic.com';
    loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
    redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
  });

  describe('Successful Redirect to Authorize Endpoint', () => {
    test('Custom Scopes Configuration at the Class Level', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
        scopes: CUSTOM_SCOPES,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
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
      expect(searchParams.get('scope')).toEqual(CUSTOM_SCOPES.join(' '));

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
      expect(loginState.customState).toBeFalsy();
    });

    test('Custom State at the Function Level', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes, { customState: CUSTOM_STATE }));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
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
      expect(loginState.customState).toEqual(CUSTOM_STATE);
    });

    // ///////////////////////////////////////////
    //  PRIORITY ORDER #1 - TENANT CUSTOM DOMAIN
    // ///////////////////////////////////////////

    test('01: Tenant custom domain query param precedence over tenant subdomains', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com' },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://query.tenant.com`);
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
      expect(loginState.customState).toBeUndefined();
    });

    test('02: Tenant custom domain query param precedence over tenant domain query param', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: false,
        useCustomDomains: true,
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com', tenant_domain: 'devs4you' },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://query.tenant.com`);
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
      expect(loginState.customState).toBeUndefined();
    });

    test('03: Tenant custom domain query param precedence over default tenant custom domain Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: false,
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com' },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.login(mockExpressReq, mockExpressRes, {
          defaultTenantCustomDomain: 'tenant.custom.com',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://query.tenant.com`);
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
      expect(loginState.customState).toBeUndefined();
    });

    test('04: Tenant custom domain query param precedence over default tenant domain name Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: false,
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com' },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.login(mockExpressReq, mockExpressRes, {
          defaultTenantDomainName: 'tenant',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://query.tenant.com`);
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
      expect(loginState.customState).toBeUndefined();
    });

    // ///////////////////////////////////////
    //  PRIORITY ORDER #2 - TENANT SUBDOMAIN
    // ///////////////////////////////////////

    test('01: Tenant subdomain takes precedence over tenant domain query param', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.login(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
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
      expect(loginState.customState).toBeUndefined();
    });

    test('02: Tenant subdomain takes precedence over default tenant custom domain Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.login(mockExpressReq, mockExpressRes, {
          defaultTenantCustomDomain: 'default.tenant.com',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
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
      expect(loginState.customState).toBeUndefined();
    });

    test('03: Tenant subdomain takes precedence over default tenant domain name Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.login(mockExpressReq, mockExpressRes, {
          defaultTenantDomainName: 'default',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
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
      expect(loginState.customState).toBeUndefined();
    });

    // ////////////////////////////////////////////////
    //  PRIORITY ORDER #3 - TENANT DOMAIN QUERY PARAM
    // ////////////////////////////////////////////////

    test('01: Tenant domain query param takes precedence over default tenant custom domain Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_domain: 'devs4you' },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.login(mockExpressReq, mockExpressRes, {
          defaultTenantCustomDomain: 'global.tenant.com',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
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
      expect(loginState.customState).toBeUndefined();
    });

    test('02: Tenant domain query param takes precedence over default tenant domain name Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_domain: 'devs4you' },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.login(mockExpressReq, mockExpressRes, {
          defaultTenantDomainName: 'global',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
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
      expect(loginState.customState).toBeUndefined();
    });

    // //////////////////////////////////////////////////////////
    //  PRIORITY ORDER #4 - DEFAULT TENANT CUSTOM DOMAIN CONFIG
    // //////////////////////////////////////////////////////////

    test('01: Default tenant custom domain takes precedence over default tenant domain name Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.login(mockExpressReq, mockExpressRes, {
          defaultTenantDomainName: 'global',
          defaultTenantCustomDomain: 'global.tenant.com',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://global.tenant.com`);
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
      expect(loginState.customState).toBeUndefined();
    });

    test('02: Default tenant custom domain without any other Login config or query params', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: false,
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.login(mockExpressReq, mockExpressRes, { defaultTenantCustomDomain: 'tenant.custom.com' })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
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
      expect(loginState.customState).toBeUndefined();
    });

    // //////////////////////////////////////////////////////////
    //  PRIORITY ORDER #5 - DEFAULT TENANT DOMAIN NAME CONFIG
    // //////////////////////////////////////////////////////////

    test('01: Default tenant domain name without any other Login config or query params', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://${rootDomain}/api/auth/login`,
        redirectUri: `https://${rootDomain}/api/auth/callback`,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.login(mockExpressReq, mockExpressRes, {
          defaultTenantDomainName: 'global',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://global.${wristbandApplicationVanityDomain}`);
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
      expect(loginState.customState).toBeUndefined();
    });
  });
});
