import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { CallbackData, CallbackResult, LoginState } from '../../src/types';
import { encryptLoginState } from '../../src/utils';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

function mockFetchCallbackEndpoints(domain: string, mockTokens: unknown, mockUserinfo: unknown) {
  global.fetch = jest.fn().mockImplementation((url: string) => {
    const body = url.includes('/oauth2/token') ? mockTokens : mockUserinfo;
    return Promise.resolve({
      status: 200,
      ok: true,
      headers: {
        get: () => {
          return 'application/json';
        },
      },
      text: jest.fn().mockResolvedValue(JSON.stringify(body)),
    });
  });
}

describe('Multi Tenant Callback', () => {
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

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Callback Happy Path', () => {
    test('Default Configuration', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: loginUrl,
        redirectUri: redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockTokens = {
        access_token: 'accessToken',
        expires_in: 1800,
        id_token: 'idToken',
        refresh_token: 'refreshToken',
        token_type: 'bearer',
      };
      const mockUserinfo = {
        sub: '5q6j4qe2cva3dm3cbdvjoxvuze',
        tnt_id: 'fr2vishnqjdvfbcijxa3a4adhe',
        app_id: 'dy42gabu5jebreq6jajskk2n34',
        idp_name: 'wristband',
        email: 'test@wristband.dev',
        email_verified: true,
      };
      mockFetchCallbackEndpoints(wristbandApplicationVanityDomain, mockTokens, mockUserinfo);

      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri: redirectUri,
        state: 'state',
        customState: { test: 'abc' },
        returnUrl: 'https://reddit.com',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      const mockExpressReq = httpMocks.createRequest({
        query: { state: 'state', code: 'code', tenant_name: 'devs4you' },
        headers: {
          cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
          host: parseTenantFromRootDomain,
        },
      }) as any;
      // node-mocks-http leaves req.protocol undefined, so set it to match a real HTTPS request.
      mockExpressReq.protocol = 'https';
      const mockExpressRes = httpMocks.createResponse() as any;

      const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      const { callbackData, type } = callbackResult;
      expect(type).toBe('completed');
      expect(callbackData).toBeTruthy();
      if (callbackData) {
        expect(callbackData.accessToken).toBe('accessToken');
        expect(callbackData.expiresIn).toBe(1740);
        expect(callbackData.idToken).toBe('idToken');
        expect(callbackData.refreshToken).toBe('refreshToken');
        expect(callbackData.customState).toEqual({ test: 'abc' });
        // Off-site returnUrl is rejected by open redirect validation.
        expect(callbackData.returnUrl).toBeUndefined();
        expect(callbackData.tenantName).toBe('devs4you');
        expect(callbackData.userinfo).toBeTruthy();
        expect(callbackData.userinfo.userId).toBe('5q6j4qe2cva3dm3cbdvjoxvuze');
        expect(callbackData.userinfo.tenantId).toBe('fr2vishnqjdvfbcijxa3a4adhe');
        expect(callbackData.userinfo.applicationId).toBe('dy42gabu5jebreq6jajskk2n34');
        expect(callbackData.userinfo.identityProviderName).toBe('wristband');
        expect(callbackData.userinfo.email).toBe('test@wristband.dev');
        expect(callbackData.userinfo.emailVerified).toBe(true);
      }

      // eslint-disable-next-line no-underscore-dangle
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeFalsy();

      // eslint-disable-next-line no-underscore-dangle
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(3);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      const setCookieHeader = headers['set-cookie'];
      expect(setCookieHeader).toBeTruthy();
      const setCookieValue = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader;
      expect(setCookieValue).toBeTruthy();
      const cookieNameMatch = setCookieValue?.match(/^([^=]+)=/);
      expect(cookieNameMatch).toBeTruthy();
      const cookieName = cookieNameMatch ? cookieNameMatch[1] : '';
      const keyParts: string[] = cookieName.split(LOGIN_STATE_COOKIE_SEPARATOR);
      expect(keyParts).toHaveLength(3);
      expect(keyParts[0]).toEqual('login');
      expect(keyParts[1]).toBe('state');
      expect(keyParts[1]).toEqual(mockExpressReq.query.state);
      expect(parseInt(keyParts[2], 10)).toBe(1234567890);
      expect(setCookieValue?.startsWith(`${cookieName}=;`)).toBe(true);
      expect(setCookieValue).toContain('Path=/');
      expect(setCookieValue).toContain('HttpOnly');
      expect(setCookieValue).toContain('Max-Age=0');

      expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('Tenant Subdomains Configuration with %s placeholder', (placeholderName, placeholder) => {
      test(`Tenant Subdomains Configuration using ${placeholderName}`, async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
        wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          parseTenantFromRootDomain,
          wristbandApplicationVanityDomain,
          autoConfigureEnabled: false,
          applicationAuthorizationRequestsEnabled: false,
        });

        const mockTokens = {
          access_token: 'accessToken',
          expires_in: 1800,
          id_token: 'idToken',
          refresh_token: 'refreshToken',
          token_type: 'bearer',
        };
        const mockUserinfo = {
          sub: '5q6j4qe2cva3dm3cbdvjoxvuze',
          tnt_id: 'fr2vishnqjdvfbcijxa3a4adhe',
          app_id: 'dy42gabu5jebreq6jajskk2n34',
          idp_name: 'wristband',
          email: 'test@wristband.dev',
          email_verified: true,
        };
        mockFetchCallbackEndpoints(wristbandApplicationVanityDomain, mockTokens, mockUserinfo);

        const loginState: LoginState = {
          codeVerifier: 'codeVerifier',
          redirectUri: redirectUri,
          state: 'state',
        };
        const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

        const mockExpressReq = httpMocks.createRequest({
          query: { state: 'state', code: 'code' },
          headers: {
            cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
            host: `devs4you.${parseTenantFromRootDomain}`,
          },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
        const { callbackData, type } = callbackResult;
        expect(type).toBe('completed');
        expect(callbackData).toBeTruthy();
        if (callbackData) {
          expect(callbackData.tenantName).toBe('devs4you');
          expect(callbackData.customState).toBeFalsy();
          expect(callbackData.returnUrl).toBeFalsy();
        }

        // eslint-disable-next-line no-underscore-dangle
        const location: string = mockExpressRes._getRedirectUrl();
        expect(location).toBeFalsy();
        expect(global.fetch).toHaveBeenCalledTimes(2);
      });
    });

    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('Custom Domains and Tenant Subdomains with %s placeholder', (placeholderName, placeholder) => {
      test(`Custom Domains and Tenant Subdomains Configuration using ${placeholderName}`, async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        wristbandApplicationVanityDomain = 'auth.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
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
          applicationAuthorizationRequestsEnabled: false,
        });

        const mockTokens = {
          access_token: 'accessToken',
          expires_in: 1800,
          id_token: 'idToken',
          refresh_token: 'refreshToken',
          token_type: 'bearer',
        };
        const mockUserinfo = {
          sub: '5q6j4qe2cva3dm3cbdvjoxvuze',
          tnt_id: 'fr2vishnqjdvfbcijxa3a4adhe',
          app_id: 'dy42gabu5jebreq6jajskk2n34',
          idp_name: 'wristband',
          email: 'test@wristband.dev',
          email_verified: true,
        };
        mockFetchCallbackEndpoints(wristbandApplicationVanityDomain, mockTokens, mockUserinfo);

        const loginState: LoginState = {
          codeVerifier: 'codeVerifier',
          redirectUri: redirectUri,
          state: 'state',
        };
        const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

        const mockExpressReq = httpMocks.createRequest({
          query: { state: 'state', code: 'code' },
          headers: {
            cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
            host: `devs4you.${parseTenantFromRootDomain}`,
          },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
        const { callbackData, type } = callbackResult;
        expect(type).toBe('completed');
        expect(callbackData).toBeTruthy();
        if (callbackData) {
          expect(callbackData.tenantName).toBe('devs4you');
          expect(callbackData.customState).toBeFalsy();
          expect(callbackData.returnUrl).toBeFalsy();
        }

        // eslint-disable-next-line no-underscore-dangle
        const location: string = mockExpressRes._getRedirectUrl();
        expect(location).toBeFalsy();
        expect(global.fetch).toHaveBeenCalledTimes(2);
      });
    });

    describe('Return URL Validation', () => {
      const rootDomain = 'business.invotastic.com';

      // Runs a successful callback with the given returnUrl in the login state and returns the callback data.
      // With tenant subdomains, the tenant comes from the host; without, it comes from the tenant_name query param.
      async function runCallbackWithReturnUrl(
        returnUrl: string,
        useTenantSubdomains: boolean,
        applicationAuthorizationRequestsEnabled: boolean = false
      ): Promise<CallbackData | undefined> {
        const host = useTenantSubdomains ? `devs4you.${rootDomain}` : rootDomain;
        const callbackLoginUrl = useTenantSubdomains
          ? `https://{tenant_name}.${rootDomain}/api/auth/login`
          : `https://${rootDomain}/api/auth/login`;
        const callbackRedirectUri = useTenantSubdomains
          ? `https://{tenant_name}.${rootDomain}/api/auth/callback`
          : `https://${rootDomain}/api/auth/callback`;

        const authConfig = {
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: callbackLoginUrl,
          redirectUri: callbackRedirectUri,
          ...(useTenantSubdomains && { parseTenantFromRootDomain: rootDomain }),
          applicationAuthorizationRequestsEnabled,
          // Required by config validation when app-level authorization requests are enabled
          // and loginUrl contains the {tenant_name} placeholder.
          ...(applicationAuthorizationRequestsEnabled && { fallbackLoginUrl: `https://${rootDomain}/api/auth/login` }),
          wristbandApplicationVanityDomain,
          autoConfigureEnabled: false,
        };
        wristbandAuth = createWristbandAuth(authConfig);

        const mockTokens = {
          access_token: 'accessToken',
          expires_in: 1800,
          id_token: 'idToken',
          refresh_token: 'refreshToken',
          token_type: 'bearer',
        };
        const mockUserinfo = {
          sub: '5q6j4qe2cva3dm3cbdvjoxvuze',
          tnt_id: 'fr2vishnqjdvfbcijxa3a4adhe',
          app_id: 'dy42gabu5jebreq6jajskk2n34',
          idp_name: 'wristband',
          email: 'test@wristband.dev',
          email_verified: true,
        };
        mockFetchCallbackEndpoints(wristbandApplicationVanityDomain, mockTokens, mockUserinfo);

        const loginState: LoginState = {
          codeVerifier: 'codeVerifier',
          redirectUri: callbackRedirectUri,
          state: 'state',
          returnUrl,
        };
        const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

        const mockExpressReq = httpMocks.createRequest({
          query: useTenantSubdomains
            ? { state: 'state', code: 'code' }
            : { state: 'state', code: 'code', tenant_name: 'devs4you' },
          headers: {
            cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
            host,
          },
        }) as any;
        // node-mocks-http leaves req.protocol undefined, so set it to match a real HTTPS request.
        mockExpressReq.protocol = 'https';
        const mockExpressRes = httpMocks.createResponse() as any;

        const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
        expect(callbackResult.type).toBe('completed');
        return callbackResult.callbackData;
      }

      test('Allows a relative path returnUrl', async () => {
        const callbackData = await runCallbackWithReturnUrl('/settings?tab=billing', false);
        expect(callbackData?.returnUrl).toBe('/settings?tab=billing');
      });

      test('Allows an absolute returnUrl on the request host', async () => {
        const callbackData = await runCallbackWithReturnUrl(`https://${rootDomain}/dashboard`, false);
        expect(callbackData?.returnUrl).toBe(`https://${rootDomain}/dashboard`);
      });

      test('Rejects an off-site returnUrl', async () => {
        const callbackData = await runCallbackWithReturnUrl('https://evil.com/phish', false);
        expect(callbackData?.returnUrl).toBeUndefined();
      });

      test('Rejects a protocol-relative returnUrl to another host', async () => {
        const callbackData = await runCallbackWithReturnUrl('//evil.com/phish', false);
        expect(callbackData?.returnUrl).toBeUndefined();
      });

      test('Rejects a returnUrl with a mismatched protocol', async () => {
        const callbackData = await runCallbackWithReturnUrl(`http://${rootDomain}/dashboard`, false);
        expect(callbackData?.returnUrl).toBeUndefined();
      });

      test('Allows a returnUrl on the current tenant subdomain', async () => {
        const callbackData = await runCallbackWithReturnUrl(`https://devs4you.${rootDomain}/dashboard`, true);
        expect(callbackData?.returnUrl).toBe(`https://devs4you.${rootDomain}/dashboard`);
      });

      test('Rejects a returnUrl on a different tenant subdomain', async () => {
        const callbackData = await runCallbackWithReturnUrl(`https://other.${rootDomain}/dashboard`, true);
        expect(callbackData?.returnUrl).toBeUndefined();
      });

      test('Allows a root domain returnUrl unchanged when app-level authorization requests are disabled', async () => {
        const callbackData = await runCallbackWithReturnUrl(`https://${rootDomain}/dashboard`, true, false);
        expect(callbackData?.returnUrl).toBe(`https://${rootDomain}/dashboard`);
      });

      test('Rewrites a root domain returnUrl to the tenant subdomain when app-level authorization requests are enabled', async () => {
        const callbackData = await runCallbackWithReturnUrl(`https://${rootDomain}/dashboard?x=1#top`, true, true);
        expect(callbackData?.returnUrl).toBe(`https://devs4you.${rootDomain}/dashboard?x=1#top`);
      });

      test('Does not rewrite a returnUrl already on the tenant subdomain when app-level authorization requests are enabled', async () => {
        const callbackData = await runCallbackWithReturnUrl(`https://devs4you.${rootDomain}/dashboard`, true, true);
        expect(callbackData?.returnUrl).toBe(`https://devs4you.${rootDomain}/dashboard`);
      });

      test('Does not rewrite a relative path when app-level authorization requests are enabled', async () => {
        const callbackData = await runCallbackWithReturnUrl('/dashboard', true, true);
        expect(callbackData?.returnUrl).toBe('/dashboard');
      });

      test('Still rejects an off-site returnUrl when app-level authorization requests are enabled', async () => {
        const callbackData = await runCallbackWithReturnUrl('https://evil.com/phish', true, true);
        expect(callbackData?.returnUrl).toBeUndefined();
      });
    });
  });

  describe('Redirect to Tenant-level Login', () => {
    test('Missing login state cookie, without tenant subdomains', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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
        query: { state: 'state', code: 'code', tenant_name: 'devs4you' },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(redirectUrl).toBe(`https://${parseTenantFromRootDomain}/api/auth/login?tenant_name=devs4you`);
      expect(callbackData).toBeFalsy();
    });

    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('Missing login state cookie with %s placeholder', (placeholderName, placeholder) => {
      test(`Missing login state cookie, with tenant subdomains using ${placeholderName}`, async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
        wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          parseTenantFromRootDomain,
          wristbandApplicationVanityDomain,
          autoConfigureEnabled: false,
          applicationAuthorizationRequestsEnabled: false,
        });

        const mockExpressReq = httpMocks.createRequest({
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
          query: { state: 'state', code: 'code' },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
        const { callbackData, redirectUrl, type } = callbackResult;
        expect(type).toBe('redirect_required');
        expect(redirectUrl).toBe(`https://devs4you.${parseTenantFromRootDomain}/api/auth/login`);
        expect(callbackData).toBeFalsy();
      });
    });

    test('Default Configuration for login_required error', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      const mockExpressReq = httpMocks.createRequest({
        query: {
          state: 'state',
          code: 'code',
          tenant_name: 'devs4you',
          error: 'login_required',
          error_description: 'Login required',
        },
        headers: {
          cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
        },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(redirectUrl).toBe(`https://${parseTenantFromRootDomain}/api/auth/login?tenant_name=devs4you`);
      expect(callbackData).toBeFalsy();
    });

    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('Login required error with %s placeholder', (placeholderName, placeholder) => {
      test(`Tenant Subdomain Configuration for login_required error using ${placeholderName}`, async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
        wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          parseTenantFromRootDomain,
          wristbandApplicationVanityDomain,
          autoConfigureEnabled: false,
          applicationAuthorizationRequestsEnabled: false,
        });

        const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
        const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

        const mockExpressReq = httpMocks.createRequest({
          query: { state: 'state', code: 'code', error: 'login_required', error_description: 'Login required' },
          headers: {
            cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
            host: `devs4you.${parseTenantFromRootDomain}`,
          },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
        const { callbackData, redirectUrl, type } = callbackResult;
        expect(type).toBe('redirect_required');
        expect(redirectUrl).toBe(`https://devs4you.${parseTenantFromRootDomain}/api/auth/login`);
        expect(callbackData).toBeFalsy();
      });
    });

    test('Cookie login state not matching query param state, without subdomains', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      const mockExpressReq = httpMocks.createRequest({
        query: { state: 'state', code: 'code', tenant_name: 'devs4you' },
        headers: {
          cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
        },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(redirectUrl).toBe(`https://${parseTenantFromRootDomain}/api/auth/login?tenant_name=devs4you`);
      expect(callbackData).toBeFalsy();
    });

    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('State mismatch with %s placeholder', (placeholderName, placeholder) => {
      test(`Cookie login state not matching query param state, with tenant subdomains using ${placeholderName}`, async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
        wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          parseTenantFromRootDomain,
          wristbandApplicationVanityDomain,
          autoConfigureEnabled: false,
          applicationAuthorizationRequestsEnabled: false,
        });

        const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
        const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

        const mockExpressReq = httpMocks.createRequest({
          query: { state: 'state', code: 'code' },
          headers: {
            cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
            host: `devs4you.${parseTenantFromRootDomain}`,
          },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
        const { callbackData, redirectUrl, type } = callbackResult;
        expect(type).toBe('redirect_required');
        expect(redirectUrl).toBe(`https://devs4you.${parseTenantFromRootDomain}/api/auth/login`);
        expect(callbackData).toBeFalsy();
      });
    });
  });
});
