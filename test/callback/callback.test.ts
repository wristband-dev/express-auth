import nock from 'nock';
import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { CallbackResult, LoginState } from '../../src/types';
import { encryptLoginState } from '../../src/utils';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

describe('Multi Tenant Callback', () => {
  let wristbandAuth: WristbandAuth;
  let parseTenantFromRootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    nock.cleanAll();

    parseTenantFromRootDomain = 'localhost:6001';
    loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
    redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
    wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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
      // Mock token data
      const mockTokens = {
        access_token: 'accessToken',
        expires_in: 1800,
        id_token: 'idToken',
        refresh_token: 'refreshToken',
        token_type: 'bearer',
      };
      const tokenScope = nock(`https://${wristbandApplicationVanityDomain}`)
        .persist()
        .post(
          '/api/v1/oauth2/token',
          `grant_type=authorization_code&code=code&redirect_uri=${redirectUri}&code_verifier=codeVerifier`
        )
        .reply(200, mockTokens);
      // Mock userinfo data
      const mockUserinfo = {
        sub: '5q6j4qe2cva3dm3cbdvjoxvuze',
        tnt_id: 'fr2vishnqjdvfbcijxa3a4adhe',
        app_id: 'dy42gabu5jebreq6jajskk2n34',
        idp_name: 'wristband',
        email: 'test@wristband.dev',
        email_verified: true,
      };
      const userinfoScope = nock(`https://${wristbandApplicationVanityDomain}`)
        .persist()
        .get('/api/v1/oauth2/userinfo')
        .reply(200, mockUserinfo);
      // Mock login state
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri: redirectUri,
        state: 'state',
        customState: { test: 'abc' },
        returnUrl: 'https://reddit.com',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        query: { state: 'state', code: 'code', tenant_name: 'devs4you' },
        headers: {
          cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
        },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;
      // Validate callback data contents
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
        expect(callbackData.returnUrl).toBe('https://reddit.com');
        expect(callbackData.tenantName).toBe('devs4you');
        expect(callbackData.userinfo).toBeTruthy();
        expect(callbackData.userinfo.userId).toBe('5q6j4qe2cva3dm3cbdvjoxvuze');
        expect(callbackData.userinfo.tenantId).toBe('fr2vishnqjdvfbcijxa3a4adhe');
        expect(callbackData.userinfo.applicationId).toBe('dy42gabu5jebreq6jajskk2n34');
        expect(callbackData.userinfo.identityProviderName).toBe('wristband');
        expect(callbackData.userinfo.email).toBe('test@wristband.dev');
        expect(callbackData.userinfo.emailVerified).toBe(true);
      }
      // Validate response is not redirecting the user
      // eslint-disable-next-line no-underscore-dangle
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeFalsy();
      // Validate no-cache headers
      // eslint-disable-next-line no-underscore-dangle
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(3);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate login state cookie is getting cleared
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

      tokenScope.done();
      userinfoScope.done();
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
        });
        // Mock token data
        const mockTokens = {
          access_token: 'accessToken',
          expires_in: 1800,
          id_token: 'idToken',
          refresh_token: 'refreshToken',
          token_type: 'bearer',
        };
        const tokenScope = nock(`https://${wristbandApplicationVanityDomain}`)
          .persist()
          .post(
            '/api/v1/oauth2/token',
            `grant_type=authorization_code&code=code&redirect_uri=${redirectUri}&code_verifier=codeVerifier`
          )
          .reply(200, mockTokens);
        // Mock userinfo data
        const mockUserinfo = {
          sub: '5q6j4qe2cva3dm3cbdvjoxvuze',
          tnt_id: 'fr2vishnqjdvfbcijxa3a4adhe',
          app_id: 'dy42gabu5jebreq6jajskk2n34',
          idp_name: 'wristband',
          email: 'test@wristband.dev',
          email_verified: true,
        };
        const userinfoScope = nock(`https://${wristbandApplicationVanityDomain}`)
          .persist()
          .get('/api/v1/oauth2/userinfo')
          .reply(200, mockUserinfo);
        // Mock login state
        const loginState: LoginState = {
          codeVerifier: 'codeVerifier',
          redirectUri: redirectUri,
          state: 'state',
        };
        const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
        // Mock Express objects
        const mockExpressReq = httpMocks.createRequest({
          query: { state: 'state', code: 'code' },
          headers: {
            cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
            host: `devs4you.${parseTenantFromRootDomain}`,
          },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;
        // Validate callback data contents
        const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
        const { callbackData, type } = callbackResult;
        expect(type).toBe('completed');
        expect(callbackData).toBeTruthy();
        if (callbackData) {
          expect(callbackData.tenantName).toBe('devs4you');
          expect(callbackData.customState).toBeFalsy();
          expect(callbackData.returnUrl).toBeFalsy();
        }
        // Validate response is not redirecting the user
        // eslint-disable-next-line no-underscore-dangle
        const location: string = mockExpressRes._getRedirectUrl();
        expect(location).toBeFalsy();
        tokenScope.done();
        userinfoScope.done();
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
        });
        // Mock token data
        const mockTokens = {
          access_token: 'accessToken',
          expires_in: 1800,
          id_token: 'idToken',
          refresh_token: 'refreshToken',
          token_type: 'bearer',
        };
        const tokenScope = nock(`https://${wristbandApplicationVanityDomain}`)
          .persist()
          .post(
            '/api/v1/oauth2/token',
            `grant_type=authorization_code&code=code&redirect_uri=${redirectUri}&code_verifier=codeVerifier`
          )
          .reply(200, mockTokens);
        // Mock userinfo data
        const mockUserinfo = {
          sub: '5q6j4qe2cva3dm3cbdvjoxvuze',
          tnt_id: 'fr2vishnqjdvfbcijxa3a4adhe',
          app_id: 'dy42gabu5jebreq6jajskk2n34',
          idp_name: 'wristband',
          email: 'test@wristband.dev',
          email_verified: true,
        };
        const userinfoScope = nock(`https://${wristbandApplicationVanityDomain}`)
          .persist()
          .get('/api/v1/oauth2/userinfo')
          .reply(200, mockUserinfo);
        // Mock login state
        const loginState: LoginState = {
          codeVerifier: 'codeVerifier',
          redirectUri: redirectUri,
          state: 'state',
        };
        const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
        // Mock Express objects
        const mockExpressReq = httpMocks.createRequest({
          query: { state: 'state', code: 'code' },
          headers: {
            cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
            host: `devs4you.${parseTenantFromRootDomain}`,
          },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;
        // Validate callback data contents
        const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
        const { callbackData, type } = callbackResult;
        expect(type).toBe('completed');
        expect(callbackData).toBeTruthy();
        if (callbackData) {
          expect(callbackData.tenantName).toBe('devs4you');
          expect(callbackData.customState).toBeFalsy();
          expect(callbackData.returnUrl).toBeFalsy();
        }
        // Validate response is not redirecting the user
        // eslint-disable-next-line no-underscore-dangle
        const location: string = mockExpressRes._getRedirectUrl();
        expect(location).toBeFalsy();
        tokenScope.done();
        userinfoScope.done();
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
      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${parseTenantFromRootDomain}` },
        query: { state: 'state', code: 'code', tenant_name: 'devs4you' },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;
      // login state cookie is missing, which should redirect to app-level login.
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
        });
        // Mock Express objects
        const mockExpressReq = httpMocks.createRequest({
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
          query: { state: 'state', code: 'code' },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;
        // login state cookie is missing, which should redirect to app-level login.
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
      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
      // Mock Express objects
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
        });
        // Mock login state
        const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
        const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
        // Mock Express objects
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
      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
      // Mock Express objects
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
        });
        // Mock login state
        const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
        const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
        // Mock Express objects
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
