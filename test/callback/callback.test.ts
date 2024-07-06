/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-underscore-dangle */

import nock from 'nock';
import httpMocks from 'node-mocks-http';

import { createWristbandAuth, CallbackData, WristbandAuth } from '../../src/index';
import { LoginState } from '../../src/types';
import { encryptLoginState } from '../../src/utils';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

describe('Multi Tenant Callback', () => {
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
    nock.cleanAll();
  });

  describe('Callback Happy Path', () => {
    test('Default Configuration', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: loginUrl,
        redirectUri: redirectUri,
        wristbandApplicationDomain,
      });

      // Mock token data
      const mockTokens = {
        access_token: 'accessToken',
        expires_in: 1800,
        id_token: 'idToken',
        refresh_token: 'refreshToken',
        token_type: 'bearer',
      };
      const tokenScope = nock(`https://${wristbandApplicationDomain}`)
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
      const userinfoScope = nock(`https://${wristbandApplicationDomain}`)
        .persist()
        .get('/api/v1/oauth2/userinfo')
        .reply(200, mockUserinfo);

      // Mock login state
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri: redirectUri,
        state: 'state',
        tenantDomainName: 'devs4you',
        customState: { test: 'abc' },
        returnUrl: 'https://reddit.com',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        query: { state: 'state', code: 'code' },
        cookies: { 'login:state:1234567890': encryptedLoginState },
      });
      const mockExpressRes = httpMocks.createResponse();

      // Validate callback data contents
      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect(callbackData).toBeTruthy();
      if (callbackData) {
        expect(callbackData.accessToken).toBe('accessToken');
        expect(callbackData.expiresIn).toBe(1800);
        expect(callbackData.idToken).toBe('idToken');
        expect(callbackData.refreshToken).toBe('refreshToken');
        expect(callbackData.customState).toEqual({ test: 'abc' });
        expect(callbackData.returnUrl).toBe('https://reddit.com');
        expect(callbackData.tenantDomainName).toBe('devs4you');

        expect(callbackData.userinfo).toBeTruthy();
        expect(callbackData.userinfo['sub']).toBe('5q6j4qe2cva3dm3cbdvjoxvuze');
        expect(callbackData.userinfo['tnt_id']).toBe('fr2vishnqjdvfbcijxa3a4adhe');
        expect(callbackData.userinfo['app_id']).toBe('dy42gabu5jebreq6jajskk2n34');
        expect(callbackData.userinfo['idp_name']).toBe('wristband');
        expect(callbackData.userinfo['email']).toBe('test@wristband.dev');
        expect(callbackData.userinfo['email_verified']).toBe(true);
      }

      // Validate response is not redirecting the user
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeFalsy();

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(2);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate login state cookie is getting cleared
      const { cookies } = mockExpressRes;
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      expect(keyParts).toHaveLength(3);
      expect(keyParts[0]).toEqual('login');
      expect(keyParts[1]).toBe('state');
      expect(keyParts[1]).toEqual(mockExpressReq.query.state);
      expect(parseInt(keyParts[2], 10)).toBe(1234567890);
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const { options, value } = cookieValue;
      expect(options.expires?.valueOf()).toBeLessThan(Date.now().valueOf());
      expect(options.path).toBe('/');
      expect(value).toBeFalsy();

      tokenScope.done();
      userinfoScope.done();
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

      // Mock token data
      const mockTokens = {
        access_token: 'accessToken',
        expires_in: 1800,
        id_token: 'idToken',
        refresh_token: 'refreshToken',
        token_type: 'bearer',
      };
      const tokenScope = nock(`https://${wristbandApplicationDomain}`)
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
      const userinfoScope = nock(`https://${wristbandApplicationDomain}`)
        .persist()
        .get('/api/v1/oauth2/userinfo')
        .reply(200, mockUserinfo);

      // Mock login state
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri: redirectUri,
        state: 'state',
        tenantDomainName: 'devs4you',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
        query: { state: 'state', code: 'code' },
        cookies: { 'login:state:1234567890': encryptedLoginState },
      });
      const mockExpressRes = httpMocks.createResponse();

      // Validate callback data contents
      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect(callbackData).toBeTruthy();
      if (callbackData) {
        expect(callbackData.tenantDomainName).toBe('devs4you');
        expect(callbackData.customState).toBeFalsy();
        expect(callbackData.returnUrl).toBeFalsy();
      }

      // Validate response is not redirecting the user
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeFalsy();

      tokenScope.done();
      userinfoScope.done();
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

      // Mock token data
      const mockTokens = {
        access_token: 'accessToken',
        expires_in: 1800,
        id_token: 'idToken',
        refresh_token: 'refreshToken',
        token_type: 'bearer',
      };
      const tokenScope = nock(`https://${wristbandApplicationDomain}`)
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
      const userinfoScope = nock(`https://${wristbandApplicationDomain}`)
        .persist()
        .get('/api/v1/oauth2/userinfo')
        .reply(200, mockUserinfo);

      // Mock login state
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri: redirectUri,
        state: 'state',
        tenantDomainName: 'devs4you',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
        query: { state: 'state', code: 'code' },
        cookies: { 'login:state:1234567890': encryptedLoginState },
      });
      const mockExpressRes = httpMocks.createResponse();

      // Validate callback data contents
      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect(callbackData).toBeTruthy();
      if (callbackData) {
        expect(callbackData.tenantDomainName).toBe('devs4you');
        expect(callbackData.customState).toBeFalsy();
        expect(callbackData.returnUrl).toBeFalsy();
      }

      // Validate response is not redirecting the user
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeFalsy();

      tokenScope.done();
      userinfoScope.done();
    });
  });

  describe('Redirect to Application-level Login', () => {
    test('Missing login state cookie without subdomains, and no default tenant domain', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationDomain,
      });

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        query: { state: 'state', code: 'code' },
      });
      const mockExpressRes = httpMocks.createResponse();

      // login state cookie is missing, which should redirect to app-level login.
      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/login');
    });

    test('Missing login state cookie without subdomains and custom application login URL', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        customApplicationLoginPageUrl: 'https://google.com',
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationDomain,
      });

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        query: { state: 'state', code: 'code' },
      });
      const mockExpressRes = httpMocks.createResponse();

      // login state cookie is missing, which should redirect to app-level login.
      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://google.com`);
      expect(pathname).toEqual('/');
    });

    test('State is missing tenantDomainName', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        wristbandApplicationDomain,
      });

      // Mock login state
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri: redirectUri,
        state: 'state',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: rootDomain },
        query: { state: 'state', code: 'code' },
        cookies: { 'login:state:1234567890': encryptedLoginState },
      });
      const mockExpressRes = httpMocks.createResponse();

      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/login');
    });
  });

  describe('Redirect to Tenant-level Login', () => {
    test('Missing login state cookie with tenant subdomains', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';

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

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
        query: { state: 'state', code: 'code' },
      });
      const mockExpressRes = httpMocks.createResponse();

      // login state cookie is missing, which should redirect to app-level login.
      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${rootDomain}`);
      expect(pathname).toEqual('/api/auth/login');
    });

    test('Default Configuration for login_required error', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      // Mock login state
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri: redirectUri,
        state: 'state',
        tenantDomainName: 'devs4you',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        query: { state: 'state', code: 'code', error: 'login_required', error_description: 'Login required' },
        cookies: { 'login:state:1234567890': encryptedLoginState },
      });
      const mockExpressRes = httpMocks.createResponse();

      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://${rootDomain}`);
      expect(pathname).toEqual('/api/auth/login');
      expect(searchParams.get('tenant_domain')).toBe('devs4you');
    });

    test('Tenant Subdomain Configuration for login_required error', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';

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

      // Mock login state
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri: redirectUri,
        state: 'state',
        tenantDomainName: 'devs4you',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
        query: { state: 'state', code: 'code', error: 'login_required', error_description: 'Login required' },
        cookies: { 'login:state:1234567890': encryptedLoginState },
      });
      const mockExpressRes = httpMocks.createResponse();

      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${rootDomain}`);
      expect(pathname).toEqual('/api/auth/login');
    });

    test('Tenant Subdomain Configuration with mismatched tenantDomain state', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';

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

      // Mock login state
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri,
        state: 'state',
        tenantDomainName: 'collabcrm',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
        query: { state: 'state', code: 'code' },
        cookies: { 'login:state:1234567890': encryptedLoginState },
      });
      const mockExpressRes = httpMocks.createResponse();

      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${rootDomain}`);
      expect(pathname).toEqual('/api/auth/login');
    });

    test('Cookie login state not matching query param state without subdomains', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationDomain,
      });

      // Mock login state
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri: redirectUri,
        state: 'bad_state',
        tenantDomainName: 'devs4you',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        query: { state: 'state', code: 'code' },
        cookies: { 'login:state:1234567890': encryptedLoginState },
      });
      const mockExpressRes = httpMocks.createResponse();

      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://${rootDomain}`);
      expect(pathname).toEqual('/api/auth/login');
      expect(searchParams.get('tenant_domain')).toBe('devs4you');
    });

    test('Cookie login state not matching query param state with tenant subdomains', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';

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

      // Mock login state
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri: redirectUri,
        state: 'bad_state',
        tenantDomainName: 'devs4you',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
        query: { state: 'state', code: 'code' },
        cookies: { 'login:state:1234567890': encryptedLoginState },
      });
      const mockExpressRes = httpMocks.createResponse();

      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${rootDomain}`);
      expect(pathname).toEqual('/api/auth/login');
    });
  });
});
