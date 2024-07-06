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

describe('Custom Callback Configurations', () => {
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

  describe('Redirect to Tenant-level Login', () => {
    test('Missing login state cookie without subdomains, with a default tenant domain', async () => {
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
      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes, {
        defaultTenantDomain: 'global',
      });
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://${wristbandApplicationDomain}?tenant_domain=global`);
      expect(pathname).toEqual('/api/auth/login');
    });

    test('State is missing tenantDomainName, with a default tenant domain', async () => {
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

      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes, {
        defaultTenantDomain: 'global',
      });
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://${wristbandApplicationDomain}?tenant_domain=global`);
      expect(pathname).toEqual('/api/auth/login');
    });

    test('login_required error without subdomains, with a default tenant domain', async () => {
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

      const callbackData: CallbackData | void = await wristbandAuth.callback(mockExpressReq, mockExpressRes, {
        defaultTenantDomain: 'global',
      });
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://${rootDomain}?tenant_domain=global`);
      expect(pathname).toEqual('/api/auth/login');
      expect(searchParams.get('tenant_domain')).toBe('devs4you');
    });
  });
});
