/* eslint-disable no-underscore-dangle */
/* eslint-disable import/no-extraneous-dependencies */

import nock from 'nock';
import httpMocks from 'node-mocks-http';

import { CallbackResultType, LoginState } from '../../src/types';
import { encryptLoginState } from '../../src/utils';
import { createWristbandAuth, WristbandAuth, WristbandError } from '../../src/index';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const LOGIN_URL = 'http://localhost:6001/api/auth/login';
const REDIRECT_URI = 'http://localhost:6001/api/auth/callback';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2c-invotastic.dev.wristband.dev';

describe('Callback Errors', () => {
  let wristbandAuth: WristbandAuth;

  beforeEach(() => {
    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl: LOGIN_URL,
      redirectUri: REDIRECT_URI,
      wristbandApplicationDomain: WRISTBAND_APPLICATION_DOMAIN,
    });
    nock.cleanAll();
  });

  test('Invalid state query param', async () => {
    // Mock Express objects
    let mockExpressReq = httpMocks.createRequest({
      query: { code: 'code', tenant_domain: 'devs4you' },
    });
    let mockExpressRes = httpMocks.createResponse();

    // Missing state query parameter should throw an error
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [state] passed from Wristband during callback');
    }

    mockExpressReq = httpMocks.createRequest({
      query: { code: 'code', state: ['1', '2'] },
    });
    mockExpressRes = httpMocks.createResponse();

    // Multiple state query parameters should throw an error
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [state] passed from Wristband during callback');
    }
  });

  test('Invalid code query param', async () => {
    // Mock login state
    const loginState: LoginState = {
      codeVerifier: 'codeVerifier',
      redirectUri: REDIRECT_URI,
      state: 'state',
    };
    const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

    // Mock Express objects
    let mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', tenant_domain: 'devs4you' },
      cookies: { 'login#state#1234567890': encryptedLoginState },
    });
    let mockExpressRes = httpMocks.createResponse();

    // Missing code query parameter should throw an error for happy path scenarios.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [code] passed from Wristband during callback');
    }

    mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', code: ['a', 'b'] },
      cookies: { 'login#state#1234567890': 'blah' },
    });
    mockExpressRes = httpMocks.createResponse();
    // Multiple code query parameters should throw an error.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [code] passed from Wristband during callback');
    }
  });

  test('Invalid error query param', async () => {
    // Mock Express objects
    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', error: ['a', 'b'] },
      cookies: { 'login#state#1234567890': 'blah' },
    });
    const mockExpressRes = httpMocks.createResponse();

    // Multiple error query parameters should throw an error.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [error] passed from Wristband during callback');
    }
  });

  test('Invalid error_description query param', async () => {
    // Mock Express objects
    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', error_description: ['a', 'b'] },
      cookies: { 'login#state#1234567890': 'blah' },
    });
    const mockExpressRes = httpMocks.createResponse();

    // Multiple error_description query parameters should throw an error.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [error_description] passed from Wristband during callback');
    }
  });

  test('Invalid tenant_domain query param', async () => {
    // Mock Express objects
    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', tenant_domain: ['a', 'b'] },
      cookies: { 'login#state#1234567890': 'blah' },
    });
    const mockExpressRes = httpMocks.createResponse();

    // Multiple tenant_domain query parameters should throw an error.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [tenant_domain] query parameter was encountered');
    }
  });

  test('Invalid tenant_custom_domain query param', async () => {
    // Mock Express objects
    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', tenant_custom_domain: ['a', 'b'] },
      cookies: { 'login#state#1234567890': 'blah' },
    });
    const mockExpressRes = httpMocks.createResponse();

    // Multiple error query parameters should throw an error.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe(
        'Invalid query parameter [tenant_custom_domain] passed from Wristband during callback'
      );
    }
  });

  test('Error query parameter throws WristbandError', async () => {
    // Mock login state
    const loginState: LoginState = {
      codeVerifier: 'codeVerifier',
      redirectUri: REDIRECT_URI,
      state: 'state',
    };
    const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

    // Mock Express objects
    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', tenant_domain: 'devs4you', error: 'BAD', error_description: 'Really bad' },
      cookies: { 'login#state#1234567890': encryptedLoginState },
    });
    const mockExpressRes = httpMocks.createResponse();

    // Only some errors are handled automatically by the SDK. All others will throw a WristbandError.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof WristbandError).toBe(true);
      expect(error.getError()).toBe('BAD');
      expect(error.getErrorDescription()).toBe('Really bad');
    }
  });

  describe('Redirect to Application-level Login', () => {
    test('Missing login state cookie, without subdomains, without tenant domain query param', async () => {
      const rootDomain = 'business.invotastic.com';
      const loginUrl = `https://${rootDomain}/api/auth/login`;
      const redirectUri = `https://${rootDomain}/api/auth/callback`;
      const wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });
      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        query: { state: 'state', code: 'code' },
      });
      const mockExpressRes = httpMocks.createResponse();

      try {
        await wristbandAuth.callback(mockExpressReq, mockExpressRes);
        expect('').fail('Error expected to be thrown.');
      } catch (error: any) {
        expect(error instanceof WristbandError).toBe(true);
        expect(error.getError()).toBe('missing_tenant_domain');
        expect(error.getErrorDescription()).toBe(
          'Callback request is missing the [tenant_domain] query parameter from Wristband'
        );
      }
    });

    test('Missing login state cookie, with subdomains, and without URL subdomain', async () => {
      const rootDomain = 'business.invotastic.com';
      const loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      const redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
      const wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        customApplicationLoginPageUrl: 'https://google.com',
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });
      // Mock Express objects
      const mockExpressReq = httpMocks.createRequest({
        query: { state: 'state', code: 'code' },
        headers: { host: rootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      try {
        await wristbandAuth.callback(mockExpressReq, mockExpressRes);
        expect('').fail('Error expected to be thrown.');
      } catch (error: any) {
        expect(error instanceof WristbandError).toBe(true);
        expect(error.getError()).toBe('missing_tenant_subdomain');
        expect(error.getErrorDescription()).toBe('Callback request URL is missing a tenant subdomain');
      }
    });
  });

  // Added tests from callback.test.ts
  test('Callback with valid input returns completed result', async () => {
    // Arrange
    // Create a valid login state cookie with matching state
    const loginState: LoginState = {
      codeVerifier: 'codeVerifier',
      redirectUri: REDIRECT_URI,
      state: 'teststate',
    };
    const encryptedLoginState = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
    const cookieKey = `login${LOGIN_STATE_COOKIE_SEPARATOR}teststate${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now()}`;

    const mockExpressReq = httpMocks.createRequest({
      query: {
        state: 'teststate',
        code: 'testcode',
        tenant_domain: 'tenant1',
      },
      cookies: {
        [cookieKey]: encryptedLoginState,
      },
    });
    const mockExpressRes = httpMocks.createResponse();

    // Mock the token response
    const mockTokens = {
      access_token: 'test_access_token',
      expires_in: 3600,
      id_token: 'test_id_token',
      refresh_token: 'test_refresh_token',
      token_type: 'bearer',
    };

    // Mock the userinfo response
    const mockUserinfo = {
      sub: 'user123',
      email: 'test@example.com',
      email_verified: true,
    };

    // Setup nock to intercept the token and userinfo requests
    nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`).post('/api/v1/oauth2/token').reply(200, mockTokens);

    nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, mockUserinfo);

    // Act
    const result = await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    // Assert
    expect(result.result).toBe(CallbackResultType.COMPLETED);
    expect(result.callbackData).toBeDefined();
    expect(result.callbackData?.tenantDomainName).toBe('tenant1');
    expect(result.callbackData?.userinfo).toBeDefined();
  });

  test('Callback with custom domain includes in result', async () => {
    // Arrange
    const customDomain = 'custom.tenant1.com';

    // Create a valid login state cookie with matching state
    const loginState: LoginState = {
      codeVerifier: 'codeVerifier',
      redirectUri: REDIRECT_URI,
      state: 'teststate',
    };
    const encryptedLoginState = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
    const cookieKey = `login${LOGIN_STATE_COOKIE_SEPARATOR}teststate${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now()}`;

    const mockExpressReq = httpMocks.createRequest({
      query: {
        state: 'teststate',
        code: 'testcode',
        tenant_domain: 'tenant1',
        tenant_custom_domain: customDomain,
      },
      cookies: {
        [cookieKey]: encryptedLoginState,
      },
    });
    const mockExpressRes = httpMocks.createResponse();

    // Mock the token response
    const mockTokens = {
      access_token: 'test_access_token',
      expires_in: 3600,
      id_token: 'test_id_token',
      refresh_token: 'test_refresh_token',
      token_type: 'bearer',
    };

    // Mock the userinfo response
    const mockUserinfo = {
      sub: 'user123',
      email: 'test@example.com',
      email_verified: true,
    };

    // Setup nock to intercept the token and userinfo requests
    nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`).post('/api/v1/oauth2/token').reply(200, mockTokens);

    nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, mockUserinfo);

    // Act
    const result = await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    // Assert
    expect(result.result).toBe(CallbackResultType.COMPLETED);
    expect(result.callbackData).toBeDefined();
    expect(result.callbackData?.tenantCustomDomain).toBe(customDomain);
  });

  test('Callback when token exchange fails returns redirect required', async () => {
    // Arrange
    // Create a valid login state cookie with matching state
    const loginState: LoginState = {
      codeVerifier: 'codeVerifier',
      redirectUri: REDIRECT_URI,
      state: 'teststate',
    };
    const encryptedLoginState = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
    const cookieKey = `login${LOGIN_STATE_COOKIE_SEPARATOR}teststate${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now()}`;

    const mockExpressReq = httpMocks.createRequest({
      query: {
        state: 'teststate',
        code: 'testcode',
        tenant_domain: 'tenant1',
      },
      cookies: {
        [cookieKey]: encryptedLoginState,
      },
    });
    const mockExpressRes = httpMocks.createResponse();

    // Mock the token exchange to fail
    const errorResponse = {
      error: 'invalid_grant',
      error_description: 'Token exchange failed',
    };

    nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`).post('/api/v1/oauth2/token').reply(400, errorResponse);

    // Act
    const result = await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    // Assert
    expect(result.result).toBe(CallbackResultType.REDIRECT_REQUIRED);
    expect(result.callbackData).toBeUndefined();
    // Check if the response has a redirect URL
    const location = mockExpressRes._getRedirectUrl();
    expect(location).toBe(`${LOGIN_URL}?tenant_domain=tenant1`);
  });

  test('Callback with tenant subdomains constructs correct redirect url', async () => {
    // Arrange
    const wristbandAuthWithSubdomains = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl: 'https://{tenant_domain}.example.com/login',
      redirectUri: 'https://{tenant_domain}.example.com/callback',
      wristbandApplicationDomain: WRISTBAND_APPLICATION_DOMAIN,
      useTenantSubdomains: true,
      rootDomain: 'example.com',
    });

    // Create a valid login state cookie with matching state
    const loginState: LoginState = {
      codeVerifier: 'codeVerifier',
      redirectUri: 'https://tenant1.example.com/callback',
      state: 'teststate',
    };
    const encryptedLoginState = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
    const cookieKey = `login${LOGIN_STATE_COOKIE_SEPARATOR}teststate${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now()}`;

    const mockExpressReq = httpMocks.createRequest({
      query: {
        state: 'teststate',
        code: 'testcode',
      },
      cookies: {
        [cookieKey]: encryptedLoginState,
      },
      headers: {
        host: 'tenant1.example.com',
      },
    });
    const mockExpressRes = httpMocks.createResponse();

    // Mock the token exchange to fail
    const errorResponse = {
      error: 'invalid_grant',
      error_description: 'Token exchange failed',
    };

    nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`).post('/api/v1/oauth2/token').reply(400, errorResponse);

    // Act
    const result = await wristbandAuthWithSubdomains.callback(mockExpressReq, mockExpressRes);

    // Assert
    expect(result.result).toBe(CallbackResultType.REDIRECT_REQUIRED);
    // Check if the response has a redirect URL
    const location = mockExpressRes._getRedirectUrl();
    expect(location).toBe('https://tenant1.example.com/login');
  });
});
