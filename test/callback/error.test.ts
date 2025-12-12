import nock from 'nock';
import httpMocks from 'node-mocks-http';

import { LoginState } from '../../src/types';
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
      wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      autoConfigureEnabled: false,
    });
    nock.cleanAll();
  });

  test('Invalid state query param', async () => {
    // Mock Express objects
    let mockExpressReq = httpMocks.createRequest({
      query: { code: 'code', tenant_name: 'devs4you' },
    }) as any;
    let mockExpressRes = httpMocks.createResponse() as any;

    // Missing state query parameter should throw an error
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [state] passed from Wristband during callback');
    }

    mockExpressReq = httpMocks.createRequest({
      query: { code: 'code', state: ['1', '2'] },
    }) as unknown as Request;
    mockExpressRes = httpMocks.createResponse();

    // Multiple state query parameters should throw an error
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      fail('Error expected to be thrown.');
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
      query: { state: 'state', tenant_name: 'devs4you' },
      headers: {
        cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
      },
    }) as any;
    let mockExpressRes = httpMocks.createResponse() as any;

    // Missing code query parameter should throw an error for happy path scenarios.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [code] passed from Wristband during callback');
    }

    mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', code: ['a', 'b'] },
      headers: {
        cookie: `login#state#1234567890=blah`,
      },
    }) as unknown as Request;
    mockExpressRes = httpMocks.createResponse() as unknown as Response;
    // Multiple code query parameters should throw an error.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [code] passed from Wristband during callback');
    }
  });

  test('Invalid error query param', async () => {
    // Mock Express objects
    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', error: ['a', 'b'] },
      headers: {
        cookie: `login#state#1234567890=blah`,
      },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    // Multiple error query parameters should throw an error.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [error] passed from Wristband during callback');
    }
  });

  test('Invalid error_description query param', async () => {
    // Mock Express objects
    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', error_description: ['a', 'b'] },
      headers: {
        cookie: `login#state#1234567890=blah`,
      },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    // Multiple error_description query parameters should throw an error.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [error_description] passed from Wristband during callback');
    }
  });

  test('Invalid tenant_name query param', async () => {
    // Mock Express objects
    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', tenant_name: ['a', 'b'] },
      headers: {
        cookie: `login#state#1234567890=blah`,
      },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    // Multiple tenant_name query parameters should throw an error.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [tenant_name] query parameter was encountered');
    }
  });

  test('Invalid tenant_custom_domain query param', async () => {
    // Mock Express objects
    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', tenant_custom_domain: ['a', 'b'] },
      headers: {
        cookie: `login#state#1234567890=blah`,
      },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    // Multiple error query parameters should throw an error.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      fail('Error expected to be thrown.');
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
      query: { state: 'state', tenant_name: 'devs4you', error: 'BAD', error_description: 'Really bad' },
      headers: {
        cookie: `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`,
      },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    // Only some errors are handled automatically by the SDK. All others will throw a WristbandError.
    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      fail('Error expected to be thrown.');
    } catch (err: any) {
      expect(err instanceof WristbandError).toBe(true);
      const error = err as WristbandError;
      expect(error.code).toBe('BAD');
      expect(error.errorDescription).toBe('Really bad');
    }
  });

  test('Missing login state cookie returns redirect_required with missing_login_state reason', async () => {
    const mockExpressReq = httpMocks.createRequest({
      query: {
        state: 'teststate',
        code: 'testcode',
        tenant_name: 'tenant1',
      },
      // No cookie header
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const result = await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    expect(result.type).toBe('redirect_required');
    expect(result.reason).toBe('missing_login_state');
    expect(result.redirectUrl).toBe(`${LOGIN_URL}?tenant_name=tenant1`);
    expect(result.callbackData).toBeUndefined();
  });

  test('State mismatch returns redirect_required with invalid_login_state reason', async () => {
    const loginState: LoginState = {
      codeVerifier: 'verifier123',
      redirectUri: REDIRECT_URI,
      state: 'correctstate',
    };
    const encryptedLoginState = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
    const cookieKey = `login${LOGIN_STATE_COOKIE_SEPARATOR}wrongstate${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now()}`;

    const mockExpressReq = httpMocks.createRequest({
      query: {
        state: 'wrongstate',
        code: 'testcode',
        tenant_name: 'tenant1',
      },
      headers: {
        cookie: `${cookieKey}=${encodeURIComponent(encryptedLoginState)}`,
      },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const result = await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    expect(result.type).toBe('redirect_required');
    expect(result.reason).toBe('invalid_login_state');
    expect(result.redirectUrl).toBe(`${LOGIN_URL}?tenant_name=tenant1`);
    expect(result.callbackData).toBeUndefined();
  });

  test('login_required error returns redirect_required with login_required reason', async () => {
    const loginState: LoginState = {
      codeVerifier: 'verifier123',
      redirectUri: REDIRECT_URI,
      state: 'teststate',
    };
    const encryptedLoginState = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
    const cookieKey = `login${LOGIN_STATE_COOKIE_SEPARATOR}teststate${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now()}`;

    const mockExpressReq = httpMocks.createRequest({
      query: {
        state: 'teststate',
        error: 'login_required',
        error_description: 'User must re-authenticate',
        tenant_name: 'tenant1',
      },
      headers: {
        cookie: `${cookieKey}=${encodeURIComponent(encryptedLoginState)}`,
      },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const result = await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    expect(result.type).toBe('redirect_required');
    expect(result.reason).toBe('login_required');
    expect(result.redirectUrl).toBe(`${LOGIN_URL}?tenant_name=tenant1`);
    expect(result.callbackData).toBeUndefined();
  });

  test('Callback when token exchange fails returns redirect_required with invalid_grant reason', async () => {
    const loginState: LoginState = {
      codeVerifier: 'verifier123',
      redirectUri: REDIRECT_URI,
      state: 'teststate',
    };
    const encryptedLoginState = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
    const cookieKey = `login${LOGIN_STATE_COOKIE_SEPARATOR}teststate${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now()}`;

    const mockExpressReq = httpMocks.createRequest({
      query: {
        state: 'teststate',
        code: 'testcode',
        tenant_name: 'tenant1',
      },
      headers: {
        cookie: `${cookieKey}=${encodeURIComponent(encryptedLoginState)}`,
      },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`).post('/api/v1/oauth2/token').reply(400, {
      error: 'invalid_grant',
      error_description: 'Token exchange failed',
    });

    const result = await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    expect(result.type).toBe('redirect_required');
    expect(result.reason).toBe('invalid_grant');
    expect(result.redirectUrl).toBe(`${LOGIN_URL}?tenant_name=tenant1`);
    expect(result.callbackData).toBeUndefined();
  });

  test('Non-InvalidGrantError during token exchange is re-thrown', async () => {
    const loginState: LoginState = {
      codeVerifier: 'verifier123',
      redirectUri: REDIRECT_URI,
      state: 'teststate',
    };
    const encryptedLoginState = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
    const cookieKey = `login${LOGIN_STATE_COOKIE_SEPARATOR}teststate${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now()}`;

    const mockExpressReq = httpMocks.createRequest({
      query: {
        state: 'teststate',
        code: 'testcode',
        tenant_name: 'tenant1',
      },
      headers: {
        cookie: `${cookieKey}=${encodeURIComponent(encryptedLoginState)}`,
      },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`).post('/api/v1/oauth2/token').reply(500, {
      error: 'server_error',
      error_description: 'Internal server error',
    });

    try {
      await wristbandAuth.callback(mockExpressReq, mockExpressRes);
      fail('Expected error to be thrown');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      const typedError = error as WristbandError;
      expect(typedError.code).toBe('unexpected_error');
      expect(typedError.errorDescription).toBe('Unexpected error');
      expect(typedError.originalError).toBeDefined();
    }
  });

  test('Callback with tenant subdomains constructs correct redirect URL with invalid_grant reason', async () => {
    const parseTenantFromRootDomain = 'example.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/callback`;

    const tenantSubdomainAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      parseTenantFromRootDomain,
      wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      autoConfigureEnabled: false,
    });

    const loginState: LoginState = {
      codeVerifier: 'verifier123',
      redirectUri,
      state: 'teststate',
    };
    const encryptedLoginState = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
    const cookieKey = `login${LOGIN_STATE_COOKIE_SEPARATOR}teststate${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now()}`;

    const mockExpressReq = httpMocks.createRequest({
      query: {
        state: 'teststate',
        code: 'testcode',
      },
      headers: {
        host: `tenant1.${parseTenantFromRootDomain}`,
        cookie: `${cookieKey}=${encodeURIComponent(encryptedLoginState)}`,
      },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`).post('/api/v1/oauth2/token').reply(400, {
      error: 'invalid_grant',
      error_description: 'Token exchange failed',
    });

    const result = await tenantSubdomainAuth.callback(mockExpressReq, mockExpressRes);

    expect(result.type).toBe('redirect_required');
    expect(result.reason).toBe('invalid_grant');
    expect(result.redirectUrl).toBe(`https://tenant1.${parseTenantFromRootDomain}/login`);
    expect(result.callbackData).toBeUndefined();
  });

  test('redirect_required type never has callbackData', async () => {
    const mockExpressReq = httpMocks.createRequest({
      query: {
        state: 'teststate',
        code: 'testcode',
        tenant_name: 'tenant1',
      },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const result = await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    if (result.type === 'redirect_required') {
      expect(result.callbackData).toBeUndefined();
      expect(result.reason).toBeDefined();
      expect(result.redirectUrl).toBeDefined();
    }
  });

  describe.each([
    ['tenant_domain', '{tenant_domain}'],
    ['tenant_name', '{tenant_name}'],
  ])('Redirect to Application-level Login with %s placeholder', (placeholderName, placeholder) => {
    test('Missing login state cookie, without subdomains, without tenant name query param', async () => {
      const parseTenantFromRootDomain = 'business.invotastic.com';
      const loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      const redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      const wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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
        query: { state: 'state', code: 'code' },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      try {
        await wristbandAuth.callback(mockExpressReq, mockExpressRes);
        fail('Error expected to be thrown.');
      } catch (err: any) {
        expect(err instanceof WristbandError).toBe(true);
        const error = err as WristbandError;
        expect(error.code).toBe('missing_tenant_name');
        expect(error.errorDescription).toBe(
          'Callback request is missing the [tenant_name] query parameter from Wristband'
        );
      }
    });

    test(`Missing login state cookie, with subdomains using ${placeholderName}, and without URL subdomain`, async () => {
      const parseTenantFromRootDomain = 'business.invotastic.com';
      const loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
      const redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
      const wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        customApplicationLoginPageUrl: 'https://google.com',
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        query: { state: 'state', code: 'code' },
        headers: { host: parseTenantFromRootDomain },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      try {
        await wristbandAuth.callback(mockExpressReq, mockExpressRes);
        fail('Error expected to be thrown.');
      } catch (err: any) {
        expect(err instanceof WristbandError).toBe(true);
        const error = err as WristbandError;
        expect(error.code).toBe('missing_tenant_subdomain');
        expect(error.errorDescription).toBe('Callback request URL is missing a tenant subdomain');
      }
    });
  });
});
