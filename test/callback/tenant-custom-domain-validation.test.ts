import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { CallbackResult, LoginState } from '../../src/types';
import { encryptLoginState } from '../../src/utils';
import { FetchError } from '../../src/error';
import { expectValidateCalled, expectValidateNotCalled, mockWristbandFetch } from '../helpers/mock-fetch';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const TENANT_CUSTOM_DOMAIN = 'callback.tenant.com';

const MOCK_TOKENS = {
  access_token: 'accessToken',
  expires_in: 1800,
  id_token: 'idToken',
  refresh_token: 'refreshToken',
  token_type: 'bearer',
};
const MOCK_USERINFO = {
  sub: '5q6j4qe2cva3dm3cbdvjoxvuze',
  tnt_id: 'fr2vishnqjdvfbcijxa3a4adhe',
  app_id: 'dy42gabu5jebreq6jajskk2n34',
  idp_name: 'wristband',
  email: 'test@wristband.dev',
  email_verified: true,
};

describe('Callback - Tenant Custom Domain Validation', () => {
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

    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      wristbandApplicationVanityDomain,
      autoConfigureEnabled: false,
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  async function createLoginStateCookieHeader(): Promise<string> {
    const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state' };
    const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
    return `login#state#1234567890=${encodeURIComponent(encryptedLoginState)}`;
  }

  test('Validates the tenant_custom_domain query param and completes the callback when it is valid', async () => {
    mockWristbandFetch({ tenantCustomDomainValid: true, tokens: MOCK_TOKENS, userinfo: MOCK_USERINFO });

    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', code: 'code', tenant_name: 'devs4you', tenant_custom_domain: TENANT_CUSTOM_DOMAIN },
      headers: { cookie: await createLoginStateCookieHeader() },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
    expect(callbackResult.type).toBe('completed');
    expect(callbackResult.callbackData?.tenantCustomDomain).toBe(TENANT_CUSTOM_DOMAIN);
  });

  test('Skips an invalid tenant_custom_domain query param and still completes the callback', async () => {
    mockWristbandFetch({ tenantCustomDomainValid: false, tokens: MOCK_TOKENS, userinfo: MOCK_USERINFO });

    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', code: 'code', tenant_name: 'devs4you', tenant_custom_domain: TENANT_CUSTOM_DOMAIN },
      headers: { cookie: await createLoginStateCookieHeader() },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
    expect(callbackResult.type).toBe('completed');
    expect(callbackResult.callbackData?.tenantCustomDomain).toBeUndefined();
  });

  test('Validates before exchanging the authorization code for tokens', async () => {
    const fetchMock = mockWristbandFetch({
      tenantCustomDomainValid: true,
      tokens: MOCK_TOKENS,
      userinfo: MOCK_USERINFO,
    });

    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', code: 'code', tenant_name: 'devs4you', tenant_custom_domain: TENANT_CUSTOM_DOMAIN },
      headers: { cookie: await createLoginStateCookieHeader() },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    expect(fetchMock.mock.calls[0][0]).toContain('/custom-domains/validate');
    expect(fetchMock.mock.calls[1][0]).toContain('/oauth2/token');
  });

  test('Omits an invalid tenant custom domain from the login redirect URL', async () => {
    mockWristbandFetch({ tenantCustomDomainValid: false, tokens: MOCK_TOKENS, userinfo: MOCK_USERINFO });

    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', code: 'code', tenant_name: 'devs4you', tenant_custom_domain: TENANT_CUSTOM_DOMAIN },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    expect(callbackResult.type).toBe('redirect_required');
    expect(callbackResult.redirectUrl).not.toContain('tenant_custom_domain');
  });

  test('Skips validation when no tenant_custom_domain query param is present', async () => {
    mockWristbandFetch({ tokens: MOCK_TOKENS, userinfo: MOCK_USERINFO });

    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', code: 'code', tenant_name: 'devs4you' },
      headers: { cookie: await createLoginStateCookieHeader() },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const callbackResult: CallbackResult = await wristbandAuth.callback(mockExpressReq, mockExpressRes);

    expectValidateNotCalled();
    expect(callbackResult.type).toBe('completed');
  });

  test('Propagates a FetchError when the validation endpoint fails', async () => {
    mockWristbandFetch({ validateStatus: 500, tokens: MOCK_TOKENS, userinfo: MOCK_USERINFO });

    const mockExpressReq = httpMocks.createRequest({
      query: { state: 'state', code: 'code', tenant_name: 'devs4you', tenant_custom_domain: TENANT_CUSTOM_DOMAIN },
      headers: { cookie: await createLoginStateCookieHeader() },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    await expect(wristbandAuth.callback(mockExpressReq, mockExpressRes)).rejects.toThrow(FetchError);
  });
});
