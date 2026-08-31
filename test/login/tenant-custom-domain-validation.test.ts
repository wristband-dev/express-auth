/* eslint-disable no-underscore-dangle */

import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { FetchError } from '../../src/error';
import { expectValidateCalled, expectValidateNotCalled, mockWristbandFetch } from '../helpers/mock-fetch';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const TENANT_CUSTOM_DOMAIN = 'login.tenant.com';

describe('Login - Tenant Custom Domain Validation', () => {
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

  test('Validates the tenant_custom_domain query param and proceeds when it is valid', async () => {
    mockWristbandFetch({ tenantCustomDomainValid: true });

    const mockExpressReq = httpMocks.createRequest({
      headers: { host: parseTenantFromRootDomain },
      query: { tenant_custom_domain: TENANT_CUSTOM_DOMAIN },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const authorizeUrl: string = await wristbandAuth.login(mockExpressReq, mockExpressRes);

    expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
    expect(new URL(authorizeUrl).origin).toEqual(`https://${TENANT_CUSTOM_DOMAIN}`);
  });

  test('Skips an invalid tenant custom domain and falls through to the tenant_name query param', async () => {
    mockWristbandFetch({ tenantCustomDomainValid: false });

    const mockExpressReq = httpMocks.createRequest({
      headers: { host: parseTenantFromRootDomain },
      query: { tenant_custom_domain: TENANT_CUSTOM_DOMAIN, tenant_name: 'devs4you' },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const authorizeUrl: string = await wristbandAuth.login(mockExpressReq, mockExpressRes);

    expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
    expect(new URL(authorizeUrl).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
  });

  test('Skips an invalid tenant custom domain and falls through to the defaultTenantCustomDomain config', async () => {
    mockWristbandFetch({ tenantCustomDomainValid: false });

    const mockExpressReq = httpMocks.createRequest({
      headers: { host: parseTenantFromRootDomain },
      query: { tenant_custom_domain: TENANT_CUSTOM_DOMAIN },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const authorizeUrl: string = await wristbandAuth.login(mockExpressReq, mockExpressRes, {
      defaultTenantCustomDomain: 'default.tenant.com',
    });

    expect(new URL(authorizeUrl).origin).toEqual('https://default.tenant.com');
  });

  test('Redirects to application-level login when an invalid tenant custom domain is the only domain', async () => {
    mockWristbandFetch({ tenantCustomDomainValid: false });

    const mockExpressReq = httpMocks.createRequest({
      headers: { host: parseTenantFromRootDomain },
      query: { tenant_custom_domain: TENANT_CUSTOM_DOMAIN },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const appLoginUrl: string = await wristbandAuth.login(mockExpressReq, mockExpressRes);

    expect(appLoginUrl).toEqual(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    expect(mockExpressRes._getHeaders()['set-cookie']).toBeUndefined();
  });

  test('Skips validation when no tenant_custom_domain query param is present', async () => {
    mockWristbandFetch();

    const mockExpressReq = httpMocks.createRequest({
      headers: { host: parseTenantFromRootDomain },
      query: { tenant_name: 'devs4you' },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const authorizeUrl: string = await wristbandAuth.login(mockExpressReq, mockExpressRes);

    expectValidateNotCalled();
    expect(new URL(authorizeUrl).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
  });

  test('Skips validation for the defaultTenantCustomDomain login config', async () => {
    mockWristbandFetch();

    const mockExpressReq = httpMocks.createRequest({ headers: { host: parseTenantFromRootDomain } }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    const authorizeUrl: string = await wristbandAuth.login(mockExpressReq, mockExpressRes, {
      defaultTenantCustomDomain: 'default.tenant.com',
    });

    expectValidateNotCalled();
    expect(new URL(authorizeUrl).origin).toEqual('https://default.tenant.com');
  });

  test('Propagates a FetchError when the validation endpoint fails', async () => {
    mockWristbandFetch({ validateStatus: 500 });

    const mockExpressReq = httpMocks.createRequest({
      headers: { host: parseTenantFromRootDomain },
      query: { tenant_custom_domain: TENANT_CUSTOM_DOMAIN },
    }) as any;
    const mockExpressRes = httpMocks.createResponse() as any;

    await expect(wristbandAuth.login(mockExpressReq, mockExpressRes)).rejects.toThrow(FetchError);
  });
});
