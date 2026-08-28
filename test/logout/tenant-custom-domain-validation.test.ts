import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { FetchError } from '../../src/error';
import { expectValidateCalled, expectValidateNotCalled, mockWristbandFetch } from '../helpers/mock-fetch';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const CONFIG_CUSTOM_DOMAIN = 'config.tenant.com';
const PARAM_CUSTOM_DOMAIN = 'param.tenant.com';

describe('Logout - Tenant Custom Domain Validation', () => {
  let wristbandAuth: WristbandAuth;
  let parseTenantFromRootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    parseTenantFromRootDomain = 'localhost:6001';
    loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
    redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
    wristbandApplicationVanityDomain = 'invotasticb2c-invotastic.dev.wristband.dev';

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

  describe('logoutConfig.tenantCustomDomain (developer-supplied)', () => {
    test('Does not validate the config value, since it cannot be manipulated by the caller', async () => {
      // The validation endpoint would reject this domain, but the config value is never sent to it.
      mockWristbandFetch({ tenantCustomDomainValid: false });

      const mockExpressReq = httpMocks.createRequest({ headers: { host: parseTenantFromRootDomain } }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const logoutUrl: string = await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
        tenantCustomDomain: CONFIG_CUSTOM_DOMAIN,
      });

      expectValidateNotCalled();
      expect(new URL(logoutUrl).origin).toEqual(`https://${CONFIG_CUSTOM_DOMAIN}`);
    });

    test('Still validates the query param even though the config value outranks it', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: true });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
        query: { tenant_custom_domain: PARAM_CUSTOM_DOMAIN },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const logoutUrl: string = await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
        tenantCustomDomain: CONFIG_CUSTOM_DOMAIN,
      });

      expectValidateCalled(wristbandApplicationVanityDomain, PARAM_CUSTOM_DOMAIN);
      expect(new URL(logoutUrl).origin).toEqual(`https://${CONFIG_CUSTOM_DOMAIN}`);
    });

    test('Rejects an invalid query param even though the config value outranks it', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
        query: { tenant_custom_domain: PARAM_CUSTOM_DOMAIN },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      await expect(
        wristbandAuth.logout(mockExpressReq, mockExpressRes, { tenantCustomDomain: CONFIG_CUSTOM_DOMAIN })
      ).rejects.toThrow('Tenant custom domain is not valid');
    });
  });

  describe('Priority 2: logoutConfig.tenantName', () => {
    test('Still validates the query param even though tenantName outranks it', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
        query: { tenant_custom_domain: PARAM_CUSTOM_DOMAIN },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      await expect(
        wristbandAuth.logout(mockExpressReq, mockExpressRes, { tenantName: 'priority2tenant' })
      ).rejects.toThrow('Tenant custom domain is not valid');
    });

    test('Redirects using tenantName when the query param is valid', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: true });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
        query: { tenant_custom_domain: PARAM_CUSTOM_DOMAIN },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const logoutUrl: string = await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
        tenantName: 'priority2tenant',
      });

      expect(new URL(logoutUrl).origin).toEqual(`https://priority2tenant-${wristbandApplicationVanityDomain}`);
    });
  });

  describe('Priority 3: tenant_custom_domain query param', () => {
    test('Validates the query param and redirects to it when valid', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: true });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
        query: { tenant_custom_domain: PARAM_CUSTOM_DOMAIN },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const logoutUrl: string = await wristbandAuth.logout(mockExpressReq, mockExpressRes);

      expectValidateCalled(wristbandApplicationVanityDomain, PARAM_CUSTOM_DOMAIN);
      expect(new URL(logoutUrl).origin).toEqual(`https://${PARAM_CUSTOM_DOMAIN}`);
    });

    test('Throws a TypeError when the query param is not valid', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
        query: { tenant_custom_domain: PARAM_CUSTOM_DOMAIN },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      await expect(wristbandAuth.logout(mockExpressReq, mockExpressRes)).rejects.toThrow(
        'Tenant custom domain is not valid'
      );
    });

    test('Propagates a FetchError when the validation endpoint fails', async () => {
      mockWristbandFetch({ validateStatus: 500 });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
        query: { tenant_custom_domain: PARAM_CUSTOM_DOMAIN },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      await expect(wristbandAuth.logout(mockExpressReq, mockExpressRes)).rejects.toThrow(FetchError);
    });

    test('Revokes the refresh token before validation rejects the logout', async () => {
      const fetchMock = mockWristbandFetch({ tenantCustomDomainValid: false });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
        query: { tenant_custom_domain: PARAM_CUSTOM_DOMAIN },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      await expect(
        wristbandAuth.logout(mockExpressReq, mockExpressRes, { refreshToken: 'refreshToken' })
      ).rejects.toThrow('Tenant custom domain is not valid');

      expect(fetchMock.mock.calls[0][0]).toContain('/oauth2/revoke');
      expect(fetchMock.mock.calls[1][0]).toContain('/custom-domains/validate');
    });
  });

  describe('Priority 4: tenant name', () => {
    test('Skips validation when no tenant custom domain is present anywhere', async () => {
      mockWristbandFetch();

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
        query: { tenant_name: 'devs4you' },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const logoutUrl: string = await wristbandAuth.logout(mockExpressReq, mockExpressRes);

      expectValidateNotCalled();
      expect(new URL(logoutUrl).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
    });
  });
});
