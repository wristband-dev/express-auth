/* eslint-disable no-underscore-dangle */

import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { mockWristbandFetch } from '../helpers/mock-fetch';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

describe('Logout - App-Level Authorization Requests', () => {
  let wristbandAuth: WristbandAuth;

  beforeEach(() => {
    mockWristbandFetch();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Tenant subdomain configuration (loginUrl contains a placeholder)', () => {
    describe.each([['{tenant_domain}'], ['{tenant_name}']])('with %s placeholder', (placeholder) => {
      test('Falls back to fallbackLoginUrl when tenant cannot be resolved', async () => {
        const parseTenantFromRootDomain = 'business.invotastic.com';
        const wristbandApplicationVanityDomain = 'auth.invotastic.com';
        const loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        const redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
        const fallbackLoginUrl = 'https://fallback.invotastic.com/login';

        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          parseTenantFromRootDomain,
          wristbandApplicationVanityDomain,
          applicationAuthorizationRequestsEnabled: true,
          fallbackLoginUrl,
          autoConfigureEnabled: false,
        });

        // No subdomain present on the host, so tenant cannot be resolved
        const mockExpressReq = httpMocks.createRequest({
          headers: { host: parseTenantFromRootDomain },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        const logoutUrl = await wristbandAuth.logout(mockExpressReq, mockExpressRes);

        expect(logoutUrl).toBe(fallbackLoginUrl);
      });
    });
  });

  describe('Fixed host configuration (loginUrl has no placeholder)', () => {
    test('Falls back directly to loginUrl when tenant cannot be resolved', async () => {
      const wristbandApplicationVanityDomain = 'invotasticb2c-invotastic.dev.wristband.dev';
      const loginUrl = 'https://localhost:6001/api/auth/login';
      const redirectUri = 'https://localhost:6001/api/auth/callback';

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: 'localhost:6001' },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const logoutUrl = await wristbandAuth.logout(mockExpressReq, mockExpressRes);

      expect(logoutUrl).toBe(loginUrl);
    });
  });

  describe('Priority ordering', () => {
    test('config.redirectUrl still takes precedence over the app-level fallback', async () => {
      const parseTenantFromRootDomain = 'business.invotastic.com';
      const wristbandApplicationVanityDomain = 'auth.invotastic.com';
      const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;
      const fallbackLoginUrl = 'https://fallback.invotastic.com/login';

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        fallbackLoginUrl,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const logoutUrl = await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
        redirectUrl: 'https://redirect.example.com',
      });

      expect(logoutUrl).toBe('https://redirect.example.com');
    });

    test('Resolves the normal tenant-level logout URL when a tenant is resolvable, even with the flag enabled', async () => {
      const parseTenantFromRootDomain = 'business.invotastic.com';
      const wristbandApplicationVanityDomain = 'auth.invotastic.com';
      const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;
      const fallbackLoginUrl = 'https://fallback.invotastic.com/login';

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        fallbackLoginUrl,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      const logoutUrl = await wristbandAuth.logout(mockExpressReq, mockExpressRes);

      expect(new URL(logoutUrl).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
    });
  });
});
