/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-underscore-dangle */

import nock from 'nock';
import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

describe('Multi Tenant Logout', () => {
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
    nock.cleanAll();
  });

  describe('Logout Happy Path', () => {
    test('Default Configuration', async () => {
      const scope = nock(`https://${wristbandApplicationVanityDomain}`)
        .persist()
        .post('/api/v1/oauth2/revoke', 'token=refreshToken')
        .reply(200);

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
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          tenantDomainName: 'devs4you',
          refreshToken: 'refreshToken',
          redirectUrl: 'https://google.com',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/logout');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(2);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_url')).toEqual('https://google.com');

      scope.done();
    });

    test('Tenant Subdomains Configuration', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      const scope = nock(`https://${wristbandApplicationVanityDomain}`)
        .persist()
        .post('/api/v1/oauth2/revoke', 'token=refreshToken')
        .reply(200);

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

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          refreshToken: 'refreshToken',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/logout');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(2);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_url')).toBeFalsy();

      scope.done();
    });

    test('Custom Domains and Tenant Subdomains Configuration', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      const scope = nock(`https://${wristbandApplicationVanityDomain}`)
        .persist()
        .post('/api/v1/oauth2/revoke', 'token=refreshToken')
        .reply(200);

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

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          refreshToken: 'refreshToken',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/logout');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(2);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_url')).toBeFalsy();

      scope.done();
    });

    test('Custom Domains with Tenant Custom Domain, without subdomains, no tenantDomainName config', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;

      const scope = nock(`https://${wristbandApplicationVanityDomain}`)
        .persist()
        .post('/api/v1/oauth2/revoke', 'token=refreshToken')
        .reply(200);

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          tenantCustomDomain: 'tenant.custom.com',
          refreshToken: 'refreshToken',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/logout');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(2);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_url')).toBeFalsy();

      scope.done();
    });

    test('Custom Domains with Tenant Custom Domain, without subdomains, with tenantDomainName config', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;

      const scope = nock(`https://${wristbandApplicationVanityDomain}`)
        .persist()
        .post('/api/v1/oauth2/revoke', 'token=refreshToken')
        .reply(200);

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          tenantCustomDomain: 'tenant.custom.com',
          tenantDomainName: 'global',
          refreshToken: 'refreshToken',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/logout');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(2);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_url')).toBeFalsy();

      scope.done();
    });

    test('Custom Domains with Tenant Custom Domain, with subdomains, no tenantDomainName config', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      const scope = nock(`https://${wristbandApplicationVanityDomain}`)
        .persist()
        .post('/api/v1/oauth2/revoke', 'token=refreshToken')
        .reply(200);

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

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you${parseTenantFromRootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          tenantCustomDomain: 'tenant.custom.com',
          refreshToken: 'refreshToken',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/logout');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(2);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_url')).toBeFalsy();

      scope.done();
    });

    test('Custom Domains with Tenant Custom Domain, with subdomains, with tenantDomainName config', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      const scope = nock(`https://${wristbandApplicationVanityDomain}`)
        .persist()
        .post('/api/v1/oauth2/revoke', 'token=refreshToken')
        .reply(200);

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

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you${parseTenantFromRootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          tenantCustomDomain: 'tenant.custom.com',
          tenantDomainName: 'global',
          refreshToken: 'refreshToken',
        })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/logout');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(2);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_url')).toBeFalsy();

      scope.done();
    });

    test('Custom Domains with Tenant Custom Domain query param', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      const scope = nock(`https://${wristbandApplicationVanityDomain}`)
        .persist()
        .post('/api/v1/oauth2/revoke', 'token=refreshToken')
        .reply(200);

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

      // Query param "tenant_custom_domain" takes precedence over "tenant_domain"
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you${parseTenantFromRootDomain}` },
        query: { tenant_custom_domain: 'custom.com', tenant_domain: 'tenant' },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, { refreshToken: 'refreshToken' })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://custom.com`);
      expect(pathname).toEqual('/api/v1/logout');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(2);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_url')).toBeFalsy();

      scope.done();
    });

    test('Tenant Domain with Tenant Domain query param', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;

      const scope = nock(`https://${wristbandApplicationVanityDomain}`)
        .persist()
        .post('/api/v1/oauth2/revoke', 'token=refreshToken')
        .reply(200);

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you${parseTenantFromRootDomain}` },
        query: { tenant_domain: 'tenant' },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, { refreshToken: 'refreshToken' })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://tenant.auth.invotastic.com`);
      expect(pathname).toEqual('/api/v1/logout');

      // Validate no-cache headers
      const headers = mockExpressRes._getHeaders();
      expect(Object.keys(headers)).toHaveLength(2);
      expect(headers['cache-control']).toBe('no-store');
      expect(headers['pragma']).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_url')).toBeFalsy();

      scope.done();
    });

    describe('Refresh Token Edge Cases', () => {
      let consoleLogSpy: jest.SpyInstance;

      beforeAll(() => {
        consoleLogSpy = jest.spyOn(console, 'debug').mockImplementation(() => {});
      });

      afterAll(() => {
        consoleLogSpy.mockRestore();
      });

      test('No Token to Revoke', async () => {
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
          headers: { host: parseTenantFromRootDomain },
        });
        const mockExpressRes = httpMocks.createResponse();

        mockExpressRes.redirect(
          await wristbandAuth.logout(mockExpressReq, mockExpressRes, { tenantDomainName: 'devs4you' })
        );

        // Validate Redirect response
        const { statusCode } = mockExpressRes;
        expect(statusCode).toEqual(302);
        const location: string = mockExpressRes._getRedirectUrl();
        expect(location).toBeTruthy();
        const locationUrl: URL = new URL(location);
        const { pathname, origin, searchParams } = locationUrl;
        expect(origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
        expect(pathname).toEqual('/api/v1/logout');

        // Validate no-cache headers
        const headers = mockExpressRes._getHeaders();
        expect(Object.keys(headers)).toHaveLength(2);
        expect(headers['cache-control']).toBe('no-store');
        expect(headers['pragma']).toBe('no-cache');

        // Validate query params of Logout URL
        expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      });

      test('Revoke Token Failure', async () => {
        const scope = nock(`https://${wristbandApplicationVanityDomain}`)
          .persist()
          .post('/api/v1/oauth2/revoke', 'token=refreshToken')
          .reply(401);

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
          headers: { host: parseTenantFromRootDomain },
        });

        const mockExpressRes = httpMocks.createResponse();

        mockExpressRes.redirect(
          await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
            refreshToken: 'refreshToken',
            tenantDomainName: 'devs4you',
          })
        );

        // Validate Redirect response
        const { statusCode } = mockExpressRes;
        expect(statusCode).toEqual(302);
        const location: string = mockExpressRes._getRedirectUrl();
        expect(location).toBeTruthy();
        const locationUrl: URL = new URL(location);
        const { pathname, origin, searchParams } = locationUrl;
        expect(origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
        expect(pathname).toEqual('/api/v1/logout');

        // Validate no-cache headers
        const headers = mockExpressRes._getHeaders();
        expect(Object.keys(headers)).toHaveLength(2);
        expect(headers['cache-control']).toBe('no-store');
        expect(headers['pragma']).toBe('no-cache');

        // Validate query params of Logout URL
        expect(searchParams.get('client_id')).toEqual(CLIENT_ID);

        scope.done();
      });
    });
  });

  describe('Redirect to Application-level Login/Tenant Discovery', () => {
    test('Unresolved tenantDomainName logout config', async () => {
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
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      // tenantDomainName logout config is missing, which should redirect to app-level login.
      mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Unresolved tenant subdomain', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

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

      // Subdomain is missing from host, which should redirect to app-level login.
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Custom application login URL redirect', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        customApplicationLoginPageUrl: 'https://google.com',
        autoConfigureEnabled: false,
      });

      // Subdomain is missing from host, which should redirect to custom app-level login.
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual('https://google.com');
      expect(pathname).toEqual('/');
    });

    test('Logout redirect URL precedence over custom application login URL', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        customApplicationLoginPageUrl: 'https://google.com',
        autoConfigureEnabled: false,
      });

      // Subdomain is missing from host, which should redirect to logout redirectUrl.
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, { redirectUrl: 'https://yahoo.com' })
      );

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual('https://yahoo.com');
      expect(pathname).toEqual('/');
    });
  });

  describe('State Configuration Tests', () => {
    test('Logout with state parameter', async () => {
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
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          tenantDomainName: 'devs4you',
          state: 'custom-logout-state-123',
        })
      );

      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { searchParams } = locationUrl;

      expect(searchParams.get('state')).toEqual('custom-logout-state-123');
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
    });

    test('Logout with state and redirectUrl parameters', async () => {
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
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          tenantDomainName: 'devs4you',
          state: 'logout-state-with-redirect',
          redirectUrl: 'https://example.com/logged-out',
        })
      );

      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { searchParams } = locationUrl;

      expect(searchParams.get('state')).toEqual('logout-state-with-redirect');
      expect(searchParams.get('redirect_url')).toEqual('https://example.com/logged-out');
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
    });

    test('Logout with empty state parameter (should not include state in query)', async () => {
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
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, { tenantDomainName: 'devs4you', state: '' })
      );

      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { searchParams } = locationUrl;

      expect(searchParams.get('state')).toBeNull();
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
    });

    test('Logout with state parameter at maximum length (512 characters)', async () => {
      const maxState = 'a'.repeat(512);

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
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, { tenantDomainName: 'devs4you', state: maxState })
      );

      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { searchParams } = locationUrl;

      expect(searchParams.get('state')).toEqual(maxState);
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
    });

    test('Logout throws error when state exceeds 512 characters', async () => {
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
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      await expect(
        wristbandAuth.logout(mockExpressReq, mockExpressRes, { tenantDomainName: 'devs4you', state: 'a'.repeat(513) })
      ).rejects.toThrow('The [state] logout config cannot exceed 512 characters.');
    });

    test('Logout with state parameter in fallback scenario (app-level login)', async () => {
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
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      // No tenant domain resolution - should fallback but state validation still applies
      const location = await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
        state: 'fallback-state',
      });

      // Should still return fallback URL (state doesn't affect fallback behavior)
      expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Logout throws error when state exceeds limit in fallback scenario', async () => {
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
        headers: { host: parseTenantFromRootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      await expect(wristbandAuth.logout(mockExpressReq, mockExpressRes, { state: 'a'.repeat(513) })).rejects.toThrow(
        'The [state] logout config cannot exceed 512 characters.'
      );
    });
  });
});
