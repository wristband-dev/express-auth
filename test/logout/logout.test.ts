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
  let rootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    rootDomain = 'localhost:6001';
    loginUrl = `https://${rootDomain}/api/auth/login`;
    redirectUri = `https://${rootDomain}/api/auth/callback`;
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
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: rootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
        tenantDomainName: 'devs4you',
        refreshToken: 'refreshToken',
        redirectUrl: 'https://google.com',
      }));

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
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

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
        rootDomain,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
        refreshToken: 'refreshToken',
      }));

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
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

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
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
        refreshToken: 'refreshToken',
      }));

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
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;

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
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
        tenantCustomDomain: 'tenant.custom.com',
        refreshToken: 'refreshToken',
      }));

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
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;

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
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
        tenantCustomDomain: 'tenant.custom.com',
        tenantDomainName: 'global',
        refreshToken: 'refreshToken',
      }));

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
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

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
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
        tenantCustomDomain: 'tenant.custom.com',
        refreshToken: 'refreshToken',
      }));

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
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

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
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
        tenantCustomDomain: 'tenant.custom.com',
        tenantDomainName: 'global',
        refreshToken: 'refreshToken',
      }));

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

    describe('Refresh Token Edge Cases', () => {
      test('No Token to Revoke', async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
        });

        const mockExpressReq = httpMocks.createRequest({
          headers: { host: rootDomain },
        });
        const mockExpressRes = httpMocks.createResponse();

        mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes, { tenantDomainName: 'devs4you' }));

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
        });

        const mockExpressReq = httpMocks.createRequest({
          headers: { host: rootDomain },
        });

        const mockExpressRes = httpMocks.createResponse();

        mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          refreshToken: 'refreshToken',
          tenantDomainName: 'devs4you',
        }));

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
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: rootDomain },
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
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
      });

      // Subdomain is missing from host, which should redirect to app-level login.
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: rootDomain },
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
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
        customApplicationLoginPageUrl: 'https://google.com',
      });

      // Subdomain is missing from host, which should redirect to custom app-level login.
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: rootDomain },
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
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
        customApplicationLoginPageUrl: 'https://google.com',
      });

      // Subdomain is missing from host, which should redirect to logout redirectUrl.
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: rootDomain },
      });
      const mockExpressRes = httpMocks.createResponse();

      mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes, { redirectUrl: 'https://yahoo.com' }));

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
});
