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

  describe('Domain Resolution Priority Tests', () => {
    describe('Priority 1: logoutConfig.tenantCustomDomain (highest priority)', () => {
      test('tenantCustomDomain config overrides everything else', async () => {
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
          headers: { host: `${parseTenantFromRootDomain}` },
          query: { tenant_custom_domain: 'ignored.com', tenant_name: 'ignored' },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        mockExpressRes.redirect(
          await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
            tenantCustomDomain: 'priority1.custom.com',
            tenantName: 'ignored',
            refreshToken: 'refreshToken',
            redirectUrl: 'https://example.com',
          })
        );

        // Validate Redirect response
        const { statusCode } = mockExpressRes;
        expect(statusCode).toEqual(302);
        const location: string = mockExpressRes._getRedirectUrl();
        expect(location).toBeTruthy();
        const locationUrl: URL = new URL(location);
        const { pathname, origin, searchParams } = locationUrl;
        expect(origin).toEqual('https://priority1.custom.com');
        expect(pathname).toEqual('/api/v1/logout');
        expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
        expect(searchParams.get('redirect_url')).toEqual('https://example.com');

        scope.done();
      });
    });

    describe('Priority 2: logoutConfig.tenantName', () => {
      test('tenantName config with default separator', async () => {
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
          headers: { host: `${parseTenantFromRootDomain}` },
          query: { tenant_custom_domain: 'ignored.com', tenant_name: 'ignored' },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        mockExpressRes.redirect(
          await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
            tenantName: 'priority2tenant',
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
        expect(origin).toEqual(`https://priority2tenant-${wristbandApplicationVanityDomain}`);
        expect(pathname).toEqual('/api/v1/logout');
        expect(searchParams.get('client_id')).toEqual(CLIENT_ID);

        scope.done();
      });

      test('tenantName config with custom domain separator', async () => {
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
          isApplicationCustomDomainActive: true,
          autoConfigureEnabled: false,
        });

        const mockExpressReq = httpMocks.createRequest({
          headers: { host: `${parseTenantFromRootDomain}` },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        mockExpressRes.redirect(
          await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
            tenantName: 'priority2tenant',
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
        expect(origin).toEqual(`https://priority2tenant.${wristbandApplicationVanityDomain}`);
        expect(pathname).toEqual('/api/v1/logout');
        expect(searchParams.get('client_id')).toEqual(CLIENT_ID);

        scope.done();
      });
    });

    describe('Priority 3: tenant_custom_domain query parameter', () => {
      test('tenant_custom_domain query param used when no config overrides', async () => {
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
          headers: { host: `${parseTenantFromRootDomain}` },
          query: { tenant_custom_domain: 'priority3.custom.com', tenant_name: 'ignored' },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

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
        expect(origin).toEqual('https://priority3.custom.com');
        expect(pathname).toEqual('/api/v1/logout');
        expect(searchParams.get('client_id')).toEqual(CLIENT_ID);

        scope.done();
      });

      test('tenant_custom_domain query param with redirect URL', async () => {
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
          headers: { host: `${parseTenantFromRootDomain}` },
          query: { tenant_custom_domain: 'priority3.custom.com' },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        mockExpressRes.redirect(
          await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
            redirectUrl: 'https://redirect.example.com',
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
        expect(origin).toEqual('https://priority3.custom.com');
        expect(pathname).toEqual('/api/v1/logout');
        expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
        expect(searchParams.get('redirect_url')).toEqual('https://redirect.example.com');

        scope.done();
      });
    });

    describe('Priority 4: tenant domain from request (subdomain or query param)', () => {
      describe.each([
        ['tenant_domain', '{tenant_domain}'],
        ['tenant_name', '{tenant_name}'],
      ])('4a: Tenant subdomains enabled with %s placeholder', (placeholderName, placeholder) => {
        test(`tenant subdomain from host header using ${placeholderName}`, async () => {
          parseTenantFromRootDomain = 'business.invotastic.com';
          loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
          redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;

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
            headers: { host: `priority4a.${parseTenantFromRootDomain}` },
          }) as any;
          const mockExpressRes = httpMocks.createResponse() as any;

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
          expect(origin).toEqual(`https://priority4a-${wristbandApplicationVanityDomain}`);
          expect(pathname).toEqual('/api/v1/logout');
          expect(searchParams.get('client_id')).toEqual(CLIENT_ID);

          scope.done();
        });

        test(`tenant subdomain with custom domain separator using ${placeholderName}`, async () => {
          parseTenantFromRootDomain = 'business.invotastic.com';
          loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
          redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;

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
            headers: { host: `priority4a.${parseTenantFromRootDomain}` },
          }) as any;
          const mockExpressRes = httpMocks.createResponse() as any;

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
          expect(origin).toEqual(`https://priority4a.${wristbandApplicationVanityDomain}`);
          expect(pathname).toEqual('/api/v1/logout');
          expect(searchParams.get('client_id')).toEqual(CLIENT_ID);

          scope.done();
        });
      });

      describe('4b: Tenant subdomains disabled - query param', () => {
        test('tenant_name query parameter with default separator', async () => {
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
            headers: { host: `${parseTenantFromRootDomain}` },
            query: { tenant_name: 'priority4b' },
          }) as any;
          const mockExpressRes = httpMocks.createResponse() as any;

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
          expect(origin).toEqual(`https://priority4b-${wristbandApplicationVanityDomain}`);
          expect(pathname).toEqual('/api/v1/logout');
          expect(searchParams.get('client_id')).toEqual(CLIENT_ID);

          scope.done();
        });

        test('tenant_name query parameter with custom domain separator', async () => {
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
            isApplicationCustomDomainActive: true,
            autoConfigureEnabled: false,
          });

          const mockExpressReq = httpMocks.createRequest({
            headers: { host: `${parseTenantFromRootDomain}` },
            query: { tenant_name: 'priority4b' },
          }) as any;
          const mockExpressRes = httpMocks.createResponse() as any;

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
          expect(origin).toEqual(`https://priority4b.${wristbandApplicationVanityDomain}`);
          expect(pathname).toEqual('/api/v1/logout');
          expect(searchParams.get('client_id')).toEqual(CLIENT_ID);

          scope.done();
        });
      });
    });

    describe('Priority 5: Fallback scenarios', () => {
      test('fallback to default application login URL', async () => {
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
          headers: { host: `${parseTenantFromRootDomain}` },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes));

        // Validate Redirect response
        const { statusCode } = mockExpressRes;
        expect(statusCode).toEqual(302);
        const location: string = mockExpressRes._getRedirectUrl();
        expect(location).toBeTruthy();
        expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
      });

      test('fallback to custom application login URL', async () => {
        const customLoginUrl = 'https://custom.login.com';
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
          customApplicationLoginPageUrl: customLoginUrl,
          autoConfigureEnabled: false,
        });

        const mockExpressReq = httpMocks.createRequest({
          headers: { host: `${parseTenantFromRootDomain}` },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes));

        // Validate Redirect response
        const { statusCode } = mockExpressRes;
        expect(statusCode).toEqual(302);
        const location: string = mockExpressRes._getRedirectUrl();
        expect(location).toBeTruthy();
        expect(location).toBe(`${customLoginUrl}?client_id=${CLIENT_ID}`);
      });

      test('fallback with redirect URL takes precedence over login URLs', async () => {
        const customLoginUrl = 'https://custom.login.com';
        const redirectUrl = 'https://redirect.priority.com';

        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
          customApplicationLoginPageUrl: customLoginUrl,
          autoConfigureEnabled: false,
        });

        const mockExpressReq = httpMocks.createRequest({
          headers: { host: `${parseTenantFromRootDomain}` },
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        mockExpressRes.redirect(
          await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
            redirectUrl,
          })
        );

        // Validate Redirect response
        const { statusCode } = mockExpressRes;
        expect(statusCode).toEqual(302);
        const location: string = mockExpressRes._getRedirectUrl();
        expect(location).toBeTruthy();
        expect(location).toBe(redirectUrl);
      });
    });
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
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          tenantName: 'devs4you',
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

    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('Tenant Subdomains Configuration with %s placeholder', (placeholderName, placeholder) => {
      test('Successful logout with tenant subdomain', async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;

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
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

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
    });

    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('Custom Domains and Tenant Subdomains Configuration with %s placeholder', (placeholderName, placeholder) => {
      test('Successful logout with custom domain', async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        wristbandApplicationVanityDomain = 'auth.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;

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
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

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
    });

    test('Custom Domains with Tenant Custom Domain, without subdomains, no tenantName config', async () => {
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
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

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

    test('Custom Domains with Tenant Custom Domain, without subdomains, with tenantName config', async () => {
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
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          tenantCustomDomain: 'tenant.custom.com',
          tenantName: 'global',
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

    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('Custom Domains with Tenant Custom Domain, with subdomains - %s placeholder', (placeholderName, placeholder) => {
      test('no tenantName config', async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        wristbandApplicationVanityDomain = 'auth.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;

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
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

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

      test('with tenantName config', async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        wristbandApplicationVanityDomain = 'auth.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;

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
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

        mockExpressRes.redirect(
          await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
            tenantCustomDomain: 'tenant.custom.com',
            tenantName: 'global',
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
    });

    test('Custom Domains with Tenant Custom Domain query param', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

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

      // Query param "tenant_custom_domain" takes precedence over "tenant_name"
      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        query: { tenant_custom_domain: 'custom.com', tenant_name: 'tenant' },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

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

    test('Tenant Domain with Tenant Name query param', async () => {
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
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        query: { tenant_name: 'tenant' },
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

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
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;
        mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes, { tenantName: 'devs4you' }));

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
        }) as any;

        const mockExpressRes = httpMocks.createResponse() as any;

        mockExpressRes.redirect(
          await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
            refreshToken: 'refreshToken',
            tenantName: 'devs4you',
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
    test('Unresolved tenantName logout config', async () => {
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
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      // tenantName logout config is missing, which should redirect to app-level login.
      mockExpressRes.redirect(await wristbandAuth.logout(mockExpressReq, mockExpressRes));

      // Validate Redirect response
      const { statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('Application-level login redirect with %s placeholder', (placeholderName, placeholder) => {
      test('Unresolved tenant subdomain', async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        wristbandApplicationVanityDomain = 'auth.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;

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
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

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
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;

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
        }) as any;
        const mockExpressRes = httpMocks.createResponse() as any;

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
    });

    test('Logout redirect URL precedence over custom application login URL', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

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
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

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
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          tenantName: 'devs4you',
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
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, {
          tenantName: 'devs4you',
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
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, { tenantName: 'devs4you', state: '' })
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
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, { tenantName: 'devs4you', state: maxState })
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
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      await expect(
        wristbandAuth.logout(mockExpressReq, mockExpressRes, { tenantName: 'devs4you', state: 'a'.repeat(513) })
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
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

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
      }) as any;
      const mockExpressRes = httpMocks.createResponse() as any;

      await expect(wristbandAuth.logout(mockExpressReq, mockExpressRes, { state: 'a'.repeat(513) })).rejects.toThrow(
        'The [state] logout config cannot exceed 512 characters.'
      );
    });
  });
});
