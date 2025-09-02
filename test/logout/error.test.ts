/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-underscore-dangle */

import nock from 'nock';
import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

describe('Logout Errors', () => {
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

    nock.cleanAll();
  });

  test('Multiple tenant_domain params', async () => {
    const mockExpressReq = httpMocks.createRequest({
      query: { tenant_domain: ['tenant1', 'tenant2'] },
    });
    const mockExpressRes = httpMocks.createResponse();

    try {
      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, { refreshToken: 'refreshToken' })
      );
      expect.fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [tenant_domain] query parameter was encountered during logout');
    }
  });

  test('Multiple tenant_custom_domain params', async () => {
    const mockExpressReq = httpMocks.createRequest({
      query: { tenant_custom_domain: ['tenant1.com', 'tenant2.com'] },
    });
    const mockExpressRes = httpMocks.createResponse();

    try {
      mockExpressRes.redirect(
        await wristbandAuth.logout(mockExpressReq, mockExpressRes, { refreshToken: 'refreshToken' })
      );
      expect.fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [tenant_custom_domain] query parameter was encountered during logout');
    }
  });
});
