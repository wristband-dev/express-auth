/* eslint-disable import/no-extraneous-dependencies */

import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2c-invotastic.dev.wristband.dev';

describe('Login Errors', () => {
  let wristbandAuth: WristbandAuth;

  const loginUrl = 'http://localhost:6001/api/auth/login';
  const redirectUri = 'http://localhost:6001/api/auth/callback';

  beforeEach(() => {
    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      wristbandApplicationDomain: WRISTBAND_APPLICATION_DOMAIN,
    });
  });

  test('Multiple tenant_domain params', async () => {
    const mockExpressReq = httpMocks.createRequest({
      query: { tenant_domain: ['tenant1', 'tenant2'] },
    });
    const mockExpressRes = httpMocks.createResponse();

    try {
      await wristbandAuth.login(mockExpressReq, mockExpressRes);
      expect.fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [tenant_domain] query parameter was passed to the login endpoint');
    }
  });

  test('Multiple return_url params', async () => {
    const mockExpressReq = httpMocks.createRequest({
      query: { tenant_domain: 'test', return_url: ['url1', 'url2'] },
    });
    const mockExpressRes = httpMocks.createResponse();

    try {
      await wristbandAuth.login(mockExpressReq, mockExpressRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [return_url] query parameter was passed to the login endpoint');
    }
  });

  test('Multiple login_hint params', async () => {
    const mockExpressReq = httpMocks.createRequest({
      query: { tenant_domain: 'test', login_hint: ['hint1', 'hint2'] },
    });
    const mockExpressRes = httpMocks.createResponse();

    try {
      await wristbandAuth.login(mockExpressReq, mockExpressRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [login_hint] query parameter was passed to the login endpoint');
    }
  });

  test('Way too large customState', async () => {
    const mockExpressReq = httpMocks.createRequest({
      query: { tenant_domain: 'test' },
    });
    const mockExpressRes = httpMocks.createResponse();

    const customState = {
      superLong: '1234567890'.repeat(300),
    };

    try {
      await wristbandAuth.login(mockExpressReq, mockExpressRes, { customState });
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe(
        'Login state cookie exceeds 4kB in size. Ensure your [customState] and [returnUrl] values are a reasonable size.'
      );
    }
  });
});
