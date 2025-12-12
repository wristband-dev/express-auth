import nock from 'nock';

import { createWristbandAuth, WristbandAuth, WristbandError } from '../../src/index';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const LOGIN_URL = 'http://localhost:6001/api/auth/login';
const REDIRECT_URI = 'http://localhost:6001/api/auth/callback';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2c-invotastic.dev.wristband.dev';

const wristbandAuth: WristbandAuth = createWristbandAuth({
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
  loginUrl: LOGIN_URL,
  redirectUri: REDIRECT_URI,
  wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
  autoConfigureEnabled: false,
});

describe('Refresh Token Errors', () => {
  beforeEach(() => {
    nock.cleanAll();
  });

  test('Invalid refreshToken', async () => {
    try {
      await wristbandAuth.refreshTokenIfExpired('', 1000);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Refresh token must be a valid string');
    }
  });

  test('Invalid expiresAt', async () => {
    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', -1000);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('The expiresAt field must be an integer greater than 0');
    }
  });

  test('Perform a token refresh with a bad token value', async () => {
    const mockError = {
      error: 'invalid_grant',
      error_description: 'Invalid refresh token',
    };
    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .persist()
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refreshToken')
      .reply(400, mockError);

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof WristbandError).toBe(true);
      expect(error.code).toBe('invalid_grant');
      expect(error.errorDescription).toBe('Invalid refresh token');
    }

    scope.done();
  });

  test('Perform a token refresh with a server error', async () => {
    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .persist()
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refreshToken')
      .reply(500);

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof WristbandError).toBe(true);
      expect(error.code).toBe('unexpected_error');
      expect(error.errorDescription).toBe('Unexpected Error');
    }

    scope.done();
  });
});
