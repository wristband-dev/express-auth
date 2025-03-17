/* eslint-disable import/no-extraneous-dependencies */

import nock from 'nock';
import { WristbandAuth } from '../../src/wristband-auth';
import { createWristbandAuth, WristbandError } from '../../src/index';

const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const LOGIN_URL = 'http://localhost:6001/api/auth/login';
const REDIRECT_URI = 'http://localhost:6001/api/auth/callback';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2c-invotastic.dev.wristband.dev';

let wristbandAuth: WristbandAuth;

beforeEach(() => {
  wristbandAuth = createWristbandAuth({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
    loginUrl: LOGIN_URL,
    redirectUri: REDIRECT_URI,
    wristbandApplicationDomain: WRISTBAND_APPLICATION_DOMAIN,
  });
});

describe('Refresh Token If Expired', () => {
  beforeEach(() => {
    nock.cleanAll();
  });

  test('Token is not expired', async () => {
    // Choose some arbitrary time in the future from the current time (in milliseconds)
    const tokenData = await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() + 1000000);
    expect(tokenData).toBeNull();
  });

  test('Token is expired, perform a token refresh', async () => {
    const mockTokens = {
      access_token: 'accessToken',
      expires_in: 1800,
      id_token: 'idToken',
      refresh_token: 'refreshToken',
      token_type: 'bearer',
    };
    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .persist()
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refreshToken')
      .reply(200, mockTokens);

    const tokenData = await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
    expect(tokenData).toEqual({
      accessToken: 'accessToken',
      expiresIn: 1800,
      idToken: 'idToken',
      refreshToken: 'refreshToken',
    });
    scope.done();
  });

  test('Token is expired, but refresh token is invalid', async () => {
    // Arrange
    const errorResponse = {
      error: 'invalid_grant',
      error_description: 'The refresh token is invalid or has expired',
    };

    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .persist()
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=invalidToken')
      .reply(400, errorResponse);

    // Act & Assert
    try {
      await wristbandAuth.refreshTokenIfExpired('invalidToken', Date.now().valueOf() - 1000);
      fail('Expected an error to be thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(WristbandError);
      expect((error as WristbandError).getError()).toBe('invalid_grant');
      expect((error as WristbandError).getErrorDescription()).toBe(errorResponse.error_description);
    }

    scope.done();
  });
});
