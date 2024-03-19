/* eslint-disable import/no-extraneous-dependencies */

import nock from 'nock';

import { createWristbandAuth, WristbandAuth } from '../../src/index';

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
  wristbandApplicationDomain: WRISTBAND_APPLICATION_DOMAIN,
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
});
