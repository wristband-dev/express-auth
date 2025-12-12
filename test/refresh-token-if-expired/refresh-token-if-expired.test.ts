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
    wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
    autoConfigureEnabled: false,
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
    expect(tokenData).toBeDefined();
    expect(tokenData?.accessToken).toBe('accessToken');
    expect(tokenData?.expiresAt).toBeGreaterThanOrEqual(Date.now());
    expect(tokenData?.expiresIn).toBe(1740);
    expect(tokenData?.idToken).toBe('idToken');
    expect(tokenData?.refreshToken).toBe('refreshToken');
    scope.done();
  });

  test('Token is expired, but refresh token is invalid', async () => {
    const errorResponse = { error: 'invalid_grant', error_description: 'The refresh token is invalid or has expired' };
    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .persist()
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=invalidToken')
      .reply(400, errorResponse);

    try {
      await wristbandAuth.refreshTokenIfExpired('invalidToken', Date.now().valueOf() - 1000);
      fail('Expected an error to be thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(WristbandError);
      expect((error as WristbandError).code).toBe('invalid_grant');
      expect((error as WristbandError).errorDescription).toBe(errorResponse.error_description);
    }

    scope.done();
  });

  test('Token refresh with custom tokenExpirationBuffer', async () => {
    // Create wristbandAuth with custom buffer
    const customBufferAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl: LOGIN_URL,
      redirectUri: REDIRECT_URI,
      wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      tokenExpirationBuffer: 120, // 2 minutes buffer
      autoConfigureEnabled: false,
    });

    const mockTokens = {
      access_token: 'accessToken',
      expires_in: 1800, // 30 minutes
      id_token: 'idToken',
      refresh_token: 'refreshToken',
      token_type: 'bearer',
    };

    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refreshToken')
      .reply(200, mockTokens);

    const tokenData = await customBufferAuth.refreshTokenIfExpired('refreshToken', Date.now() - 1000);

    expect(tokenData).toBeDefined();
    expect(tokenData?.expiresIn).toBe(1680); // 1800 - 120 (custom buffer)
    scope.done();
  });

  test('Token refresh with zero tokenExpirationBuffer', async () => {
    const zeroBufferAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl: LOGIN_URL,
      redirectUri: REDIRECT_URI,
      wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      tokenExpirationBuffer: 0,
      autoConfigureEnabled: false,
    });

    const mockTokens = {
      access_token: 'accessToken',
      expires_in: 1800,
      id_token: 'idToken',
      refresh_token: 'refreshToken',
      token_type: 'bearer',
    };

    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refreshToken')
      .reply(200, mockTokens);

    const tokenData = await zeroBufferAuth.refreshTokenIfExpired('refreshToken', Date.now() - 1000);

    expect(tokenData?.expiresIn).toBe(1800); // No buffer applied
    scope.done();
  });

  test('Token at exact expiration boundary', async () => {
    const currentTime = Date.now();

    // Mock the HTTP call since token will be considered expired
    const mockTokens = {
      access_token: 'accessToken',
      expires_in: 1800,
      id_token: 'idToken',
      refresh_token: 'refreshToken',
      token_type: 'bearer',
    };

    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refreshToken')
      .reply(200, mockTokens);

    // Mock Date.now to return consistent time
    const mockDateNow = jest.spyOn(Date, 'now').mockReturnValue(currentTime);

    const tokenData = await wristbandAuth.refreshTokenIfExpired('refreshToken', currentTime);

    // At exact expiration time, token should be considered expired and refreshed
    expect(tokenData).toBeDefined();
    expect(tokenData?.accessToken).toBe('accessToken');

    mockDateNow.mockRestore();
    scope.done();
  });

  test('ExpiresAt calculation includes buffer correctly', async () => {
    const mockTokens = {
      access_token: 'accessToken',
      expires_in: 3600, // 1 hour
      id_token: 'idToken',
      refresh_token: 'newRefreshToken',
      token_type: 'bearer',
    };

    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refreshToken')
      .reply(200, mockTokens);

    const beforeRefresh = Date.now();
    const tokenData = await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now() - 1000);
    const afterRefresh = Date.now();

    expect(tokenData).toBeDefined();
    // Default buffer is 60 seconds, so 3600 - 60 = 3540 seconds
    expect(tokenData?.expiresIn).toBe(3540);

    // expiresAt should be roughly current time + 3540 seconds (in milliseconds)
    const expectedExpiresAt = beforeRefresh + 3540 * 1000;
    expect(tokenData?.expiresAt).toBeGreaterThanOrEqual(expectedExpiresAt);
    expect(tokenData?.expiresAt).toBeLessThanOrEqual(afterRefresh + 3540 * 1000);

    scope.done();
  });

  test('Handles server error with retry logic (5xx errors)', async () => {
    const mockTokens = {
      access_token: 'accessToken',
      expires_in: 1800,
      id_token: 'idToken',
      refresh_token: 'refreshToken',
      token_type: 'bearer',
    };

    // First two calls return 500, third succeeds
    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refreshToken')
      .reply(500, { error: 'server_error' })
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refreshToken')
      .reply(500, { error: 'server_error' })
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refreshToken')
      .reply(200, mockTokens);

    const tokenData = await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now() - 1000);

    expect(tokenData).toBeDefined();
    expect(tokenData?.accessToken).toBe('accessToken');
    scope.done();
  });

  test('Handles 4xx client error without retry', async () => {
    const errorResponse = {
      error: 'invalid_client',
      error_description: 'Client authentication failed',
    };

    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refreshToken')
      .reply(401, errorResponse);

    await expect(wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now() - 1000)).rejects.toThrow(
      WristbandError
    );

    // Should only make one call (no retry for 4xx)
    scope.done();
  });

  test('Handles 4xx error without error_description', async () => {
    const errorResponse = {
      error: 'invalid_request',
    };

    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refreshToken')
      .reply(400, errorResponse);

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now() - 1000);
      fail('Expected an error to be thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(WristbandError);
      expect((error as WristbandError).code).toBe('invalid_refresh_token');
      expect((error as WristbandError).errorDescription).toBe('Invalid Refresh Token'); // Default description
    }

    scope.done();
  });

  test('Parameter validation - empty refresh token', async () => {
    await expect(wristbandAuth.refreshTokenIfExpired('', Date.now() + 1000)).rejects.toThrow(
      'Refresh token must be a valid string'
    );
  });

  test('Parameter validation - null refresh token', async () => {
    await expect(wristbandAuth.refreshTokenIfExpired(null as any, Date.now() + 1000)).rejects.toThrow(
      'Refresh token must be a valid string'
    );
  });

  test('Parameter validation - zero expiresAt', async () => {
    await expect(wristbandAuth.refreshTokenIfExpired('refreshToken', 0)).rejects.toThrow(
      'The expiresAt field must be an integer greater than 0'
    );
  });

  test('Parameter validation - negative expiresAt', async () => {
    await expect(wristbandAuth.refreshTokenIfExpired('refreshToken', -1000)).rejects.toThrow(
      'The expiresAt field must be an integer greater than 0'
    );
  });

  test('Parameter validation - null expiresAt', async () => {
    await expect(wristbandAuth.refreshTokenIfExpired('refreshToken', null as any)).rejects.toThrow(
      'The expiresAt field must be an integer greater than 0'
    );
  });
});
