import { createWristbandAuth, WristbandAuth, WristbandError } from '../../src';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const LOGIN_URL = 'http://localhost:6001/api/auth/login';
const REDIRECT_URI = 'http://localhost:6001/api/auth/callback';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2c-invotastic.dev.wristband.dev';
const TOKEN_ENDPOINT = `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`;

const wristbandAuth: WristbandAuth = createWristbandAuth({
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
  loginUrl: LOGIN_URL,
  redirectUri: REDIRECT_URI,
  wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
  autoConfigureEnabled: false,
});

function mockFetchToken(status: number, body: unknown) {
  const bodyText = JSON.stringify(body);
  global.fetch = jest.fn().mockResolvedValue({
    status,
    ok: status >= 200 && status < 300,
    headers: {
      get: () => {
        return 'application/json';
      },
    },
    text: jest.fn().mockResolvedValue(bodyText),
  });
}

describe('Refresh Token Errors', () => {
  afterEach(() => {
    jest.restoreAllMocks();
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
    const mockError = { error: 'invalid_grant', error_description: 'Invalid refresh token' };
    mockFetchToken(400, mockError);

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof WristbandError).toBe(true);
      expect(error.code).toBe('invalid_refresh_token');
      expect(error.errorDescription).toBe('Invalid refresh token');
    }

    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(global.fetch).toHaveBeenCalledWith(
      TOKEN_ENDPOINT,
      expect.objectContaining({
        method: 'POST',
        body: 'grant_type=refresh_token&refresh_token=refreshToken',
      })
    );
  });

  test('Perform a token refresh with a server error', async () => {
    mockFetchToken(500, { error: 'server_error' });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof WristbandError).toBe(true);
      expect(error.code).toBe('unexpected_error');
      expect(error.errorDescription).toBe('Unexpected Error');
    }

    expect(global.fetch).toHaveBeenCalledTimes(3); // All 3 retry attempts exhausted
  });
});
