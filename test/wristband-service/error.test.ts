/* eslint-disable no-new */
/* eslint-disable no-restricted-syntax */
/* eslint-disable no-await-in-loop */

import nock from 'nock';
import { WristbandService } from '../../src/wristband-service';
import { InvalidGrantError } from '../../src/error';

const DOMAIN = 'your-wristband-domain';
const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';

describe('WristbandService - Error Handling', () => {
  let wristbandService: WristbandService;

  beforeEach(() => {
    // Clean up any previous nock interceptors
    nock.cleanAll();

    // Create service instance
    wristbandService = new WristbandService(DOMAIN, CLIENT_ID, CLIENT_SECRET);
  });

  describe('Constructor Validation', () => {
    test('With empty domain throws error', () => {
      try {
        new WristbandService('', CLIENT_ID, CLIENT_SECRET);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Wristband application domain is required');
      }
    });

    test('With null domain throws error', () => {
      try {
        new WristbandService(null as any, CLIENT_ID, CLIENT_SECRET);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Wristband application domain is required');
      }
    });

    test('With whitespace-only domain throws error', () => {
      try {
        new WristbandService('   ', CLIENT_ID, CLIENT_SECRET);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Wristband application domain is required');
      }
    });

    test('With empty client ID throws error', () => {
      try {
        new WristbandService(DOMAIN, '', CLIENT_SECRET);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Client ID is required');
      }
    });

    test('With null client ID throws error', () => {
      try {
        new WristbandService(DOMAIN, null as any, CLIENT_SECRET);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Client ID is required');
      }
    });

    test('With whitespace-only client ID throws error', () => {
      try {
        new WristbandService(DOMAIN, '   ', CLIENT_SECRET);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Client ID is required');
      }
    });

    test('With empty client secret throws error', () => {
      try {
        new WristbandService(DOMAIN, CLIENT_ID, '');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Client secret is required');
      }
    });

    test('With null client secret throws error', () => {
      try {
        new WristbandService(DOMAIN, CLIENT_ID, null as any);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Client secret is required');
      }
    });

    test('With whitespace-only client secret throws error', () => {
      try {
        new WristbandService(DOMAIN, CLIENT_ID, '   ');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Client secret is required');
      }
    });
  });

  describe('Parameter Validation', () => {
    test('getTokens with empty code throws error', async () => {
      const redirectUri = 'https://app.example.com/callback';
      const codeVerifier = 'valid-code-verifier';

      try {
        await wristbandService.getTokens('', redirectUri, codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Authorization code is required');
      }
    });

    test('getTokens with null code throws error', async () => {
      const redirectUri = 'https://app.example.com/callback';
      const codeVerifier = 'valid-code-verifier';

      try {
        await wristbandService.getTokens(null as any, redirectUri, codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Authorization code is required');
      }
    });

    test('getTokens with whitespace-only code throws error', async () => {
      const redirectUri = 'https://app.example.com/callback';
      const codeVerifier = 'valid-code-verifier';

      try {
        await wristbandService.getTokens('   ', redirectUri, codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Authorization code is required');
      }
    });

    test('getTokens with empty redirect URI throws error', async () => {
      const code = 'valid-auth-code';
      const codeVerifier = 'valid-code-verifier';

      try {
        await wristbandService.getTokens(code, '', codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Redirect URI is required');
      }
    });

    test('getTokens with null redirect URI throws error', async () => {
      const code = 'valid-auth-code';
      const codeVerifier = 'valid-code-verifier';

      try {
        await wristbandService.getTokens(code, null as any, codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Redirect URI is required');
      }
    });

    test('getTokens with whitespace-only redirect URI throws error', async () => {
      const code = 'valid-auth-code';
      const codeVerifier = 'valid-code-verifier';

      try {
        await wristbandService.getTokens(code, '   ', codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Redirect URI is required');
      }
    });

    test('getTokens with empty code verifier throws error', async () => {
      const code = 'valid-auth-code';
      const redirectUri = 'https://app.example.com/callback';

      try {
        await wristbandService.getTokens(code, redirectUri, '');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Code verifier is required');
      }
    });

    test('getTokens with null code verifier throws error', async () => {
      const code = 'valid-auth-code';
      const redirectUri = 'https://app.example.com/callback';

      try {
        await wristbandService.getTokens(code, redirectUri, null as any);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Code verifier is required');
      }
    });

    test('getTokens with whitespace-only code verifier throws error', async () => {
      const code = 'valid-auth-code';
      const redirectUri = 'https://app.example.com/callback';

      try {
        await wristbandService.getTokens(code, redirectUri, '   ');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Code verifier is required');
      }
    });

    test('refreshToken with empty refresh token throws error', async () => {
      try {
        await wristbandService.refreshToken('');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Refresh token is required');
      }
    });

    test('refreshToken with null refresh token throws error', async () => {
      try {
        await wristbandService.refreshToken(null as any);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Refresh token is required');
      }
    });

    test('refreshToken with whitespace-only refresh token throws error', async () => {
      try {
        await wristbandService.refreshToken('   ');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Refresh token is required');
      }
    });

    test('getUserInfo with empty access token throws error', async () => {
      try {
        await wristbandService.getUserInfo('');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Access token is required');
      }
    });

    test('getUserInfo with null access token throws error', async () => {
      try {
        await wristbandService.getUserInfo(null as any);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Access token is required');
      }
    });

    test('getUserInfo with whitespace-only access token throws error', async () => {
      try {
        await wristbandService.getUserInfo('   ');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Access token is required');
      }
    });

    test('revokeRefreshToken with empty refresh token throws error', async () => {
      try {
        await wristbandService.revokeRefreshToken('');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Refresh token is required');
      }
    });

    test('revokeRefreshToken with null refresh token throws error', async () => {
      try {
        await wristbandService.revokeRefreshToken(null as any);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Refresh token is required');
      }
    });

    test('revokeRefreshToken with whitespace-only refresh token throws error', async () => {
      try {
        await wristbandService.revokeRefreshToken('   ');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Refresh token is required');
      }
    });
  });

  describe('Token Response Validation', () => {
    test('getTokens with invalid token response (missing access_token) throws error', async () => {
      const code = 'valid-auth-code';
      const redirectUri = 'https://app.example.com/callback';
      const codeVerifier = 'valid-code-verifier';

      const invalidResponse = {
        refresh_token: 'refresh-token',
        expires_in: 3600,
        token_type: 'bearer',
        // missing access_token
      };
      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(200, invalidResponse);

      try {
        await wristbandService.getTokens(code, redirectUri, codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Invalid token response: missing access_token');
      }

      scope.done();
    });

    test('getTokens with invalid token response (missing expires_in) throws error', async () => {
      const code = 'valid-auth-code';
      const redirectUri = 'https://app.example.com/callback';
      const codeVerifier = 'valid-code-verifier';
      const invalidResponse = {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        token_type: 'bearer',
        // missing expires_in
      };
      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(200, invalidResponse);

      try {
        await wristbandService.getTokens(code, redirectUri, codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Invalid token response: missing expires_in');
      }

      scope.done();
    });

    test('getTokens with invalid token response (non-object) throws error', async () => {
      const code = 'valid-auth-code';
      const redirectUri = 'https://app.example.com/callback';
      const codeVerifier = 'valid-code-verifier';
      const invalidResponse = 'not an object';
      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(200, invalidResponse);

      try {
        await wristbandService.getTokens(code, redirectUri, codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Invalid token response');
      }

      scope.done();
    });

    test('refreshToken with invalid token response (missing access_token) throws error', async () => {
      const refreshToken = 'valid-refresh-token';
      const invalidResponse = {
        refresh_token: 'new-refresh-token',
        expires_in: 3600,
        token_type: 'bearer',
        // missing access_token
      };
      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(200, invalidResponse);

      try {
        await wristbandService.refreshToken(refreshToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Invalid token response: missing access_token');
      }

      scope.done();
    });

    test('refreshToken with invalid token response (missing expires_in) throws error', async () => {
      const refreshToken = 'valid-refresh-token';
      const invalidResponse = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        token_type: 'bearer',
        // missing expires_in
      };
      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(200, invalidResponse);

      try {
        await wristbandService.refreshToken(refreshToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Invalid token response: missing expires_in');
      }

      scope.done();
    });
  });

  describe('UserInfo Response Validation', () => {
    test('getUserInfo with invalid response (non-object) throws error', async () => {
      const accessToken = 'valid-access-token';
      const invalidResponse = 'not an object';
      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, invalidResponse);

      try {
        await wristbandService.getUserInfo(accessToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Invalid userinfo response: expected object');
      }

      scope.done();
    });

    test('getUserInfo with null response throws error', async () => {
      const accessToken = 'valid-access-token';
      // @ts-ignore
      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, null);

      try {
        await wristbandService.getUserInfo(accessToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Invalid userinfo response: expected object');
      }

      scope.done();
    });
  });

  describe('SDK Configuration Error Handling', () => {
    test('getSdkConfiguration with network error throws error', async () => {
      const scope = nock(`https://${DOMAIN}`)
        .get(`/api/v1/clients/${CLIENT_ID}/sdk-configuration`)
        .reply(500, { error: 'Internal Server Error' });

      try {
        await wristbandService.getSdkConfiguration();
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }

      scope.done();
    });

    test('getSdkConfiguration with 404 error throws error', async () => {
      const scope = nock(`https://${DOMAIN}`)
        .get(`/api/v1/clients/${CLIENT_ID}/sdk-configuration`)
        .reply(404, { error: 'Client not found' });

      try {
        await wristbandService.getSdkConfiguration();
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }

      scope.done();
    });
  });

  describe('API Error Handling', () => {
    test('getTokens with invalid grant error throws InvalidGrantError', async () => {
      const code = 'invalid-auth-code';
      const redirectUri = 'https://app.example.com/callback';
      const codeVerifier = 'valid-code-verifier';
      const errorResponse = {
        error: 'invalid_grant',
        error_description: 'The authorization code is invalid or has expired',
      };
      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(400, errorResponse);

      try {
        await wristbandService.getTokens(code, redirectUri, codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(InvalidGrantError);
        expect((error as InvalidGrantError).code).toBe('invalid_grant');
        expect((error as InvalidGrantError).errorDescription).toBe(errorResponse.error_description);
      }

      scope.done();
    });

    test('getTokens with invalid grant error (no description) throws InvalidGrantError with default message', async () => {
      const code = 'invalid-auth-code';
      const redirectUri = 'https://app.example.com/callback';
      const codeVerifier = 'valid-code-verifier';
      const errorResponse = {
        error: 'invalid_grant',
        // no error_description
      };
      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(400, errorResponse);

      try {
        await wristbandService.getTokens(code, redirectUri, codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(InvalidGrantError);
        expect((error as InvalidGrantError).code).toBe('invalid_grant');
        expect((error as InvalidGrantError).errorDescription).toBe('Invalid grant');
      }

      scope.done();
    });

    test('refreshToken with invalid token throws InvalidGrantError', async () => {
      const refreshToken = 'invalid-refresh-token';
      const errorResponse = {
        error: 'invalid_grant',
        error_description: 'The refresh token is invalid or has expired',
      };
      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(400, errorResponse);

      try {
        await wristbandService.refreshToken(refreshToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(InvalidGrantError);
        expect((error as InvalidGrantError).code).toBe('invalid_grant');
        expect((error as InvalidGrantError).errorDescription).toBe(errorResponse.error_description);
      }

      scope.done();
    });

    test('refreshToken with invalid grant error (no description) throws InvalidGrantError with default message', async () => {
      const refreshToken = 'invalid-refresh-token';
      const errorResponse = {
        error: 'invalid_grant',
        // no error_description
      };
      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(400, errorResponse);

      try {
        await wristbandService.refreshToken(refreshToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(InvalidGrantError);
        expect((error as InvalidGrantError).code).toBe('invalid_grant');
        expect((error as InvalidGrantError).errorDescription).toBe('Invalid refresh token');
      }

      scope.done();
    });

    test('getTokens with other API error throws original error', async () => {
      const code = 'valid-code';
      const redirectUri = 'https://app.example.com/callback';
      const codeVerifier = 'valid-code-verifier';
      const errorResponse = {
        error: 'unsupported_grant_type',
        error_description: 'Grant type not supported',
      };
      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(400, errorResponse);

      try {
        await wristbandService.getTokens(code, redirectUri, codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).not.toBeInstanceOf(InvalidGrantError);
        expect(error).toBeInstanceOf(Error);
      }

      scope.done();
    });

    test('getUserInfo with invalid token throws error', async () => {
      const accessToken = 'invalid-access-token';
      const errorResponse = {
        error: 'invalid_token',
        error_description: 'The access token is invalid or has expired',
      };
      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(401, errorResponse);

      try {
        await wristbandService.getUserInfo(accessToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }

      scope.done();
    });

    test('getUserInfo with forbidden response (403) throws error', async () => {
      const accessToken = 'valid-access-token';
      const errorResponse = {
        error: 'forbidden',
        error_description: 'Insufficient permissions',
      };
      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(403, errorResponse);

      try {
        await wristbandService.getUserInfo(accessToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }

      scope.done();
    });

    test('revokeRefreshToken with error throws original error', async () => {
      const refreshToken = 'valid-refresh-token';
      const errorResponse = {
        error: 'server_error',
        error_description: 'Internal server error',
      };
      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/revoke').reply(500, errorResponse);

      try {
        await wristbandService.revokeRefreshToken(refreshToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }

      scope.done();
    });

    test('Different HTTP status codes are handled appropriately', async () => {
      const accessToken = 'valid-access-token';
      const statusCodes = [400, 401, 403, 404, 500];

      for (const status of statusCodes) {
        const errorResponse = { error: 'error', error_description: `Error with status ${status}` };
        const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(status, errorResponse);

        try {
          await wristbandService.getUserInfo(accessToken);
          fail(`Expected an error to be thrown for status ${status}`);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }

        scope.done();
      }
    });
  });
});
