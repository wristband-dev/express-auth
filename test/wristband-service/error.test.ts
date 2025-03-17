/* eslint-disable import/no-extraneous-dependencies */
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
      // Act & Assert
      try {
        new WristbandService('', CLIENT_ID, CLIENT_SECRET);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Wristband application domain is required');
      }
    });

    test('With empty client ID throws error', () => {
      // Act & Assert
      try {
        new WristbandService(DOMAIN, '', CLIENT_SECRET);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Client ID is required');
      }
    });

    test('With empty client secret throws error', () => {
      // Act & Assert
      try {
        new WristbandService(DOMAIN, CLIENT_ID, '');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Client secret is required');
      }
    });
  });

  describe('Parameter Validation', () => {
    test('getTokens with empty code throws error', async () => {
      // Arrange
      const redirectUri = 'https://app.example.com/callback';
      const codeVerifier = 'valid-code-verifier';

      // Act & Assert
      try {
        await wristbandService.getTokens('', redirectUri, codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Authorization code is required');
      }
    });

    test('getTokens with empty redirect URI throws error', async () => {
      // Arrange
      const code = 'valid-auth-code';
      const codeVerifier = 'valid-code-verifier';

      // Act & Assert
      try {
        await wristbandService.getTokens(code, '', codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Redirect URI is required');
      }
    });

    test('getTokens with empty code verifier throws error', async () => {
      // Arrange
      const code = 'valid-auth-code';
      const redirectUri = 'https://app.example.com/callback';

      // Act & Assert
      try {
        await wristbandService.getTokens(code, redirectUri, '');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Code verifier is required');
      }
    });

    test('refreshToken with empty refresh token throws error', async () => {
      // Act & Assert
      try {
        await wristbandService.refreshToken('');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Refresh token is required');
      }
    });

    test('getUserinfo with empty access token throws error', async () => {
      // Act & Assert
      try {
        await wristbandService.getUserinfo('');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Access token is required');
      }
    });

    test('revokeRefreshToken with empty refresh token throws error', async () => {
      // Act & Assert
      try {
        await wristbandService.revokeRefreshToken('');
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Refresh token is required');
      }
    });
  });

  describe('API Error Handling', () => {
    test('getTokens with invalid grant error throws InvalidGrantError', async () => {
      // Arrange
      const code = 'invalid-auth-code';
      const redirectUri = 'https://app.example.com/callback';
      const codeVerifier = 'valid-code-verifier';

      const errorResponse = {
        error: 'invalid_grant',
        error_description: 'The authorization code is invalid or has expired',
      };

      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(400, errorResponse);

      // Act & Assert
      try {
        await wristbandService.getTokens(code, redirectUri, codeVerifier);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(InvalidGrantError);
        expect((error as InvalidGrantError).getError()).toBe('invalid_grant');
        expect((error as InvalidGrantError).getErrorDescription()).toBe(errorResponse.error_description);
      }

      scope.done();
    });

    test('refreshToken with invalid token throws InvalidGrantError', async () => {
      // Arrange
      const refreshToken = 'invalid-refresh-token';

      const errorResponse = {
        error: 'invalid_grant',
        error_description: 'The refresh token is invalid or has expired',
      };

      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(400, errorResponse);

      // Act & Assert
      try {
        await wristbandService.refreshToken(refreshToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(InvalidGrantError);
        expect((error as InvalidGrantError).getError()).toBe('invalid_grant');
        expect((error as InvalidGrantError).getErrorDescription()).toBe(errorResponse.error_description);
      }

      scope.done();
    });

    test('getUserinfo with invalid token throws error', async () => {
      // Arrange
      const accessToken = 'invalid-access-token';

      const errorResponse = {
        error: 'invalid_token',
        error_description: 'The access token is invalid or has expired',
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(401, errorResponse);

      // Act & Assert
      try {
        await wristbandService.getUserinfo(accessToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }

      scope.done();
    });

    test('getUserinfo with forbidden response (403) throws error', async () => {
      // Arrange
      const accessToken = 'valid-access-token';

      const errorResponse = {
        error: 'forbidden',
        error_description: 'Insufficient permissions',
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(403, errorResponse);

      // Act & Assert
      try {
        await wristbandService.getUserinfo(accessToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }

      scope.done();
    });

    test('revokeRefreshToken with error throws original error', async () => {
      // Arrange
      const refreshToken = 'valid-refresh-token';

      const errorResponse = {
        error: 'server_error',
        error_description: 'Internal server error',
      };

      const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/revoke').reply(500, errorResponse);

      // Act & Assert
      try {
        await wristbandService.revokeRefreshToken(refreshToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }

      scope.done();
    });

    test('Different HTTP status codes are handled appropriately', async () => {
      // Arrange
      const accessToken = 'valid-access-token';

      // Test different status codes
      const statusCodes = [400, 401, 403, 404, 500];

      for (const status of statusCodes) {
        // Create a mock error response
        const errorResponse = {
          error: 'error',
          error_description: `Error with status ${status}`,
        };

        const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(status, errorResponse);

        // Act & Assert
        try {
          await wristbandService.getUserinfo(accessToken);
          fail(`Expected an error to be thrown for status ${status}`);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }

        scope.done();
      }
    });
  });
});
