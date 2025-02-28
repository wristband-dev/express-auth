/* eslint-disable import/no-extraneous-dependencies */

import nock from 'nock';
import { WristbandService } from '../../src/wristband-service';
import { TokenResponse } from '../../src/types';

const DOMAIN = 'your-wristband-domain';
const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';

describe('WristbandService - Basic Functionality', () => {
  let wristbandService: WristbandService;

  beforeEach(() => {
    // Clean up any previous nock interceptors
    nock.cleanAll();

    // Create service instance
    wristbandService = new WristbandService(DOMAIN, CLIENT_ID, CLIENT_SECRET);
  });

  describe('Constructor', () => {
    test('Creates instance with correct properties', () => {
      // Assert
      expect(wristbandService).toBeDefined();
    });
  });

  describe('Token Operations', () => {
    describe('getTokens', () => {
      test('With valid request returns token response', async () => {
        // Arrange
        const code = 'valid-auth-code';
        const redirectUri = 'https://app.example.com/callback';
        const codeVerifier = 'valid-code-verifier';

        const expectedResponse: TokenResponse = {
          access_token: 'new-access-token',
          refresh_token: 'new-refresh-token',
          id_token: 'new-id-token',
          expires_in: 3600,
          token_type: 'bearer',
        };

        const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(200, expectedResponse);

        // Act
        const result = await wristbandService.getTokens(code, redirectUri, codeVerifier);

        // Assert
        expect(result).toEqual(expectedResponse);
        scope.done();
      });
    });

    describe('refreshToken', () => {
      test('With valid token returns token response', async () => {
        // Arrange
        const refreshToken = 'valid-refresh-token';

        const expectedResponse: TokenResponse = {
          access_token: 'new-access-token',
          refresh_token: 'new-refresh-token',
          id_token: 'new-id-token',
          expires_in: 3600,
          token_type: 'bearer',
        };

        const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(200, expectedResponse);

        // Act
        const result = await wristbandService.refreshToken(refreshToken);

        // Assert
        expect(result).toEqual(expectedResponse);
        scope.done();
      });
    });

    describe('revokeRefreshToken', () => {
      test('With valid token succeeds', async () => {
        // Arrange
        const refreshToken = 'valid-refresh-token';

        const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/revoke').reply(200);

        // Act
        await wristbandService.revokeRefreshToken(refreshToken);

        // Assert
        scope.done();
      });
    });
  });

  describe('User Information', () => {
    test('getUserinfo with valid token returns userinfo', async () => {
      // Arrange
      const accessToken = 'valid-access-token';
      const userInfoData = {
        sub: 'user123',
        email: 'test@example.com',
        email_verified: true,
        name: 'Test User',
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoData);

      // Act
      const result = await wristbandService.getUserinfo(accessToken);

      // Assert
      expect(result).toEqual(userInfoData);
      scope.done();
    });
  });
});
