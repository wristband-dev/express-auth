/* eslint-disable import/no-extraneous-dependencies */

import nock from 'nock';
import { WristbandService } from '../../src/wristband-service';
import { TokenResponse, SdkConfiguration, Userinfo } from '../../src/types';

const DOMAIN = 'your-wristband-domain';
const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';

describe('WristbandService - Basic Functionality', () => {
  let wristbandService: WristbandService;

  beforeEach(() => {
    nock.cleanAll();
    wristbandService = new WristbandService(DOMAIN, CLIENT_ID, CLIENT_SECRET);
  });

  describe('Constructor', () => {
    test('Creates instance with correct properties', () => {
      expect(wristbandService).toBeDefined();
    });
  });

  describe('SDK Configuration', () => {
    describe('getSdkConfiguration', () => {
      test('Returns SDK configuration successfully', async () => {
        const expectedSdkConfig: SdkConfiguration = {
          customApplicationLoginPageUrl: 'https://custom.example.com/login',
          isApplicationCustomDomainActive: true,
          loginUrl: 'https://your-wristband-domain/login',
          loginUrlTenantDomainSuffix: '.tenant',
          redirectUri: 'https://app.example.com/callback',
        };

        const scope = nock(`https://${DOMAIN}`)
          .get(`/api/v1/clients/${CLIENT_ID}/sdk-configuration`)
          .reply(200, expectedSdkConfig);

        const result = await wristbandService.getSdkConfiguration();
        expect(result).toEqual(expectedSdkConfig);
        scope.done();
      });
    });
  });

  describe('Token Operations', () => {
    describe('getTokens', () => {
      test('With valid request returns token response', async () => {
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

        const result = await wristbandService.getTokens(code, redirectUri, codeVerifier);
        expect(result).toEqual(expectedResponse);
        scope.done();
      });

      test('Sends correct form parameters in request body', async () => {
        const code = 'test-code';
        const redirectUri = 'https://app.example.com/callback';
        const codeVerifier = 'test-verifier';

        const expectedResponse: TokenResponse = {
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          id_token: 'id-token',
          expires_in: 3600,
          token_type: 'bearer',
        };
        const expectedFormData = `grant_type=authorization_code&code=${code}&redirect_uri=${redirectUri}&code_verifier=${codeVerifier}`;
        const scope = nock(`https://${DOMAIN}`)
          .post('/api/v1/oauth2/token', expectedFormData)
          .reply(200, expectedResponse);

        const result = await wristbandService.getTokens(code, redirectUri, codeVerifier);
        expect(result).toEqual(expectedResponse);
        scope.done();
      });
    });

    describe('refreshToken', () => {
      test('With valid token returns token response', async () => {
        const refreshToken = 'valid-refresh-token';

        const expectedResponse: TokenResponse = {
          access_token: 'new-access-token',
          refresh_token: 'new-refresh-token',
          id_token: 'new-id-token',
          expires_in: 3600,
          token_type: 'bearer',
        };

        const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/token').reply(200, expectedResponse);

        const result = await wristbandService.refreshToken(refreshToken);
        expect(result).toEqual(expectedResponse);
        scope.done();
      });

      test('Sends correct form parameters in request body', async () => {
        const refreshToken = 'test-refresh-token';
        const expectedResponse: TokenResponse = {
          access_token: 'new-access-token',
          refresh_token: 'new-refresh-token',
          id_token: 'new-id-token',
          expires_in: 3600,
          token_type: 'bearer',
        };
        const expectedFormData = `grant_type=refresh_token&refresh_token=${refreshToken}`;

        const scope = nock(`https://${DOMAIN}`)
          .post('/api/v1/oauth2/token', expectedFormData)
          .reply(200, expectedResponse);

        const result = await wristbandService.refreshToken(refreshToken);
        expect(result).toEqual(expectedResponse);
        scope.done();
      });
    });

    describe('revokeRefreshToken', () => {
      test('With valid token succeeds', async () => {
        const refreshToken = 'valid-refresh-token';

        const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/revoke').reply(200);

        await wristbandService.revokeRefreshToken(refreshToken);
        scope.done();
      });

      test('Sends correct form parameters in request body', async () => {
        const refreshToken = 'test-refresh-token';
        const expectedFormData = `token=${refreshToken}`;

        const scope = nock(`https://${DOMAIN}`).post('/api/v1/oauth2/revoke', expectedFormData).reply(200);

        await wristbandService.revokeRefreshToken(refreshToken);
        scope.done();
      });
    });
  });

  describe('User Information', () => {
    test('getUserinfo with valid token returns userinfo', async () => {
      const accessToken = 'valid-access-token';
      const userInfoData: Userinfo = {
        sub: 'user123',
        email: 'test@example.com',
        email_verified: true,
        name: 'Test User',
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoData);

      const result = await wristbandService.getUserinfo(accessToken);

      expect(result).toEqual(userInfoData);
      scope.done();
    });

    test('getUserinfo sends correct authorization header', async () => {
      const accessToken = 'test-access-token';
      const userInfoData: Userinfo = {
        sub: 'user123',
        email: 'test@example.com',
        email_verified: true,
        name: 'Test User',
      };

      const scope = nock(`https://${DOMAIN}`)
        .get('/api/v1/oauth2/userinfo')
        .matchHeader('Authorization', `Bearer ${accessToken}`)
        .matchHeader('Content-Type', /^application\/json/)
        .matchHeader('Accept', /^application\/json/)
        .reply(200, userInfoData);

      const result = await wristbandService.getUserinfo(accessToken);
      expect(result).toEqual(userInfoData);
      scope.done();
    });
  });

  describe('Authentication', () => {
    test('getTokens uses correct basic auth headers', async () => {
      const code = 'test-code';
      const redirectUri = 'https://app.example.com/callback';
      const codeVerifier = 'test-verifier';

      const expectedResponse: TokenResponse = {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        id_token: 'id-token',
        expires_in: 3600,
        token_type: 'bearer',
      };
      const expectedAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

      const scope = nock(`https://${DOMAIN}`)
        .post('/api/v1/oauth2/token')
        .matchHeader('Authorization', `Basic ${expectedAuth}`)
        .reply(200, expectedResponse);

      const result = await wristbandService.getTokens(code, redirectUri, codeVerifier);
      expect(result).toEqual(expectedResponse);
      scope.done();
    });

    test('refreshToken uses correct basic auth headers', async () => {
      const refreshToken = 'test-refresh-token';

      const expectedResponse: TokenResponse = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        id_token: 'new-id-token',
        expires_in: 3600,
        token_type: 'bearer',
      };
      const expectedAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

      const scope = nock(`https://${DOMAIN}`)
        .post('/api/v1/oauth2/token')
        .matchHeader('Authorization', `Basic ${expectedAuth}`)
        .reply(200, expectedResponse);

      const result = await wristbandService.refreshToken(refreshToken);
      expect(result).toEqual(expectedResponse);
      scope.done();
    });

    test('revokeRefreshToken uses correct basic auth headers', async () => {
      const refreshToken = 'test-refresh-token';
      const expectedAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

      const scope = nock(`https://${DOMAIN}`)
        .post('/api/v1/oauth2/revoke')
        .matchHeader('Authorization', `Basic ${expectedAuth}`)
        .reply(200);

      await wristbandService.revokeRefreshToken(refreshToken);
      scope.done();
    });
  });
});
