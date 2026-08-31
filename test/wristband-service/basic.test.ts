import { WristbandService } from '../../src/wristband-service';
import { FetchError } from '../../src/error/fetch-error';
import { InvalidGrantError } from '../../src/error';
import {
  SdkConfiguration,
  UserInfo,
  ValidateTenantCustomDomainResponse,
  WristbandTokenResponse,
  WristbandUserinfoResponse,
} from '../../src/types';
import { JSON_MEDIA_TYPE } from '../../src/utils/constants';

const DOMAIN = 'your-wristband-domain';
const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';
const BASE_URL = `https://${DOMAIN}/api/v1`;
const EXPECTED_BASIC_AUTH = `Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`;

function mockFetch(status: number, body: unknown) {
  const bodyText = typeof body === 'string' ? body : JSON.stringify(body);
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

describe('WristbandService', () => {
  let wristbandService: WristbandService;

  beforeEach(() => {
    wristbandService = new WristbandService(DOMAIN, CLIENT_ID, CLIENT_SECRET);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Constructor', () => {
    test('Creates instance successfully', () => {
      expect(wristbandService).toBeDefined();
    });

    test('Throws when domain is missing', () => {
      expect(() => {
        return new WristbandService('', CLIENT_ID, CLIENT_SECRET);
      }).toThrow('Wristband application domain is required');
    });

    test('Throws when domain is whitespace', () => {
      expect(() => {
        return new WristbandService('   ', CLIENT_ID, CLIENT_SECRET);
      }).toThrow('Wristband application domain is required');
    });

    test('Throws when clientId is missing', () => {
      expect(() => {
        return new WristbandService(DOMAIN, '', CLIENT_SECRET);
      }).toThrow('Client ID is required');
    });

    test('Throws when clientSecret is missing', () => {
      expect(() => {
        return new WristbandService(DOMAIN, CLIENT_ID, '');
      }).toThrow('Client secret is required');
    });
  });

  describe('getSdkConfiguration', () => {
    test('Returns SDK configuration successfully', async () => {
      const expectedSdkConfig: SdkConfiguration = {
        customApplicationLoginPageUrl: 'https://custom.example.com/login',
        isApplicationCustomDomainActive: true,
        loginUrl: 'https://your-wristband-domain/login',
        loginUrlTenantDomainSuffix: '.tenant',
        redirectUri: 'https://app.example.com/callback',
      };
      mockFetch(200, expectedSdkConfig);

      const result = await wristbandService.getSdkConfiguration();

      expect(result).toEqual(expectedSdkConfig);
      expect(global.fetch).toHaveBeenCalledWith(
        `${BASE_URL}/clients/${CLIENT_ID}/sdk-configuration`,
        expect.objectContaining({ method: 'GET' })
      );
    });

    test('Sends JSON content-type and accept headers', async () => {
      mockFetch(200, {});

      await wristbandService.getSdkConfiguration();

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': JSON_MEDIA_TYPE,
            Accept: JSON_MEDIA_TYPE,
          }),
        })
      );
    });
  });

  describe('getTokens', () => {
    const code = 'valid-auth-code';
    const redirectUri = 'https://app.example.com/callback';
    const codeVerifier = 'valid-code-verifier';
    const expectedResponse: WristbandTokenResponse = {
      access_token: 'new-access-token',
      refresh_token: 'new-refresh-token',
      id_token: 'new-id-token',
      expires_in: 3600,
      token_type: 'bearer',
    };

    test('Returns token response on success', async () => {
      mockFetch(200, expectedResponse);

      const result = await wristbandService.getTokens(code, redirectUri, codeVerifier);

      expect(result).toEqual(expectedResponse);
    });

    test('Sends correct form-encoded body', async () => {
      mockFetch(200, expectedResponse);

      await wristbandService.getTokens(code, redirectUri, codeVerifier);

      const expectedBody = [
        'grant_type=authorization_code',
        `code=${code}`,
        `redirect_uri=${encodeURIComponent(redirectUri)}`,
        `code_verifier=${encodeURIComponent(codeVerifier)}`,
      ].join('&');

      expect(global.fetch).toHaveBeenCalledWith(
        `${BASE_URL}/oauth2/token`,
        expect.objectContaining({ body: expectedBody })
      );
    });

    test('Sends correct Basic auth header', async () => {
      mockFetch(200, expectedResponse);

      await wristbandService.getTokens(code, redirectUri, codeVerifier);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({ Authorization: EXPECTED_BASIC_AUTH }),
        })
      );
    });

    test('Throws InvalidGrantError on invalid_grant response', async () => {
      mockFetch(400, { error: 'invalid_grant', error_description: 'Code expired' });

      await expect(wristbandService.getTokens(code, redirectUri, codeVerifier)).rejects.toThrow(InvalidGrantError);
    });

    test('InvalidGrantError carries correct description', async () => {
      mockFetch(400, { error: 'invalid_grant', error_description: 'Code expired' });

      await expect(wristbandService.getTokens(code, redirectUri, codeVerifier)).rejects.toThrow('Code expired');
    });

    test('Rethrows non-invalid_grant FetchError', async () => {
      mockFetch(500, { error: 'server_error' });

      await expect(wristbandService.getTokens(code, redirectUri, codeVerifier)).rejects.toThrow(FetchError);
    });

    test('Throws when code is empty', async () => {
      await expect(wristbandService.getTokens('', redirectUri, codeVerifier)).rejects.toThrow(
        'Authorization code is required'
      );
    });

    test('Throws when redirectUri is empty', async () => {
      await expect(wristbandService.getTokens(code, '', codeVerifier)).rejects.toThrow('Redirect URI is required');
    });

    test('Throws when codeVerifier is empty', async () => {
      await expect(wristbandService.getTokens(code, redirectUri, '')).rejects.toThrow('Code verifier is required');
    });

    test('Rethrows non-FetchError errors', async () => {
      global.fetch = jest.fn().mockRejectedValue(new Error('Network failure'));
      await expect(wristbandService.getTokens(code, redirectUri, codeVerifier)).rejects.toThrow('Network failure');
    });
  });

  describe('getUserInfo', () => {
    const accessToken = 'valid-access-token';
    const userinfoResponse: WristbandUserinfoResponse = {
      sub: 'user123',
      app_id: 'devApp',
      tnt_id: 'tenantA',
      idp_name: 'wristband',
      email: 'test@example.com',
      email_verified: true,
      name: 'Test User',
    };
    const expectedUserInfo: UserInfo = {
      userId: 'user123',
      applicationId: 'devApp',
      tenantId: 'tenantA',
      identityProviderName: 'wristband',
      email: 'test@example.com',
      emailVerified: true,
      fullName: 'Test User',
    };

    test('Returns mapped UserInfo on success', async () => {
      mockFetch(200, userinfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result).toEqual(expectedUserInfo);
    });

    test('Sends correct Bearer auth header', async () => {
      mockFetch(200, userinfoResponse);

      await wristbandService.getUserInfo(accessToken);

      expect(global.fetch).toHaveBeenCalledWith(
        `${BASE_URL}/oauth2/userinfo`,
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': JSON_MEDIA_TYPE,
            Accept: JSON_MEDIA_TYPE,
          }),
        })
      );
    });

    test('Throws when accessToken is empty', async () => {
      await expect(wristbandService.getUserInfo('')).rejects.toThrow('Access token is required');
    });

    test('Throws TypeError when userinfo response is invalid', async () => {
      mockFetch(200, null);

      await expect(wristbandService.getUserInfo(accessToken)).rejects.toThrow(TypeError);
    });

    test('Throws TypeError when sub claim is missing', async () => {
      mockFetch(200, { ...userinfoResponse, sub: undefined });

      await expect(wristbandService.getUserInfo(accessToken)).rejects.toThrow('missing sub claim');
    });

    test('Throws TypeError when tnt_id claim is missing', async () => {
      mockFetch(200, { ...userinfoResponse, tnt_id: undefined });

      await expect(wristbandService.getUserInfo(accessToken)).rejects.toThrow('missing tnt_id claim');
    });

    test('Throws TypeError when app_id claim is missing', async () => {
      mockFetch(200, { ...userinfoResponse, app_id: undefined });

      await expect(wristbandService.getUserInfo(accessToken)).rejects.toThrow('missing app_id claim');
    });

    test('Throws TypeError when idp_name claim is missing', async () => {
      mockFetch(200, { ...userinfoResponse, idp_name: undefined });

      await expect(wristbandService.getUserInfo(accessToken)).rejects.toThrow('missing idp_name claim');
    });
  });

  describe('refreshToken', () => {
    const refreshToken = 'valid-refresh-token';
    const expectedResponse: WristbandTokenResponse = {
      access_token: 'new-access-token',
      refresh_token: 'new-refresh-token',
      id_token: 'new-id-token',
      expires_in: 3600,
      token_type: 'bearer',
    };

    test('Returns token response on success', async () => {
      mockFetch(200, expectedResponse);

      const result = await wristbandService.refreshToken(refreshToken);

      expect(result).toEqual(expectedResponse);
    });

    test('Sends correct form-encoded body', async () => {
      mockFetch(200, expectedResponse);

      await wristbandService.refreshToken(refreshToken);

      expect(global.fetch).toHaveBeenCalledWith(
        `${BASE_URL}/oauth2/token`,
        expect.objectContaining({
          body: `grant_type=refresh_token&refresh_token=${refreshToken}`,
        })
      );
    });

    test('Sends correct Basic auth header', async () => {
      mockFetch(200, expectedResponse);

      await wristbandService.refreshToken(refreshToken);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({ Authorization: EXPECTED_BASIC_AUTH }),
        })
      );
    });

    test('Throws InvalidGrantError on invalid_grant response', async () => {
      mockFetch(400, { error: 'invalid_grant', error_description: 'Refresh token expired' });

      await expect(wristbandService.refreshToken(refreshToken)).rejects.toThrow(InvalidGrantError);
    });

    test('InvalidGrantError carries correct description', async () => {
      mockFetch(400, { error: 'invalid_grant', error_description: 'Refresh token expired' });

      await expect(wristbandService.refreshToken(refreshToken)).rejects.toThrow('Refresh token expired');
    });

    test('Rethrows non-invalid_grant FetchError', async () => {
      mockFetch(500, { error: 'server_error' });

      await expect(wristbandService.refreshToken(refreshToken)).rejects.toThrow(FetchError);
    });

    test('Throws when refreshToken is empty', async () => {
      await expect(wristbandService.refreshToken('')).rejects.toThrow('Refresh token is required');
    });
  });

  describe('revokeRefreshToken', () => {
    const refreshToken = 'valid-refresh-token';

    test('Resolves successfully on 200', async () => {
      mockFetch(200, '');

      await expect(wristbandService.revokeRefreshToken(refreshToken)).resolves.toBeUndefined();
    });

    test('Sends correct form-encoded body', async () => {
      mockFetch(200, '');

      await wristbandService.revokeRefreshToken(refreshToken);

      expect(global.fetch).toHaveBeenCalledWith(
        `${BASE_URL}/oauth2/revoke`,
        expect.objectContaining({ body: `token=${refreshToken}` })
      );
    });

    test('Sends correct Basic auth header', async () => {
      mockFetch(200, '');

      await wristbandService.revokeRefreshToken(refreshToken);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({ Authorization: EXPECTED_BASIC_AUTH }),
        })
      );
    });

    test('Throws FetchError on error response', async () => {
      mockFetch(400, { error: 'bad_request' });

      await expect(wristbandService.revokeRefreshToken(refreshToken)).rejects.toThrow(FetchError);
    });

    test('Throws when refreshToken is empty', async () => {
      await expect(wristbandService.revokeRefreshToken('')).rejects.toThrow('Refresh token is required');
    });
  });

  describe('validateTenantCustomDomain', () => {
    const tenantCustomDomain = 'auth.yourapp.io';

    test('Returns true when the tenant custom domain is valid', async () => {
      const expectedResponse: ValidateTenantCustomDomainResponse = { valid: true };
      mockFetch(200, expectedResponse);

      const result = await wristbandService.validateTenantCustomDomain(tenantCustomDomain);

      expect(result).toBe(true);
    });

    test('Returns false when the tenant custom domain is invalid', async () => {
      const expectedResponse: ValidateTenantCustomDomainResponse = { valid: false };
      mockFetch(200, expectedResponse);

      const result = await wristbandService.validateTenantCustomDomain(tenantCustomDomain);

      expect(result).toBe(false);
    });

    test('Sends correct JSON body', async () => {
      mockFetch(200, { valid: true });

      await wristbandService.validateTenantCustomDomain(tenantCustomDomain);

      expect(global.fetch).toHaveBeenCalledWith(
        `${BASE_URL}/custom-domains/validate`,
        expect.objectContaining({ body: JSON.stringify({ tenantCustomDomain }) })
      );
    });

    test('Sends JSON content-type and accept headers', async () => {
      mockFetch(200, { valid: true });

      await wristbandService.validateTenantCustomDomain(tenantCustomDomain);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': JSON_MEDIA_TYPE,
            Accept: JSON_MEDIA_TYPE,
          }),
        })
      );
    });

    test('Throws FetchError on error response', async () => {
      mockFetch(400, { error: 'bad_request' });

      await expect(wristbandService.validateTenantCustomDomain(tenantCustomDomain)).rejects.toThrow(FetchError);
    });

    test('Throws when tenantCustomDomain is missing', async () => {
      await expect(wristbandService.validateTenantCustomDomain('')).rejects.toThrow('Tenant custom domain is required');
    });

    test('Throws when tenantCustomDomain is whitespace', async () => {
      await expect(wristbandService.validateTenantCustomDomain('   ')).rejects.toThrow(
        'Tenant custom domain is required'
      );
    });
  });
});
