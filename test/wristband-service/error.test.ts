import { WristbandService } from '../../src/wristband-service';
import { FetchError } from '../../src/error/fetch-error';
import { InvalidGrantError } from '../../src/error';

const DOMAIN = 'your-wristband-domain';
const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';

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

describe('WristbandService - Error Handling', () => {
  let wristbandService: WristbandService;

  beforeEach(() => {
    wristbandService = new WristbandService(DOMAIN, CLIENT_ID, CLIENT_SECRET);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Constructor Validation', () => {
    test('With empty domain throws error', () => {
      expect(() => {
        return new WristbandService('', CLIENT_ID, CLIENT_SECRET);
      }).toThrow('Wristband application domain is required');
    });

    test('With null domain throws error', () => {
      expect(() => {
        return new WristbandService(null as any, CLIENT_ID, CLIENT_SECRET);
      }).toThrow('Wristband application domain is required');
    });

    test('With whitespace-only domain throws error', () => {
      expect(() => {
        return new WristbandService('   ', CLIENT_ID, CLIENT_SECRET);
      }).toThrow('Wristband application domain is required');
    });

    test('With empty client ID throws error', () => {
      expect(() => {
        return new WristbandService(DOMAIN, '', CLIENT_SECRET);
      }).toThrow('Client ID is required');
    });

    test('With null client ID throws error', () => {
      expect(() => {
        return new WristbandService(DOMAIN, null as any, CLIENT_SECRET);
      }).toThrow('Client ID is required');
    });

    test('With whitespace-only client ID throws error', () => {
      expect(() => {
        return new WristbandService(DOMAIN, '   ', CLIENT_SECRET);
      }).toThrow('Client ID is required');
    });

    test('With empty client secret throws error', () => {
      expect(() => {
        return new WristbandService(DOMAIN, CLIENT_ID, '');
      }).toThrow('Client secret is required');
    });

    test('With null client secret throws error', () => {
      expect(() => {
        return new WristbandService(DOMAIN, CLIENT_ID, null as any);
      }).toThrow('Client secret is required');
    });

    test('With whitespace-only client secret throws error', () => {
      expect(() => {
        return new WristbandService(DOMAIN, CLIENT_ID, '   ');
      }).toThrow('Client secret is required');
    });
  });

  describe('Parameter Validation', () => {
    test('getTokens with empty code throws error', async () => {
      await expect(wristbandService.getTokens('', 'https://app.example.com/callback', 'verifier')).rejects.toThrow(
        'Authorization code is required'
      );
    });

    test('getTokens with null code throws error', async () => {
      await expect(
        wristbandService.getTokens(null as any, 'https://app.example.com/callback', 'verifier')
      ).rejects.toThrow('Authorization code is required');
    });

    test('getTokens with whitespace-only code throws error', async () => {
      await expect(wristbandService.getTokens('   ', 'https://app.example.com/callback', 'verifier')).rejects.toThrow(
        'Authorization code is required'
      );
    });

    test('getTokens with empty redirect URI throws error', async () => {
      await expect(wristbandService.getTokens('code', '', 'verifier')).rejects.toThrow('Redirect URI is required');
    });

    test('getTokens with null redirect URI throws error', async () => {
      await expect(wristbandService.getTokens('code', null as any, 'verifier')).rejects.toThrow(
        'Redirect URI is required'
      );
    });

    test('getTokens with whitespace-only redirect URI throws error', async () => {
      await expect(wristbandService.getTokens('code', '   ', 'verifier')).rejects.toThrow('Redirect URI is required');
    });

    test('getTokens with empty code verifier throws error', async () => {
      await expect(wristbandService.getTokens('code', 'https://app.example.com/callback', '')).rejects.toThrow(
        'Code verifier is required'
      );
    });

    test('getTokens with null code verifier throws error', async () => {
      await expect(wristbandService.getTokens('code', 'https://app.example.com/callback', null as any)).rejects.toThrow(
        'Code verifier is required'
      );
    });

    test('getTokens with whitespace-only code verifier throws error', async () => {
      await expect(wristbandService.getTokens('code', 'https://app.example.com/callback', '   ')).rejects.toThrow(
        'Code verifier is required'
      );
    });

    test('refreshToken with empty refresh token throws error', async () => {
      await expect(wristbandService.refreshToken('')).rejects.toThrow('Refresh token is required');
    });

    test('refreshToken with null refresh token throws error', async () => {
      await expect(wristbandService.refreshToken(null as any)).rejects.toThrow('Refresh token is required');
    });

    test('refreshToken with whitespace-only refresh token throws error', async () => {
      await expect(wristbandService.refreshToken('   ')).rejects.toThrow('Refresh token is required');
    });

    test('getUserInfo with empty access token throws error', async () => {
      await expect(wristbandService.getUserInfo('')).rejects.toThrow('Access token is required');
    });

    test('getUserInfo with null access token throws error', async () => {
      await expect(wristbandService.getUserInfo(null as any)).rejects.toThrow('Access token is required');
    });

    test('getUserInfo with whitespace-only access token throws error', async () => {
      await expect(wristbandService.getUserInfo('   ')).rejects.toThrow('Access token is required');
    });

    test('revokeRefreshToken with empty refresh token throws error', async () => {
      await expect(wristbandService.revokeRefreshToken('')).rejects.toThrow('Refresh token is required');
    });

    test('revokeRefreshToken with null refresh token throws error', async () => {
      await expect(wristbandService.revokeRefreshToken(null as any)).rejects.toThrow('Refresh token is required');
    });

    test('revokeRefreshToken with whitespace-only refresh token throws error', async () => {
      await expect(wristbandService.revokeRefreshToken('   ')).rejects.toThrow('Refresh token is required');
    });
  });

  describe('UserInfo Response Validation', () => {
    test('getUserInfo with non-object response throws TypeError', async () => {
      mockFetch(200, 42);
      await expect(wristbandService.getUserInfo('valid-access-token')).rejects.toThrow(
        'Invalid userinfo response: expected object'
      );
    });

    test('getUserInfo with null response throws TypeError', async () => {
      mockFetch(200, null);
      await expect(wristbandService.getUserInfo('valid-access-token')).rejects.toThrow(
        'Invalid userinfo response: expected object'
      );
    });
  });

  describe('SDK Configuration Error Handling', () => {
    test('getSdkConfiguration with 500 response throws FetchError', async () => {
      mockFetch(500, { error: 'Internal Server Error' });
      await expect(wristbandService.getSdkConfiguration()).rejects.toThrow(FetchError);
    });

    test('getSdkConfiguration with 404 response throws FetchError', async () => {
      mockFetch(404, { error: 'Client not found' });
      await expect(wristbandService.getSdkConfiguration()).rejects.toThrow(FetchError);
    });
  });

  describe('API Error Handling', () => {
    test('getTokens with invalid_grant throws InvalidGrantError', async () => {
      const errorResponse = {
        error: 'invalid_grant',
        error_description: 'The authorization code is invalid or has expired',
      };
      mockFetch(400, errorResponse);

      const error = await wristbandService
        .getTokens('invalid-code', 'https://app.example.com/callback', 'verifier')
        .catch((e) => {
          return e;
        });
      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(error.code).toBe('invalid_grant');
      expect(error.errorDescription).toBe(errorResponse.error_description);
    });

    test('getTokens with invalid_grant and no description uses default message', async () => {
      mockFetch(400, { error: 'invalid_grant' });

      const error = await wristbandService
        .getTokens('invalid-code', 'https://app.example.com/callback', 'verifier')
        .catch((e) => {
          return e;
        });
      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(error.errorDescription).toBe('Invalid grant');
    });

    test('getTokens with non-invalid_grant error rethrows FetchError', async () => {
      mockFetch(400, { error: 'unsupported_grant_type', error_description: 'Grant type not supported' });
      await expect(wristbandService.getTokens('code', 'https://app.example.com/callback', 'verifier')).rejects.toThrow(
        FetchError
      );
    });

    test('refreshToken with invalid_grant throws InvalidGrantError', async () => {
      const errorResponse = {
        error: 'invalid_grant',
        error_description: 'The refresh token is invalid or has expired',
      };
      mockFetch(400, errorResponse);

      const error = await wristbandService.refreshToken('invalid-refresh-token').catch((e) => {
        return e;
      });
      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(error.code).toBe('invalid_grant');
      expect(error.errorDescription).toBe(errorResponse.error_description);
    });

    test('refreshToken with invalid_grant and no description uses default message', async () => {
      mockFetch(400, { error: 'invalid_grant' });

      const error = await wristbandService.refreshToken('invalid-refresh-token').catch((e) => {
        return e;
      });
      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(error.errorDescription).toBe('Invalid refresh token');
    });

    test('getTokens with other API error rethrows FetchError', async () => {
      mockFetch(400, { error: 'unsupported_grant_type' });
      await expect(
        wristbandService.getTokens('code', 'https://app.example.com/callback', 'verifier')
      ).rejects.not.toThrow(InvalidGrantError);
    });

    test('getUserInfo with 401 response throws FetchError', async () => {
      mockFetch(401, { error: 'invalid_token', error_description: 'The access token is invalid or has expired' });
      await expect(wristbandService.getUserInfo('invalid-access-token')).rejects.toThrow(FetchError);
    });

    test('getUserInfo with 403 response throws FetchError', async () => {
      mockFetch(403, { error: 'forbidden', error_description: 'Insufficient permissions' });
      await expect(wristbandService.getUserInfo('valid-access-token')).rejects.toThrow(FetchError);
    });

    test('revokeRefreshToken with 500 response throws FetchError', async () => {
      mockFetch(500, { error: 'server_error', error_description: 'Internal server error' });
      await expect(wristbandService.revokeRefreshToken('valid-refresh-token')).rejects.toThrow(FetchError);
    });

    test('Different HTTP status codes all throw FetchError', async () => {
      await Promise.all(
        [400, 401, 403, 404, 500].map((status) => {
          mockFetch(status, { error: 'error', error_description: `Error with status ${status}` });
          return expect(wristbandService.getUserInfo('valid-access-token')).rejects.toThrow(FetchError);
        })
      );
    });
  });
});
