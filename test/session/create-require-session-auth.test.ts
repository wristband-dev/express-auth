import nock from 'nock';
import { Request, Response, NextFunction } from 'express';
import { WristbandAuth } from '../../src/wristband-auth';
import { createWristbandAuth, WristbandError } from '../../src/index';

// Extend Express Request type to include session
declare module 'express' {
  interface Request {
    session?: any;
  }
}

const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const LOGIN_URL = 'http://localhost:6001/api/auth/login';
const REDIRECT_URI = 'http://localhost:6001/api/auth/callback';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2c-invotastic.dev.wristband.dev';

let wristbandAuth: WristbandAuth;

// Mock session object with all required methods and properties
const createMockSession = (overrides = {}) => {
  return {
    isAuthenticated: false,
    accessToken: undefined,
    expiresAt: undefined,
    refreshToken: undefined,
    csrfToken: undefined,
    save: jest.fn().mockResolvedValue(undefined),
    destroy: jest.fn(),
    ...overrides,
  };
};

// Mock Express request object
const createMockRequest = (overrides = {}): Partial<Request> => {
  return {
    headers: {},
    session: createMockSession(),
    ...overrides,
  };
};

// Mock Express response object
const createMockResponse = (): Partial<Response> => {
  const res: any = {
    status: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  };
  return res;
};

// Mock next function
const createMockNext = (): NextFunction => {
  return jest.fn();
};

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
  nock.cleanAll();
  jest.clearAllMocks();
});

describe('createRequireSessionAuth', () => {
  describe('Session Middleware Configuration Check', () => {
    test('Should throw error when session middleware is not configured', async () => {
      const middleware = wristbandAuth.createRequireSessionAuth();
      const req = createMockRequest({ session: undefined }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(WristbandError));
      const error = (next as jest.Mock).mock.calls[0][0];
      expect(error.getError()).toBe('SESSION_NOT_CONFIGURED');
      expect(error.getErrorDescription()).toContain('Ensure you have added the Wristband session middleware');
    });

    test('Should throw error when session.save method is missing', async () => {
      const middleware = wristbandAuth.createRequireSessionAuth();
      const req = createMockRequest({ session: { isAuthenticated: true } }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(WristbandError));
      const error = (next as jest.Mock).mock.calls[0][0];
      expect(error.getError()).toBe('SESSION_NOT_CONFIGURED');
    });
  });

  describe('Authentication Check', () => {
    test('Should return 401 when user is not authenticated', async () => {
      const middleware = wristbandAuth.createRequireSessionAuth();
      const req = createMockRequest({
        session: createMockSession({ isAuthenticated: false }),
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.send).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    test('Should return 401 when isAuthenticated is undefined', async () => {
      const middleware = wristbandAuth.createRequireSessionAuth();
      const req = createMockRequest({
        session: createMockSession({ isAuthenticated: undefined }),
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.send).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('CSRF Protection', () => {
    describe('When CSRF protection is disabled (default)', () => {
      test('Should allow request without CSRF token', async () => {
        const middleware = wristbandAuth.createRequireSessionAuth();
        const req = createMockRequest({
          session: createMockSession({ isAuthenticated: true }),
        }) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalledWith(403);
      });

      test('Should allow request even with mismatched CSRF tokens', async () => {
        const middleware = wristbandAuth.createRequireSessionAuth();
        const req = createMockRequest({
          session: createMockSession({
            isAuthenticated: true,
            csrfToken: 'session-token',
          }),
          headers: { 'x-csrf-token': 'different-token' },
        }) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalledWith(403);
      });
    });

    describe('When CSRF protection is enabled', () => {
      test('Should return 403 when CSRF token is missing in session', async () => {
        const middleware = wristbandAuth.createRequireSessionAuth({
          enableCsrfProtection: true,
        });
        const req = createMockRequest({
          session: createMockSession({
            isAuthenticated: true,
            csrfToken: undefined,
          }),
          headers: { 'x-csrf-token': 'some-token' },
        }) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await middleware(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.send).toHaveBeenCalled();
        expect(next).not.toHaveBeenCalled();
      });

      test('Should return 403 when CSRF token is missing in request header', async () => {
        const middleware = wristbandAuth.createRequireSessionAuth({
          enableCsrfProtection: true,
        });
        const req = createMockRequest({
          session: createMockSession({
            isAuthenticated: true,
            csrfToken: 'session-token',
          }),
          headers: {},
        }) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await middleware(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.send).toHaveBeenCalled();
        expect(next).not.toHaveBeenCalled();
      });

      test('Should return 403 when CSRF tokens do not match', async () => {
        const middleware = wristbandAuth.createRequireSessionAuth({
          enableCsrfProtection: true,
        });
        const req = createMockRequest({
          session: createMockSession({
            isAuthenticated: true,
            csrfToken: 'session-token',
          }),
          headers: { 'x-csrf-token': 'different-token' },
        }) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await middleware(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.send).toHaveBeenCalled();
        expect(next).not.toHaveBeenCalled();
      });

      test('Should allow request when CSRF tokens match', async () => {
        const middleware = wristbandAuth.createRequireSessionAuth({
          enableCsrfProtection: true,
        });
        const req = createMockRequest({
          session: createMockSession({
            isAuthenticated: true,
            csrfToken: 'matching-token',
          }),
          headers: { 'x-csrf-token': 'matching-token' },
        }) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
      });

      test('Should use custom CSRF header name when provided', async () => {
        const middleware = wristbandAuth.createRequireSessionAuth({
          enableCsrfProtection: true,
          csrfTokenHeaderName: 'custom-csrf-header',
        });
        const req = createMockRequest({
          session: createMockSession({
            isAuthenticated: true,
            csrfToken: 'matching-token',
          }),
          headers: { 'custom-csrf-header': 'matching-token' },
        }) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
      });

      test('Should return 403 when using wrong custom header name', async () => {
        const middleware = wristbandAuth.createRequireSessionAuth({
          enableCsrfProtection: true,
          csrfTokenHeaderName: 'custom-csrf-header',
        });
        const req = createMockRequest({
          session: createMockSession({
            isAuthenticated: true,
            csrfToken: 'matching-token',
          }),
          headers: { 'x-csrf-token': 'matching-token' }, // Wrong header name
        }) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await middleware(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.send).toHaveBeenCalled();
        expect(next).not.toHaveBeenCalled();
      });
    });
  });

  describe('Token Refresh Logic', () => {
    test('Should not attempt refresh when refreshToken is missing', async () => {
      const middleware = wristbandAuth.createRequireSessionAuth();
      const mockSave = jest.fn().mockResolvedValue(undefined);
      const req = createMockRequest({
        session: createMockSession({
          isAuthenticated: true,
          accessToken: 'access-token',
          expiresAt: Date.now() - 1000, // Expired
          refreshToken: undefined,
          save: mockSave,
        }),
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(mockSave).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
      // No HTTP calls should be made since there's no refresh token
      expect(nock.isDone()).toBe(true);
    });

    test('Should not attempt refresh when expiresAt is undefined', async () => {
      const middleware = wristbandAuth.createRequireSessionAuth();
      const mockSave = jest.fn().mockResolvedValue(undefined);
      const req = createMockRequest({
        session: createMockSession({
          isAuthenticated: true,
          accessToken: 'access-token',
          expiresAt: undefined,
          refreshToken: 'refresh-token',
          save: mockSave,
        }),
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(mockSave).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
      // No HTTP calls should be made since there's no expiresAt
      expect(nock.isDone()).toBe(true);
    });

    test('Should not refresh when token is not expired', async () => {
      const middleware = wristbandAuth.createRequireSessionAuth();
      const mockSave = jest.fn().mockResolvedValue(undefined);
      const req = createMockRequest({
        session: createMockSession({
          isAuthenticated: true,
          accessToken: 'access-token',
          expiresAt: Date.now() + 10000, // Not expired
          refreshToken: 'refresh-token',
          save: mockSave,
        }),
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(mockSave).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
      // No HTTP calls should be made since token is still valid
      expect(nock.isDone()).toBe(true);
    });

    test('Should refresh token when expired and update session', async () => {
      const mockTokens = {
        access_token: 'new-access-token',
        expires_in: 1800,
        id_token: 'new-id-token',
        refresh_token: 'new-refresh-token',
        token_type: 'bearer',
      };

      const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
        .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=old-refresh-token')
        .reply(200, mockTokens);

      const middleware = wristbandAuth.createRequireSessionAuth();
      const mockSession = createMockSession({
        isAuthenticated: true,
        accessToken: 'old-access-token',
        expiresAt: Date.now() - 1000, // Expired
        refreshToken: 'old-refresh-token',
      });
      const req = createMockRequest({ session: mockSession }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      // Check that session was updated with new tokens
      expect(req.session.accessToken).toBe('new-access-token');
      expect(req.session.refreshToken).toBe('new-refresh-token');
      expect(req.session.expiresAt).toBeGreaterThan(Date.now());
      expect(req.session.save).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
      scope.done();
    });

    test('Should return 401 when token refresh fails', async () => {
      const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
        .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=invalid-token')
        .reply(400, {
          error: 'invalid_grant',
          error_description: 'The refresh token is invalid or has expired',
        });

      const middleware = wristbandAuth.createRequireSessionAuth();
      const req = createMockRequest({
        session: createMockSession({
          isAuthenticated: true,
          accessToken: 'old-access-token',
          expiresAt: Date.now() - 1000, // Expired
          refreshToken: 'invalid-token',
        }),
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.send).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
      scope.done();
    });
  });

  describe('Session Save (Rolling Sessions)', () => {
    test('Should call session.save() to extend session expiration', async () => {
      const middleware = wristbandAuth.createRequireSessionAuth();
      const mockSave = jest.fn().mockResolvedValue(undefined);
      const req = createMockRequest({
        session: createMockSession({
          isAuthenticated: true,
          save: mockSave,
        }),
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(mockSave).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
    });

    test('Should call session.save() after successful token refresh', async () => {
      const mockTokens = {
        access_token: 'new-access-token',
        expires_in: 1800,
        id_token: 'new-id-token',
        refresh_token: 'new-refresh-token',
        token_type: 'bearer',
      };

      const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
        .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refresh-token')
        .reply(200, mockTokens);

      const middleware = wristbandAuth.createRequireSessionAuth();
      const mockSave = jest.fn().mockResolvedValue(undefined);
      const req = createMockRequest({
        session: createMockSession({
          isAuthenticated: true,
          accessToken: 'old-access-token',
          expiresAt: Date.now() - 1000,
          refreshToken: 'refresh-token',
          save: mockSave,
        }),
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(mockSave).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
      scope.done();
    });
  });

  describe('Combined Scenarios', () => {
    test('Should handle CSRF validation and token refresh together', async () => {
      const mockTokens = {
        access_token: 'new-access-token',
        expires_in: 1800,
        id_token: 'new-id-token',
        refresh_token: 'new-refresh-token',
        token_type: 'bearer',
      };

      const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
        .post('/api/v1/oauth2/token', 'grant_type=refresh_token&refresh_token=refresh-token')
        .reply(200, mockTokens);

      const middleware = wristbandAuth.createRequireSessionAuth({
        enableCsrfProtection: true,
        csrfTokenHeaderName: 'x-csrf-token',
      });

      const req = createMockRequest({
        session: createMockSession({
          isAuthenticated: true,
          accessToken: 'old-access-token',
          expiresAt: Date.now() - 1000,
          refreshToken: 'refresh-token',
          csrfToken: 'valid-csrf-token',
        }),
        headers: { 'x-csrf-token': 'valid-csrf-token' },
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(req.session.accessToken).toBe('new-access-token');
      expect(req.session.save).toHaveBeenCalled();
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
      scope.done();
    });

    test('Should fail CSRF validation before attempting token refresh', async () => {
      const middleware = wristbandAuth.createRequireSessionAuth({
        enableCsrfProtection: true,
      });

      const req = createMockRequest({
        session: createMockSession({
          isAuthenticated: true,
          accessToken: 'old-access-token',
          expiresAt: Date.now() - 1000, // Expired - would trigger refresh
          refreshToken: 'refresh-token',
          csrfToken: 'valid-csrf-token',
        }),
        headers: { 'x-csrf-token': 'invalid-csrf-token' }, // Wrong CSRF token
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      // Should fail on CSRF before attempting token refresh
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
      // No HTTP calls should be made
      expect(nock.isDone()).toBe(true);
    });
  });

  describe('Error Handling', () => {
    test('Should handle session.save() errors', async () => {
      const middleware = wristbandAuth.createRequireSessionAuth();
      const mockSave = jest.fn().mockRejectedValue(new Error('Save failed'));
      const req = createMockRequest({
        session: createMockSession({
          isAuthenticated: true,
          save: mockSave,
        }),
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(mockSave).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.send).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    test('Should handle token refresh network errors', async () => {
      const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
        .post('/api/v1/oauth2/token')
        .replyWithError('Network error');

      const middleware = wristbandAuth.createRequireSessionAuth();
      const req = createMockRequest({
        session: createMockSession({
          isAuthenticated: true,
          accessToken: 'old-access-token',
          expiresAt: Date.now() - 1000,
          refreshToken: 'refresh-token',
        }),
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.send).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
      scope.done();
    });
  });

  describe('Configuration Defaults', () => {
    test('Should use default CSRF settings when not provided', async () => {
      const middleware = wristbandAuth.createRequireSessionAuth();
      const req = createMockRequest({
        session: createMockSession({ isAuthenticated: true }),
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      // Default is CSRF disabled, so should succeed
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test('Should accept empty config object', async () => {
      const middleware = wristbandAuth.createRequireSessionAuth({});
      const req = createMockRequest({
        session: createMockSession({ isAuthenticated: true }),
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });
  });
});
