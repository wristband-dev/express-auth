import { Request, Response, NextFunction } from 'express';
import { Session } from '@wristband/typescript-session';

import {
  createWristbandAuth,
  type AuthConfig,
  type AuthMiddlewareConfig,
  type WristbandAuth,
} from '../../../src/index';
import { expectTokenNotCalled, mockWristbandFetch } from '../../helpers/mock-fetch';

const MOCK_REFRESH_TOKENS = {
  access_token: 'new-access-token',
  refresh_token: 'new-refresh-token',
  expires_in: 3600,
  id_token: 'new-id-token',
  token_type: 'bearer',
};

describe('createAuthMiddleware - SESSION Strategy', () => {
  let wristbandAuth: WristbandAuth;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let mockSession: any;

  const authConfig: AuthConfig = {
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    wristbandApplicationVanityDomain: 'auth.example.com',
  };

  beforeEach(() => {
    mockSession = {
      isAuthenticated: false,
      save: jest.fn().mockResolvedValue(undefined),
      csrfToken: undefined,
      refreshToken: undefined,
      expiresAt: undefined,
      accessToken: undefined,
    } as Partial<Session> & { save: jest.Mock };

    mockReq = {
      headers: {},
      session: mockSession as Session,
    } as any;

    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };

    mockNext = jest.fn();

    wristbandAuth = createWristbandAuth(authConfig);
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  describe('Delegation', () => {
    it('should create middleware that authenticates SESSION requests', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(config);

      mockSession.isAuthenticated = true;
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Custom Session Data Types', () => {
    it('should support custom session data types with additional fields', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      const customSession = {
        isAuthenticated: true,
        csrfToken: undefined,
        userId: 'user-123',
        email: 'test@example.com',
        roles: ['admin', 'user'],
        preferences: {
          theme: 'dark' as const,
          language: 'en-US',
        },
        save: jest.fn().mockResolvedValue(undefined),
      };

      (mockReq as any).session = customSession as any;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(customSession.save).toHaveBeenCalled();
      expect((mockReq as any).session.userId).toBe('user-123');
      expect((mockReq as any).session.email).toBe('test@example.com');
      expect((mockReq as any).session.roles).toEqual(['admin', 'user']);
    });

    it('should handle custom session data during token refresh', async () => {
      mockWristbandFetch({ tokens: MOCK_REFRESH_TOKENS });

      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      const customSession = {
        isAuthenticated: true,
        csrfToken: undefined,
        refreshToken: 'refresh-token',
        expiresAt: Date.now() - 1000,
        accessToken: 'old-token',
        userId: 'user-123',
        email: 'test@example.com',
        roles: ['admin'],
        save: jest.fn().mockResolvedValue(undefined),
      };

      (mockReq as any).session = customSession as any;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(customSession.accessToken).toBe('new-access-token');
      expect(customSession.refreshToken).toBe('new-refresh-token');
      expect((mockReq as any).session.userId).toBe('user-123');
      expect((mockReq as any).session.email).toBe('test@example.com');
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Session Strategy Error Messages', () => {
    it('should return "Unauthorized" message text for 401 status', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = false;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
    });

    it('should return "Forbidden" message text for 403 status (CSRF failed)', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
            enableCsrfProtection: true,
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.csrfToken = 'valid-token';
      mockReq.headers = { 'x-csrf-token': 'wrong-token' };

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Forbidden' });
    });

    it('should return "Internal Server Error" message text for 500 status', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      (mockSession.save as jest.Mock).mockRejectedValue(new Error('Database connection failed'));

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
    });

    it('should return "Unauthorized" for token refresh failures', async () => {
      mockWristbandFetch({
        tokenStatus: 400,
        tokens: { error: 'invalid_grant', error_description: 'Invalid refresh token' },
      });

      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'expired-refresh';
      mockSession.expiresAt = Date.now() - 1000;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
    });
  });

  describe('Session Edge Cases', () => {
    it('should handle null refreshToken explicitly', async () => {
      mockWristbandFetch();

      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = null as any;
      mockSession.expiresAt = Date.now() - 1000;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expectTokenNotCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle empty string refreshToken', async () => {
      mockWristbandFetch();

      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = '' as any;
      mockSession.expiresAt = Date.now() - 1000;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expectTokenNotCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should return 401 when expiresAt is 0', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'refresh-token';
      mockSession.expiresAt = 0;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
    });

    it('should return 401 when expiresAt is negative', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'refresh-token';
      mockSession.expiresAt = -1000;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
    });
  });

  describe('Session Save Behavior', () => {
    it('should always call session.save() for rolling expiration even without refresh', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.csrfToken = undefined;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockSession.save).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should call session.save() after successful token refresh', async () => {
      mockWristbandFetch({ tokens: MOCK_REFRESH_TOKENS });

      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'refresh-token';
      mockSession.expiresAt = Date.now() - 1000;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockSession.save).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should NOT call session.save() when session is not authenticated', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = false;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockSession.save).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(401);
    });

    it('should NOT call session.save() when CSRF validation fails', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
            enableCsrfProtection: true,
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.csrfToken = 'valid-token';
      mockReq.headers = { 'x-csrf-token': 'wrong-token' };

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockSession.save).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(403);
    });

    it('should NOT call session.save() when token refresh fails', async () => {
      mockWristbandFetch({
        tokenStatus: 400,
        tokens: { error: 'invalid_grant', error_description: 'Refresh failed' },
      });

      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'expired-token';
      mockSession.expiresAt = Date.now() - 1000;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockSession.save).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(401);
    });
  });

  describe('Multiple Sequential Requests', () => {
    it('should handle multiple authenticated requests in sequence', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;

      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockSession.save).toHaveBeenCalledTimes(1);

      jest.clearAllMocks();

      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockSession.save).toHaveBeenCalledTimes(1);
    });

    it('should handle session state changes between requests', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);

      jest.clearAllMocks();

      mockSession.isAuthenticated = false;
      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockNext).not.toHaveBeenCalled();
    });
  });
});
