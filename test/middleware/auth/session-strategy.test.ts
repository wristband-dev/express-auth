import { Request, Response, NextFunction } from 'express';
import { Session } from '@wristband/typescript-session';

import { AuthService } from '../../../src/auth-service';
import { AuthConfig, AuthMiddlewareConfig, TokenData } from '../../../src/types';
import { WristbandAuthImpl } from '../../../src/wristband-auth';

describe('AuthService - SESSION Strategy - Additional Coverage', () => {
  let authService: AuthService;
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

    authService = new AuthService(authConfig);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('WristbandAuthImpl Delegation', () => {
    it('should delegate createAuthMiddleware call to AuthService', async () => {
      const wristbandAuth = new WristbandAuthImpl(authConfig);

      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(config);

      // Verify middleware works
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

      const middleware = authService.createAuthMiddleware(sessionConfig);

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
      // Verify custom fields are preserved
      expect((mockReq as any).session.userId).toBe('user-123');
      expect((mockReq as any).session.email).toBe('test@example.com');
      expect((mockReq as any).session.roles).toEqual(['admin', 'user']);
    });

    it('should handle custom session data during token refresh', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = authService.createAuthMiddleware(sessionConfig);

      const customSession = {
        isAuthenticated: true,
        csrfToken: undefined,
        refreshToken: 'refresh-token',
        expiresAt: Date.now() - 1000, // Expired
        accessToken: 'old-token',
        userId: 'user-123',
        email: 'test@example.com',
        roles: ['admin'],
        save: jest.fn().mockResolvedValue(undefined),
      };

      (mockReq as any).session = customSession as any;

      const newTokenData: TokenData = {
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        expiresAt: Date.now() + 3600000,
        expiresIn: 3600,
        idToken: 'new-id-token',
      };

      jest.spyOn(authService, 'refreshTokenIfExpired').mockResolvedValue(newTokenData);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(authService.refreshTokenIfExpired).toHaveBeenCalled();
      expect(customSession.accessToken).toBe('new-access-token');
      expect(customSession.refreshToken).toBe('new-refresh-token');
      // Custom fields should be preserved
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

      const middleware = authService.createAuthMiddleware(sessionConfig);

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

      const middleware = authService.createAuthMiddleware(sessionConfig);

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

      const middleware = authService.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      (mockSession.save as jest.Mock).mockRejectedValue(new Error('Database connection failed'));

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
    });

    it('should return "Unauthorized" for token refresh failures', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = authService.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'expired-refresh';
      mockSession.expiresAt = Date.now() - 1000;

      jest.spyOn(authService, 'refreshTokenIfExpired').mockRejectedValue(new Error('Invalid refresh token'));

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
    });
  });

  describe('Session Edge Cases', () => {
    it('should handle null refreshToken explicitly', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = authService.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = null as any;
      mockSession.expiresAt = Date.now() - 1000; // Expired

      const refreshSpy = jest.spyOn(authService, 'refreshTokenIfExpired');

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(refreshSpy).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle empty string refreshToken', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = authService.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = '' as any;
      mockSession.expiresAt = Date.now() - 1000;

      const refreshSpy = jest.spyOn(authService, 'refreshTokenIfExpired');

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // Empty string is falsy, should skip refresh
      expect(refreshSpy).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle expiresAt as 0', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = authService.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'refresh-token';
      mockSession.expiresAt = 0; // Edge case: epoch time

      const refreshSpy = jest.spyOn(authService, 'refreshTokenIfExpired');

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // 0 is falsy but should still call refresh since it's technically a timestamp
      // However, based on the code: if (refreshToken && expiresAt !== undefined)
      // 0 is defined, so it SHOULD call refresh
      expect(refreshSpy).toHaveBeenCalledWith('refresh-token', 0);
    });

    it('should handle negative expiresAt', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = authService.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'refresh-token';
      mockSession.expiresAt = -1000; // Negative timestamp

      jest.spyOn(authService, 'refreshTokenIfExpired').mockResolvedValue(null);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(authService.refreshTokenIfExpired).toHaveBeenCalledWith('refresh-token', -1000);
      expect(mockNext).toHaveBeenCalled();
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

      const middleware = authService.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.csrfToken = undefined;
      // No refresh token or expiry

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockSession.save).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should call session.save() after successful token refresh', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = authService.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'refresh-token';
      mockSession.expiresAt = Date.now() - 1000;

      const newTokenData: TokenData = {
        accessToken: 'new-token',
        refreshToken: 'new-refresh',
        expiresAt: Date.now() + 3600000,
        expiresIn: 3600,
        idToken: 'new-id',
      };

      jest.spyOn(authService, 'refreshTokenIfExpired').mockResolvedValue(newTokenData);

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

      const middleware = authService.createAuthMiddleware(sessionConfig);

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

      const middleware = authService.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.csrfToken = 'valid-token';
      mockReq.headers = { 'x-csrf-token': 'wrong-token' };

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockSession.save).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(403);
    });

    it('should NOT call session.save() when token refresh fails', async () => {
      const sessionConfig: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
          },
        },
      };

      const middleware = authService.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'expired-token';
      mockSession.expiresAt = Date.now() - 1000;

      jest.spyOn(authService, 'refreshTokenIfExpired').mockRejectedValue(new Error('Refresh failed'));

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

      const middleware = authService.createAuthMiddleware(sessionConfig);

      mockSession.isAuthenticated = true;

      // First request
      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockSession.save).toHaveBeenCalledTimes(1);

      jest.clearAllMocks();

      // Second request - same session
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

      const middleware = authService.createAuthMiddleware(sessionConfig);

      // First request - authenticated
      mockSession.isAuthenticated = true;
      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);

      jest.clearAllMocks();

      // Second request - session expired
      mockSession.isAuthenticated = false;
      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockNext).not.toHaveBeenCalled();
    });
  });
});
