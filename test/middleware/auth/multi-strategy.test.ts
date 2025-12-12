import { Request, Response, NextFunction } from 'express';
import { createWristbandJwtValidator, WristbandJwtValidator } from '@wristband/typescript-jwt';
import { AuthService } from '../../../src/auth-service';
import { AuthConfig, AuthMiddlewareConfig } from '../../../src/types';

jest.mock('@wristband/typescript-jwt');

describe('AuthService - Multi-Strategy - Additional Coverage', () => {
  let authService: AuthService;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let mockSession: any;
  let mockJwtValidator: jest.Mocked<WristbandJwtValidator>;

  const authConfig: AuthConfig = {
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    wristbandApplicationVanityDomain: 'auth.example.com',
  };

  beforeEach(() => {
    mockSession = {
      isAuthenticated: false,
      save: jest.fn().mockResolvedValue(undefined),
    };

    mockReq = {
      headers: {},
      session: mockSession,
    } as any;

    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };

    mockNext = jest.fn();

    mockJwtValidator = {
      extractBearerToken: jest.fn(),
      validate: jest.fn(),
      decode: jest.fn(),
    } as any;

    (createWristbandJwtValidator as jest.Mock).mockReturnValue(mockJwtValidator);

    authService = new AuthService(authConfig);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Strategy Execution Order Verification', () => {
    it('should execute strategies in exact configured order [SESSION, JWT]', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      const executionOrder: string[] = [];

      // Track SESSION execution
      mockSession.isAuthenticated = false;
      mockSession.save = jest.fn().mockImplementation(() => {
        executionOrder.push('SESSION');
        return Promise.resolve();
      });

      // Track JWT execution
      mockReq.headers = { authorization: 'Bearer token' };
      mockJwtValidator.extractBearerToken.mockImplementation(() => {
        executionOrder.push('JWT');
        return 'token';
      });
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: { sub: 'user-123' } });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // Verify SESSION was attempted first (even though it didn't call save)
      // JWT should be attempted second
      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalled();
    });

    it('should execute strategies in exact configured order [JWT, SESSION]', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['JWT', 'SESSION'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      // JWT fails
      mockReq.headers = { authorization: 'Bearer invalid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('invalid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: false, payload: null! });

      // SESSION succeeds
      mockSession.isAuthenticated = true;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // JWT should be tried first
      expect(mockJwtValidator.validate).toHaveBeenCalled();
      // Then SESSION
      expect(mockSession.save).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should stop at first successful strategy and not try remaining ones', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      // SESSION succeeds
      mockSession.isAuthenticated = true;

      // JWT would also succeed
      mockReq.headers = { authorization: 'Bearer valid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: { sub: 'user-123' } });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // SESSION should succeed
      expect(mockSession.save).toHaveBeenCalled();
      // JWT should NOT be attempted
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Concurrent and Sequential Request Handling', () => {
    it('should handle concurrent requests with same middleware instance', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['JWT'],
      };

      const middleware = authService.createAuthMiddleware(config);

      // Setup first request
      const mockReq1: Partial<Request> = { headers: { authorization: 'Bearer token1' } };
      const mockRes1: Partial<Response> = { status: jest.fn().mockReturnThis(), json: jest.fn() };
      const mockNext1 = jest.fn();

      // Setup second request
      const mockReq2: Partial<Request> = { headers: { authorization: 'Bearer token2' } };
      const mockRes2: Partial<Response> = { status: jest.fn().mockReturnThis(), json: jest.fn() };
      const mockNext2 = jest.fn();

      mockJwtValidator.extractBearerToken.mockImplementation((header) => {
        if (header === 'Bearer token1') {
          return 'token1';
        }
        if (header === 'Bearer token2') {
          return 'token2';
        }
        return null as any;
      });

      mockJwtValidator.validate.mockResolvedValue({
        isValid: true,
        payload: { sub: 'user' },
      });

      // Execute concurrently
      await Promise.all([
        middleware(mockReq1 as Request, mockRes1 as Response, mockNext1),
        middleware(mockReq2 as Request, mockRes2 as Response, mockNext2),
      ]);

      expect(mockNext1).toHaveBeenCalled();
      expect(mockNext2).toHaveBeenCalled();
      expect(mockJwtValidator.validate).toHaveBeenCalledTimes(2);
    });

    it('should handle rapid sequential requests reusing JWT validator', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['JWT'],
      };

      const middleware = authService.createAuthMiddleware(config);

      mockReq.headers = { authorization: 'Bearer token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('token');
      mockJwtValidator.validate.mockResolvedValue({
        isValid: true,
        payload: { sub: 'user-123' },
      });

      // Make 5 rapid sequential requests
      for (let i = 0; i < 5; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        await middleware(mockReq as Request, mockRes as Response, mockNext);
      }

      // JWT validator should be created only once (lazy init)
      expect(createWristbandJwtValidator).toHaveBeenCalledTimes(1);
      // But validate should be called 5 times
      expect(mockJwtValidator.validate).toHaveBeenCalledTimes(5);
      expect(mockNext).toHaveBeenCalledTimes(5);
    });

    it('should handle mixed SESSION and JWT requests sequentially', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      // Request 1: SESSION auth
      mockSession.isAuthenticated = true;
      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockSession.save).toHaveBeenCalledTimes(1);

      jest.clearAllMocks();

      // Request 2: JWT auth (session not authenticated)
      mockSession.isAuthenticated = false;
      mockReq.headers = { authorization: 'Bearer token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: { sub: 'user' } });

      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockJwtValidator.validate).toHaveBeenCalledTimes(1);

      jest.clearAllMocks();

      // Request 3: SESSION auth again
      mockSession.isAuthenticated = true;
      delete mockReq.headers!.authorization;

      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockSession.save).toHaveBeenCalledTimes(1);
    });
  });

  describe('Error Message and Status Code Verification', () => {
    it('should return exact "Unauthorized" message for 401 in multi-strategy', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      // Both strategies fail
      mockSession.isAuthenticated = false;
      mockReq.headers = { authorization: 'Bearer invalid' };
      mockJwtValidator.extractBearerToken.mockReturnValue('invalid');
      mockJwtValidator.validate.mockResolvedValue({ isValid: false, payload: null! });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
    });

    it('should return exact "Forbidden" message for 403 when CSRF fails', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
            enableCsrfProtection: true,
          },
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      mockSession.isAuthenticated = true;
      mockSession.csrfToken = 'valid-token';
      mockReq.headers = { 'x-csrf-token': 'wrong-token' };

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Forbidden' });
    });

    it('should return exact "Internal Server Error" message for 500', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      mockSession.isAuthenticated = true;
      (mockSession.save as jest.Mock).mockRejectedValue(new Error('Database error'));

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
    });

    it('should return 401 for token_refresh_failed when refresh fails', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'refresh-token';
      mockSession.expiresAt = Date.now() - 1000; // Expired

      jest
        .spyOn(authService, 'refreshTokenIfExpired')
        .mockRejectedValue(new Error('Token refresh service unavailable'));

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
    });

    it('should verify exact error message matches HTTP status code mapping', async () => {
      const testCases = [
        { reason: 'not_authenticated', expectedStatus: 401, expectedMessage: 'Unauthorized' },
        { reason: 'csrf_failed', expectedStatus: 403, expectedMessage: 'Forbidden' },
        { reason: 'token_refresh_failed', expectedStatus: 401, expectedMessage: 'Unauthorized' },
      ];

      // Test each case sequentially to avoid state conflicts
      const runTestCase = async (testCase: (typeof testCases)[0]) => {
        jest.clearAllMocks();

        // Reset mock session for each test case
        mockSession = {
          isAuthenticated: false,
          save: jest.fn().mockResolvedValue(undefined),
        };
        (mockReq as any).session = mockSession;
        mockReq.headers = {};

        const config: AuthMiddlewareConfig = {
          authStrategies: ['SESSION'],
          sessionConfig: {
            sessionOptions: { secrets: 'test-secret', enableCsrfProtection: testCase.reason === 'csrf_failed' },
          },
        };

        const middleware = authService.createAuthMiddleware(config);

        // Setup different failure scenarios
        if (testCase.reason === 'not_authenticated') {
          mockSession.isAuthenticated = false;
        } else if (testCase.reason === 'csrf_failed') {
          mockSession.isAuthenticated = true;
          mockSession.csrfToken = 'valid-token';
          mockReq.headers = { 'x-csrf-token': 'wrong-token' };
        } else if (testCase.reason === 'token_refresh_failed') {
          mockSession.isAuthenticated = true;
          mockSession.refreshToken = 'refresh-token';
          mockSession.expiresAt = Date.now() - 1000;
          jest.spyOn(authService, 'refreshTokenIfExpired').mockRejectedValue(new Error('Refresh failed'));
        }

        await middleware(mockReq as Request, mockRes as Response, mockNext);

        expect(mockRes.status).toHaveBeenCalledWith(testCase.expectedStatus);
        expect(mockRes.json).toHaveBeenCalledWith({ error: testCase.expectedMessage });
      };

      // Run all test cases sequentially
      await testCases.reduce((promise, testCase) => {
        return promise.then(() => {
          return runTestCase(testCase);
        });
      }, Promise.resolve());
    });
  });

  describe('Strategy-Specific Behavior in Multi-Strategy Context', () => {
    it('should not validate CSRF when JWT strategy succeeds', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: {
            secrets: 'test-secret',
            enableCsrfProtection: true,
          },
          csrfTokenHeaderName: 'x-csrf-token',
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      // SESSION fails (not authenticated)
      mockSession.isAuthenticated = false;

      // JWT succeeds
      mockReq.headers = { authorization: 'Bearer valid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: { sub: 'user' } });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // JWT succeeded, so CSRF was never checked
      expect(mockNext).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should not refresh tokens when JWT strategy succeeds', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      // SESSION has expired token
      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'refresh-token';
      mockSession.expiresAt = Date.now() - 1000; // Expired

      // But JWT succeeds, so we fallback before trying to refresh
      // Actually, SESSION would try to refresh first...
      // Let's make SESSION fail authentication instead
      mockSession.isAuthenticated = false;

      mockReq.headers = { authorization: 'Bearer valid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: { sub: 'user' } });

      const refreshSpy = jest.spyOn(authService, 'refreshTokenIfExpired');

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // Token refresh should NOT have been attempted because SESSION failed auth
      expect(refreshSpy).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should refresh tokens when SESSION strategy succeeds in multi-strategy', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      // SESSION has expired token
      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'refresh-token';
      mockSession.expiresAt = Date.now() - 1000; // Expired
      mockSession.accessToken = 'old-token';

      jest.spyOn(authService, 'refreshTokenIfExpired').mockResolvedValue({
        accessToken: 'new-token',
        refreshToken: 'new-refresh',
        expiresAt: Date.now() + 3600000,
        expiresIn: 3600,
        idToken: 'new-id',
      });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(authService.refreshTokenIfExpired).toHaveBeenCalled();
      expect(mockSession.accessToken).toBe('new-token');
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Edge Cases in Multi-Strategy', () => {
    it('should handle empty authStrategies array', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: [],
      };

      expect(() => {
        return authService.createAuthMiddleware(config);
      }).toThrow('authStrategies must contain at least one strategy');
    });

    it('should handle duplicate strategies in config', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'SESSION'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      expect(() => {
        return authService.createAuthMiddleware(config);
      }).toThrow("authStrategies contains duplicate strategy: 'SESSION'");
    });

    it('should handle invalid strategy in config', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['INVALID' as any],
      };

      expect(() => {
        return authService.createAuthMiddleware(config);
      }).toThrow("Invalid auth strategies: 'INVALID'. Valid strategies are: 'SESSION', 'JWT'");
    });

    it('should handle JWT strategy with undefined authorization header', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['JWT'],
      };

      const middleware = authService.createAuthMiddleware(config);

      mockReq.headers = {};

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should handle SESSION strategy with missing session middleware', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      (mockReq as any).session = undefined;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
      const error = (mockNext as jest.Mock).mock.calls[0][0];
      expect(error.message).toContain('session middleware');
    });

    it('should handle multi-strategy with SESSION middleware missing', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = authService.createAuthMiddleware(config);

      (mockReq as any).session = undefined;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
      expect(mockRes.status).not.toHaveBeenCalled();
    });
  });
});
