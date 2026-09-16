import { Request, Response, NextFunction } from 'express';
import { createWristbandJwtValidator, WristbandJwtValidator } from '@wristband/typescript-jwt';

import {
  createWristbandAuth,
  type AuthConfig,
  type AuthMiddlewareConfig,
  type WristbandAuth,
} from '../../../src/index';
import { expectTokenNotCalled, mockWristbandFetch } from '../../helpers/mock-fetch';

jest.mock('@wristband/typescript-jwt');

const MOCK_REFRESH_TOKENS = {
  access_token: 'new-token',
  refresh_token: 'new-refresh',
  expires_in: 3600,
  id_token: 'new-id',
  token_type: 'bearer',
};

describe('createAuthMiddleware - Multi-Strategy', () => {
  let wristbandAuth: WristbandAuth;
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

    wristbandAuth = createWristbandAuth(authConfig);
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  describe('Strategy Execution Order Verification', () => {
    it('should execute strategies in exact configured order [SESSION, JWT]', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(config);

      mockSession.isAuthenticated = false;

      mockReq.headers = { authorization: 'Bearer token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: { sub: 'user-123' } });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should execute strategies in exact configured order [JWT, SESSION]', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['JWT', 'SESSION'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(config);

      mockReq.headers = { authorization: 'Bearer invalid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('invalid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: false, payload: null! });

      mockSession.isAuthenticated = true;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockJwtValidator.validate).toHaveBeenCalled();
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

      const middleware = wristbandAuth.createAuthMiddleware(config);

      mockSession.isAuthenticated = true;

      mockReq.headers = { authorization: 'Bearer valid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: { sub: 'user-123' } });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockSession.save).toHaveBeenCalled();
      expect(mockJwtValidator.extractBearerToken).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Concurrent and Sequential Request Handling', () => {
    it('should handle concurrent requests with same middleware instance', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['JWT'],
      };

      const middleware = wristbandAuth.createAuthMiddleware(config);

      const mockReq1: Partial<Request> = { headers: { authorization: 'Bearer token1' } };
      const mockRes1: Partial<Response> = { status: jest.fn().mockReturnThis(), json: jest.fn() };
      const mockNext1 = jest.fn();

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

      const middleware = wristbandAuth.createAuthMiddleware(config);

      mockReq.headers = { authorization: 'Bearer token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('token');
      mockJwtValidator.validate.mockResolvedValue({
        isValid: true,
        payload: { sub: 'user-123' },
      });

      for (let i = 0; i < 5; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        await middleware(mockReq as Request, mockRes as Response, mockNext);
      }

      expect(createWristbandJwtValidator).toHaveBeenCalledTimes(1);
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

      const middleware = wristbandAuth.createAuthMiddleware(config);

      mockSession.isAuthenticated = true;
      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockSession.save).toHaveBeenCalledTimes(1);

      jest.clearAllMocks();
      mockJwtValidator.extractBearerToken.mockReturnValue('token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: { sub: 'user' } });

      mockSession.isAuthenticated = false;
      mockReq.headers = { authorization: 'Bearer token' };

      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockJwtValidator.validate).toHaveBeenCalledTimes(1);

      jest.clearAllMocks();

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

      const middleware = wristbandAuth.createAuthMiddleware(config);

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

      const middleware = wristbandAuth.createAuthMiddleware(config);

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

      const middleware = wristbandAuth.createAuthMiddleware(config);

      mockSession.isAuthenticated = true;
      (mockSession.save as jest.Mock).mockRejectedValue(new Error('Database error'));

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
    });

    it('should return 401 for token_refresh_failed when refresh fails', async () => {
      mockWristbandFetch({
        tokenStatus: 400,
        tokens: { error: 'invalid_grant', error_description: 'Token refresh service unavailable' },
      });

      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(config);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'refresh-token';
      mockSession.expiresAt = Date.now() - 1000;

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

      const runTestCase = async (testCase: (typeof testCases)[0]) => {
        jest.clearAllMocks();

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

        const middleware = wristbandAuth.createAuthMiddleware(config);

        if (testCase.reason === 'not_authenticated') {
          mockSession.isAuthenticated = false;
        } else if (testCase.reason === 'csrf_failed') {
          mockSession.isAuthenticated = true;
          mockSession.csrfToken = 'valid-token';
          mockReq.headers = { 'x-csrf-token': 'wrong-token' };
        } else if (testCase.reason === 'token_refresh_failed') {
          mockWristbandFetch({
            tokenStatus: 400,
            tokens: { error: 'invalid_grant', error_description: 'Refresh failed' },
          });
          mockSession.isAuthenticated = true;
          mockSession.refreshToken = 'refresh-token';
          mockSession.expiresAt = Date.now() - 1000;
        }

        await middleware(mockReq as Request, mockRes as Response, mockNext);

        expect(mockRes.status).toHaveBeenCalledWith(testCase.expectedStatus);
        expect(mockRes.json).toHaveBeenCalledWith({ error: testCase.expectedMessage });
      };

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

      const middleware = wristbandAuth.createAuthMiddleware(config);

      mockSession.isAuthenticated = false;

      mockReq.headers = { authorization: 'Bearer valid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: { sub: 'user' } });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should not refresh tokens when JWT strategy succeeds', async () => {
      mockWristbandFetch();

      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(config);

      mockSession.isAuthenticated = false;
      mockSession.refreshToken = 'refresh-token';
      mockSession.expiresAt = Date.now() - 1000;

      mockReq.headers = { authorization: 'Bearer valid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: { sub: 'user' } });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expectTokenNotCalled();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should refresh tokens when SESSION strategy succeeds in multi-strategy', async () => {
      mockWristbandFetch({ tokens: MOCK_REFRESH_TOKENS });

      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION', 'JWT'],
        sessionConfig: {
          sessionOptions: { secrets: 'test-secret' },
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(config);

      mockSession.isAuthenticated = true;
      mockSession.refreshToken = 'refresh-token';
      mockSession.expiresAt = Date.now() - 1000;
      mockSession.accessToken = 'old-token';

      await middleware(mockReq as Request, mockRes as Response, mockNext);

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
        return wristbandAuth.createAuthMiddleware(config);
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
        return wristbandAuth.createAuthMiddleware(config);
      }).toThrow("authStrategies contains duplicate strategy: 'SESSION'");
    });

    it('should handle invalid strategy in config', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['INVALID' as any],
      };

      expect(() => {
        return wristbandAuth.createAuthMiddleware(config);
      }).toThrow("Invalid auth strategies: 'INVALID'. Valid strategies are: 'SESSION', 'JWT'");
    });

    it('should handle JWT strategy with undefined authorization header', async () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['JWT'],
      };

      const middleware = wristbandAuth.createAuthMiddleware(config);

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

      const middleware = wristbandAuth.createAuthMiddleware(config);

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

      const middleware = wristbandAuth.createAuthMiddleware(config);

      (mockReq as any).session = undefined;

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
      expect(mockRes.status).not.toHaveBeenCalled();
    });
  });
});
