import { Request, Response, NextFunction } from 'express';
import { WristbandJwtValidator, createWristbandJwtValidator } from '@wristband/typescript-jwt';

import {
  createWristbandAuth,
  type AuthConfig,
  type AuthMiddlewareConfig,
  type WristbandAuth,
} from '../../../src/index';

jest.mock('@wristband/typescript-jwt');

describe('createAuthMiddleware - JWT Strategy', () => {
  let wristbandAuth: WristbandAuth;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let mockJwtValidator: jest.Mocked<WristbandJwtValidator>;

  const authConfig: AuthConfig = {
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    wristbandApplicationVanityDomain: 'auth.example.com',
  };

  beforeEach(() => {
    mockReq = {
      headers: {},
      session: undefined,
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
  });

  describe('createAuthMiddleware - JWT only', () => {
    const jwtConfig: AuthMiddlewareConfig = {
      authStrategies: ['JWT'],
    };

    it('should authenticate successfully with valid JWT', async () => {
      const middleware = wristbandAuth.createAuthMiddleware(jwtConfig);

      const mockPayload = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'Wristband',
        exp: Math.floor(Date.now() / 1000) + 3600,
      };

      mockReq.headers = { authorization: 'Bearer valid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: mockPayload });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalledWith('Bearer valid-token');
      expect(mockJwtValidator.validate).toHaveBeenCalledWith('valid-token');
      expect((mockReq as any).auth).toEqual({ ...mockPayload, jwt: 'valid-token' });
      expect(mockNext).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should return 401 when Authorization header is missing', async () => {
      const middleware = wristbandAuth.createAuthMiddleware(jwtConfig);

      mockReq.headers = {};
      mockJwtValidator.extractBearerToken.mockReturnValue(null!);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalledWith(undefined);
      expect((mockReq as any).auth).toEqual({});
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 when Authorization header is not a string', async () => {
      const middleware = wristbandAuth.createAuthMiddleware(jwtConfig);

      mockReq.headers = { authorization: ['Bearer token'] as any };
      mockJwtValidator.extractBearerToken.mockReturnValue(null!);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect((mockReq as any).auth).toEqual({});
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 when bearer token cannot be extracted', async () => {
      const middleware = wristbandAuth.createAuthMiddleware(jwtConfig);

      mockReq.headers = { authorization: 'InvalidFormat token' };
      mockJwtValidator.extractBearerToken.mockReturnValue(null!);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalledWith('InvalidFormat token');
      expect((mockReq as any).auth).toEqual({});
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 when JWT validation fails', async () => {
      const middleware = wristbandAuth.createAuthMiddleware(jwtConfig);

      mockReq.headers = { authorization: 'Bearer invalid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('invalid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: false, payload: null! });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockJwtValidator.validate).toHaveBeenCalledWith('invalid-token');
      expect((mockReq as any).auth).toEqual({});
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 500 when JWT validation throws unexpected error', async () => {
      const middleware = wristbandAuth.createAuthMiddleware(jwtConfig);

      mockReq.headers = { authorization: 'Bearer valid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockRejectedValue(new Error('Network error'));

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect((mockReq as any).auth).toEqual({});
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should attach full JWT payload to req.auth', async () => {
      const middleware = wristbandAuth.createAuthMiddleware(jwtConfig);

      const mockPayload = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'Wristband',
        email: 'user@example.com',
        roles: ['admin', 'user'],
        custom_claim: 'custom_value',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      mockReq.headers = { authorization: 'Bearer valid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: mockPayload });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect((mockReq as any).auth).toEqual({ ...mockPayload, jwt: 'valid-token' });
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle JWT with custom jwksCacheMaxSize', async () => {
      const customConfig: AuthMiddlewareConfig = {
        authStrategies: ['JWT'],
        jwtConfig: {
          jwksCacheMaxSize: 50,
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(customConfig);

      const mockPayload = { sub: 'user-123', tnt_id: 'tenant-456' };
      mockReq.headers = { authorization: 'Bearer valid-token' };

      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: mockPayload });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle JWT with custom jwksCacheTtl', async () => {
      const customConfig: AuthMiddlewareConfig = {
        authStrategies: ['JWT'],
        jwtConfig: {
          jwksCacheTtl: 60000,
        },
      };

      const middleware = wristbandAuth.createAuthMiddleware(customConfig);

      const mockPayload = { sub: 'user-123', tnt_id: 'tenant-456' };
      mockReq.headers = { authorization: 'Bearer valid-token' };

      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: mockPayload });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should initialize req.auth as empty object before authentication', async () => {
      const middleware = wristbandAuth.createAuthMiddleware(jwtConfig);

      mockReq.headers = {};
      mockJwtValidator.extractBearerToken.mockReturnValue(null!);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect((mockReq as any).auth).toBeDefined();
      expect((mockReq as any).auth).toEqual({});
    });
  });

  describe('JWT Authentication for Multiple Protected Routes', () => {
    it('should authenticate successfully for different API endpoints', async () => {
      const middleware = wristbandAuth.createAuthMiddleware({
        authStrategies: ['JWT'],
      });

      const mockPayload = { sub: 'user-123', tnt_id: 'tenant-456' };
      mockReq.headers = { authorization: 'Bearer valid-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: mockPayload });

      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
      expect((mockReq as any).auth).toEqual({ ...mockPayload, jwt: 'valid-token' });

      jest.clearAllMocks();
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: mockPayload });

      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
      expect((mockReq as any).auth).toEqual({ ...mockPayload, jwt: 'valid-token' });
    });

    it('should handle concurrent requests with same JWT', async () => {
      const middleware = wristbandAuth.createAuthMiddleware({
        authStrategies: ['JWT'],
      });

      const mockPayload = { sub: 'user-123', tnt_id: 'tenant-456' };
      const mockReq2 = { ...mockReq };
      const mockRes2 = { ...mockRes };
      const mockNext2 = jest.fn();

      mockReq.headers = { authorization: 'Bearer token1' };
      (mockReq2 as any).headers = { authorization: 'Bearer token1' };

      mockJwtValidator.extractBearerToken.mockReturnValue('token1');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: mockPayload });

      await Promise.all([
        middleware(mockReq as Request, mockRes as Response, mockNext),
        middleware(mockReq2 as Request, mockRes2 as Response, mockNext2),
      ]);

      expect(mockNext).toHaveBeenCalled();
      expect(mockNext2).toHaveBeenCalled();
    });
  });

  describe('JWT with different Authorization header formats', () => {
    it('should handle lowercase "bearer" prefix', async () => {
      const middleware = wristbandAuth.createAuthMiddleware({
        authStrategies: ['JWT'],
      });

      const mockPayload = { sub: 'user-123' };
      mockReq.headers = { authorization: 'bearer lowercase-token' };
      mockJwtValidator.extractBearerToken.mockReturnValue('lowercase-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: mockPayload });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalledWith('bearer lowercase-token');
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle Authorization header with extra whitespace', async () => {
      const middleware = wristbandAuth.createAuthMiddleware({
        authStrategies: ['JWT'],
      });

      mockReq.headers = { authorization: '  Bearer   token-with-spaces  ' };
      mockJwtValidator.extractBearerToken.mockReturnValue('token-with-spaces');
      mockJwtValidator.validate.mockResolvedValue({
        isValid: true,
        payload: { sub: 'user-123' },
      });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });
});
