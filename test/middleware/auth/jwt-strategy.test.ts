import { Request, Response, NextFunction } from 'express';
import { WristbandJwtValidator, createWristbandJwtValidator } from '@wristband/typescript-jwt';
import { AuthService } from '../../../src/auth-service';
import { AuthConfig, AuthMiddlewareConfig } from '../../../src/types';

// Mock dependencies
jest.mock('@wristband/typescript-jwt');

describe('AuthService - JWT Strategy', () => {
  let authService: AuthService;
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

    // Mock JWT validator
    mockJwtValidator = {
      extractBearerToken: jest.fn(),
      validate: jest.fn(),
      decode: jest.fn(),
    } as any;

    // Mock the factory function to return our mock validator
    (createWristbandJwtValidator as jest.Mock).mockReturnValue(mockJwtValidator);

    authService = new AuthService(authConfig);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createAuthMiddleware - JWT only', () => {
    const jwtConfig: AuthMiddlewareConfig = {
      authStrategies: ['JWT'],
    };

    it('should authenticate successfully with valid JWT', async () => {
      const middleware = authService.createAuthMiddleware(jwtConfig);

      // Mock valid JWT
      const mockPayload = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'Wristband',
        exp: Math.floor(Date.now() / 1000) + 3600,
      };

      mockReq.headers = { authorization: 'Bearer valid-token' };
      (authService as any).jwtValidator = mockJwtValidator;
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
      const middleware = authService.createAuthMiddleware(jwtConfig);

      mockReq.headers = {};
      (authService as any).jwtValidator = mockJwtValidator;
      mockJwtValidator.extractBearerToken.mockReturnValue(null!);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalledWith(undefined);
      expect((mockReq as any).auth).toEqual({});
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 when Authorization header is not a string', async () => {
      const middleware = authService.createAuthMiddleware(jwtConfig);

      mockReq.headers = { authorization: ['Bearer token'] as any };
      (authService as any).jwtValidator = mockJwtValidator;
      mockJwtValidator.extractBearerToken.mockReturnValue(null!);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect((mockReq as any).auth).toEqual({});
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 when bearer token cannot be extracted', async () => {
      const middleware = authService.createAuthMiddleware(jwtConfig);

      mockReq.headers = { authorization: 'InvalidFormat token' };
      (authService as any).jwtValidator = mockJwtValidator;
      mockJwtValidator.extractBearerToken.mockReturnValue(null!);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalledWith('InvalidFormat token');
      expect((mockReq as any).auth).toEqual({});
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Unauthorized' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 when JWT validation fails', async () => {
      const middleware = authService.createAuthMiddleware(jwtConfig);

      mockReq.headers = { authorization: 'Bearer invalid-token' };
      (authService as any).jwtValidator = mockJwtValidator;
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
      const middleware = authService.createAuthMiddleware(jwtConfig);

      mockReq.headers = { authorization: 'Bearer valid-token' };
      (authService as any).jwtValidator = mockJwtValidator;
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockRejectedValue(new Error('Network error'));

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect((mockReq as any).auth).toEqual({});
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should attach full JWT payload to req.auth', async () => {
      const middleware = authService.createAuthMiddleware(jwtConfig);

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
      (authService as any).jwtValidator = mockJwtValidator;
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

      const middleware = authService.createAuthMiddleware(customConfig);

      const mockPayload = { sub: 'user-123', tnt_id: 'tenant-456' };
      mockReq.headers = { authorization: 'Bearer valid-token' };

      // Trigger validator initialization
      (authService as any).jwtValidator = mockJwtValidator;
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

      const middleware = authService.createAuthMiddleware(customConfig);

      const mockPayload = { sub: 'user-123', tnt_id: 'tenant-456' };
      mockReq.headers = { authorization: 'Bearer valid-token' };

      (authService as any).jwtValidator = mockJwtValidator;
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: mockPayload });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should initialize req.auth as empty object before authentication', async () => {
      const middleware = authService.createAuthMiddleware(jwtConfig);

      mockReq.headers = {};
      (authService as any).jwtValidator = mockJwtValidator;
      mockJwtValidator.extractBearerToken.mockReturnValue(null!);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // req.auth should be initialized as empty object
      expect((mockReq as any).auth).toBeDefined();
      expect((mockReq as any).auth).toEqual({});
    });
  });

  describe('JWT Authentication for Multiple Protected Routes', () => {
    it('should authenticate successfully for different API endpoints', async () => {
      const middleware = authService.createAuthMiddleware({
        authStrategies: ['JWT'],
      });

      const mockPayload = { sub: 'user-123', tnt_id: 'tenant-456' };
      mockReq.headers = { authorization: 'Bearer valid-token' };
      (authService as any).jwtValidator = mockJwtValidator;
      mockJwtValidator.extractBearerToken.mockReturnValue('valid-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: mockPayload });

      // Test first endpoint
      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
      expect((mockReq as any).auth).toEqual({ ...mockPayload, jwt: 'valid-token' });

      jest.clearAllMocks();

      // Test second endpoint - should reuse validator
      await middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
      expect((mockReq as any).auth).toEqual({ ...mockPayload, jwt: 'valid-token' });
    });

    it('should handle concurrent requests with same JWT', async () => {
      const middleware = authService.createAuthMiddleware({
        authStrategies: ['JWT'],
      });

      const mockPayload = { sub: 'user-123', tnt_id: 'tenant-456' };
      const mockReq2 = { ...mockReq };
      const mockRes2 = { ...mockRes };
      const mockNext2 = jest.fn();

      mockReq.headers = { authorization: 'Bearer token1' };
      (mockReq2 as any).headers = { authorization: 'Bearer token1' };

      (authService as any).jwtValidator = mockJwtValidator;
      mockJwtValidator.extractBearerToken.mockReturnValue('token1');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: mockPayload });

      // Concurrent requests
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
      const middleware = authService.createAuthMiddleware({
        authStrategies: ['JWT'],
      });

      const mockPayload = { sub: 'user-123' };
      mockReq.headers = { authorization: 'bearer lowercase-token' };
      (authService as any).jwtValidator = mockJwtValidator;
      mockJwtValidator.extractBearerToken.mockReturnValue('lowercase-token');
      mockJwtValidator.validate.mockResolvedValue({ isValid: true, payload: mockPayload });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockJwtValidator.extractBearerToken).toHaveBeenCalledWith('bearer lowercase-token');
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle Authorization header with extra whitespace', async () => {
      const middleware = authService.createAuthMiddleware({
        authStrategies: ['JWT'],
      });

      mockReq.headers = { authorization: '  Bearer   token-with-spaces  ' };
      (authService as any).jwtValidator = mockJwtValidator;
      mockJwtValidator.extractBearerToken.mockReturnValue('token-with-spaces');
      mockJwtValidator.validate.mockResolvedValue({
        isValid: true,
        payload: { sub: 'user-123' },
      });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('getJwtValidator - lazy initialization', () => {
    it('should create JWT validator on first call', () => {
      const jwtConfig = {
        jwksCacheMaxSize: 30,
        jwksCacheTtl: 90000,
      };

      expect((authService as any).jwtValidator).toBeUndefined();

      const validator = (authService as any).getJwtValidator(jwtConfig);

      expect(validator).toBeDefined();
      expect((authService as any).jwtValidator).toBe(validator);
      expect(createWristbandJwtValidator).toHaveBeenCalledWith({
        wristbandApplicationVanityDomain: 'auth.example.com',
        jwksCacheMaxSize: 30,
        jwksCacheTtl: 90000,
      });
    });

    it('should reuse existing JWT validator on subsequent calls', () => {
      const jwtConfig = {
        jwksCacheMaxSize: 30,
      };

      const firstValidator = (authService as any).getJwtValidator(jwtConfig);
      const secondValidator = (authService as any).getJwtValidator(jwtConfig);

      expect(firstValidator).toBe(secondValidator);
      expect(createWristbandJwtValidator).toHaveBeenCalledTimes(1);
    });

    it('should create validator with default config when no jwtConfig provided', () => {
      const jwtConfig = {};

      const validator = (authService as any).getJwtValidator(jwtConfig);

      expect(validator).toBeDefined();
      expect(createWristbandJwtValidator).toHaveBeenCalledWith({
        wristbandApplicationVanityDomain: 'auth.example.com',
        jwksCacheMaxSize: undefined,
        jwksCacheTtl: undefined,
      });
    });

    it('should create validator with wristbandApplicationVanityDomain from config', () => {
      const jwtConfig = {
        jwksCacheMaxSize: 20,
      };

      (authService as any).getJwtValidator(jwtConfig);

      expect(createWristbandJwtValidator).toHaveBeenCalledWith({
        wristbandApplicationVanityDomain: 'auth.example.com',
        jwksCacheMaxSize: 20,
        jwksCacheTtl: undefined,
      });
      expect((authService as any).jwtValidator).toBeDefined();
    });
  });
});
