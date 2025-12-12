import { Request, Response } from 'express';
import { normalizeAuthMiddlewareConfig, isValidCsrf, sendAuthFailureResponse } from '../../src/utils/middleware';
import { AuthMiddlewareConfig } from '../../src/types';

describe('Middleware Utils', () => {
  describe('normalizeAuthMiddlewareConfig', () => {
    describe('validation - authStrategies', () => {
      it('should throw when authStrategies is empty array', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: [],
        };

        expect(() => {
          return normalizeAuthMiddlewareConfig(config);
        }).toThrow('authStrategies must contain at least one strategy');
      });

      it('should throw when authStrategies is undefined', () => {
        const config = {} as AuthMiddlewareConfig;

        expect(() => {
          return normalizeAuthMiddlewareConfig(config);
        }).toThrow('authStrategies must contain at least one strategy');
      });

      it('should throw when authStrategies contains invalid strategy', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['INVALID' as any],
        };

        expect(() => {
          return normalizeAuthMiddlewareConfig(config);
        }).toThrow("Invalid auth strategies: 'INVALID'. Valid strategies are: 'SESSION', 'JWT'");
      });

      it('should throw when authStrategies contains multiple invalid strategies', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['INVALID1' as any, 'SESSION', 'INVALID2' as any],
          sessionConfig: {
            sessionOptions: { secrets: 'test' },
          },
        };

        expect(() => {
          return normalizeAuthMiddlewareConfig(config);
        }).toThrow("Invalid auth strategies: 'INVALID1', 'INVALID2'. Valid strategies are: 'SESSION', 'JWT'");
      });

      it('should throw when authStrategies contains duplicate SESSION', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['SESSION', 'SESSION'],
          sessionConfig: {
            sessionOptions: { secrets: 'test' },
          },
        };

        expect(() => {
          return normalizeAuthMiddlewareConfig(config);
        }).toThrow("authStrategies contains duplicate strategy: 'SESSION'");
      });

      it('should throw when authStrategies contains duplicate JWT', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['JWT', 'JWT'],
        };

        expect(() => {
          return normalizeAuthMiddlewareConfig(config);
        }).toThrow("authStrategies contains duplicate strategy: 'JWT'");
      });

      it('should throw when SESSION strategy is used without sessionConfig', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['SESSION'],
        };

        expect(() => {
          return normalizeAuthMiddlewareConfig(config);
        }).toThrow('sessionConfig is required when using SESSION strategy');
      });

      it('should throw when SESSION strategy is used without sessionOptions', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['SESSION'],
          sessionConfig: {} as any,
        };

        expect(() => {
          return normalizeAuthMiddlewareConfig(config);
        }).toThrow('sessionConfig.sessionOptions is required when using SESSION strategy');
      });
    });

    describe('normalization - SESSION only', () => {
      it('should normalize SESSION config with all fields provided', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['SESSION'],
          sessionConfig: {
            sessionOptions: {
              secrets: 'test-secret',
              enableCsrfProtection: true,
            },
            csrfTokenHeaderName: 'x-custom-csrf',
          },
        };

        const result = normalizeAuthMiddlewareConfig(config);

        expect(result).toEqual({
          authStrategies: ['SESSION'],
          sessionConfig: {
            sessionOptions: {
              secrets: 'test-secret',
              enableCsrfProtection: true,
            },
            csrfTokenHeaderName: 'x-custom-csrf',
          },
          jwtConfig: {
            jwksCacheMaxSize: undefined,
            jwksCacheTtl: undefined,
          },
        });
      });

      it('should apply default csrfTokenHeaderName when not provided', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['SESSION'],
          sessionConfig: {
            sessionOptions: { secrets: 'test-secret' },
          },
        };

        const result = normalizeAuthMiddlewareConfig(config);

        expect(result.sessionConfig.csrfTokenHeaderName).toBe('x-csrf-token');
      });

      it('should preserve full sessionOptions object', () => {
        const sessionOptions = {
          secrets: 'test-secret',
          cookieName: 'my-session',
          maxAge: 3600000,
          enableCsrfProtection: true,
          secure: true,
          httpOnly: true,
          sameSite: 'strict' as const,
        };

        const config: AuthMiddlewareConfig = {
          authStrategies: ['SESSION'],
          sessionConfig: { sessionOptions },
        };

        const result = normalizeAuthMiddlewareConfig(config);

        expect(result.sessionConfig.sessionOptions).toEqual(sessionOptions);
      });
    });

    describe('normalization - JWT only', () => {
      it('should normalize JWT config with no jwtConfig provided', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['JWT'],
        };

        const result = normalizeAuthMiddlewareConfig(config);

        expect(result).toEqual({
          authStrategies: ['JWT'],
          sessionConfig: {
            sessionOptions: undefined,
            csrfTokenHeaderName: 'x-csrf-token',
          },
          jwtConfig: {
            jwksCacheMaxSize: undefined,
            jwksCacheTtl: undefined,
          },
        });
      });

      it('should normalize JWT config with jwksCacheMaxSize', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['JWT'],
          jwtConfig: {
            jwksCacheMaxSize: 50,
          },
        };

        const result = normalizeAuthMiddlewareConfig(config);

        expect(result.jwtConfig).toEqual({
          jwksCacheMaxSize: 50,
          jwksCacheTtl: undefined,
        });
      });

      it('should normalize JWT config with jwksCacheTtl', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['JWT'],
          jwtConfig: {
            jwksCacheTtl: 60000,
          },
        };

        const result = normalizeAuthMiddlewareConfig(config);

        expect(result.jwtConfig).toEqual({
          jwksCacheMaxSize: undefined,
          jwksCacheTtl: 60000,
        });
      });

      it('should normalize JWT config with both jwks settings', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['JWT'],
          jwtConfig: {
            jwksCacheMaxSize: 100,
            jwksCacheTtl: 120000,
          },
        };

        const result = normalizeAuthMiddlewareConfig(config);

        expect(result.jwtConfig).toEqual({
          jwksCacheMaxSize: 100,
          jwksCacheTtl: 120000,
        });
      });
    });

    describe('normalization - Multi-strategy', () => {
      it('should normalize SESSION then JWT config', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['SESSION', 'JWT'],
          sessionConfig: {
            sessionOptions: { secrets: 'test-secret' },
            csrfTokenHeaderName: 'x-custom-csrf',
          },
          jwtConfig: {
            jwksCacheMaxSize: 30,
          },
        };

        const result = normalizeAuthMiddlewareConfig(config);

        expect(result).toEqual({
          authStrategies: ['SESSION', 'JWT'],
          sessionConfig: {
            sessionOptions: { secrets: 'test-secret' },
            csrfTokenHeaderName: 'x-custom-csrf',
          },
          jwtConfig: {
            jwksCacheMaxSize: 30,
            jwksCacheTtl: undefined,
          },
        });
      });

      it('should normalize JWT then SESSION config', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['JWT', 'SESSION'],
          sessionConfig: {
            sessionOptions: { secrets: 'test-secret' },
          },
          jwtConfig: {
            jwksCacheTtl: 90000,
          },
        };

        const result = normalizeAuthMiddlewareConfig(config);

        expect(result).toEqual({
          authStrategies: ['JWT', 'SESSION'],
          sessionConfig: {
            sessionOptions: { secrets: 'test-secret' },
            csrfTokenHeaderName: 'x-csrf-token',
          },
          jwtConfig: {
            jwksCacheMaxSize: undefined,
            jwksCacheTtl: 90000,
          },
        });
      });
    });

    describe('edge cases', () => {
      it('should handle sessionOptions with undefined as explicit value', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['JWT'],
          sessionConfig: {
            sessionOptions: undefined as any,
          },
        };

        const result = normalizeAuthMiddlewareConfig(config);

        expect(result.sessionConfig.sessionOptions).toBeUndefined();
      });

      it('should handle empty jwtConfig object', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['JWT'],
          jwtConfig: {},
        };

        const result = normalizeAuthMiddlewareConfig(config);

        expect(result.jwtConfig).toEqual({
          jwksCacheMaxSize: undefined,
          jwksCacheTtl: undefined,
        });
      });

      it('should handle jwksCacheMaxSize as 0', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['JWT'],
          jwtConfig: {
            jwksCacheMaxSize: 0,
          },
        };

        const result = normalizeAuthMiddlewareConfig(config);

        // 0 is falsy, so it gets converted to undefined by ||
        expect(result.jwtConfig.jwksCacheMaxSize).toBeUndefined();
      });

      it('should handle jwksCacheTtl as 0', () => {
        const config: AuthMiddlewareConfig = {
          authStrategies: ['JWT'],
          jwtConfig: {
            jwksCacheTtl: 0,
          },
        };

        const result = normalizeAuthMiddlewareConfig(config);

        // 0 is falsy, so it gets converted to undefined by ||
        expect(result.jwtConfig.jwksCacheTtl).toBeUndefined();
      });
    });
  });

  describe('isValidCsrf', () => {
    let mockReq: Partial<Request>;

    beforeEach(() => {
      mockReq = {
        headers: {},
      };
    });

    it('should return false when csrfToken is undefined', () => {
      mockReq.headers = { 'x-csrf-token': 'header-token' };

      const result = isValidCsrf(mockReq as Request, undefined, 'x-csrf-token');

      expect(result).toBe(false);
    });

    it('should return false when csrfToken is empty string', () => {
      mockReq.headers = { 'x-csrf-token': 'header-token' };

      const result = isValidCsrf(mockReq as Request, '', 'x-csrf-token');

      expect(result).toBe(false);
    });

    it('should return false when header is missing', () => {
      mockReq.headers = {};

      const result = isValidCsrf(mockReq as Request, 'session-token', 'x-csrf-token');

      expect(result).toBe(false);
    });

    it('should return false when header value is not a string', () => {
      mockReq.headers = { 'x-csrf-token': ['array-value'] as any };

      const result = isValidCsrf(mockReq as Request, 'session-token', 'x-csrf-token');

      expect(result).toBe(false);
    });

    it('should return false when header value is undefined', () => {
      mockReq.headers = { 'x-csrf-token': undefined as any };

      const result = isValidCsrf(mockReq as Request, 'session-token', 'x-csrf-token');

      expect(result).toBe(false);
    });

    it('should return false when tokens do not match', () => {
      mockReq.headers = { 'x-csrf-token': 'different-token' };

      const result = isValidCsrf(mockReq as Request, 'session-token', 'x-csrf-token');

      expect(result).toBe(false);
    });

    it('should return true when tokens match exactly', () => {
      const token = 'matching-token';
      mockReq.headers = { 'x-csrf-token': token };

      const result = isValidCsrf(mockReq as Request, token, 'x-csrf-token');

      expect(result).toBe(true);
    });

    it('should be case-sensitive for token values', () => {
      mockReq.headers = { 'x-csrf-token': 'Token' };

      const result = isValidCsrf(mockReq as Request, 'token', 'x-csrf-token');

      expect(result).toBe(false);
    });

    it('should work with custom header name', () => {
      const token = 'custom-token';
      mockReq.headers = { 'x-custom-csrf-header': token };

      const result = isValidCsrf(mockReq as Request, token, 'x-custom-csrf-header');

      expect(result).toBe(true);
    });

    it('should handle header names with different casing', () => {
      const token = 'my-token';
      mockReq.headers = { 'X-CSRF-TOKEN': token };

      // Express normalizes headers to lowercase
      const result = isValidCsrf(mockReq as Request, token, 'x-csrf-token');

      expect(result).toBe(false); // Won't match because key is uppercase
    });

    it('should handle tokens with special characters', () => {
      const token = 'token-with-special!@#$%^&*()_+={}[]|:;<>?,./~`';
      mockReq.headers = { 'x-csrf-token': token };

      const result = isValidCsrf(mockReq as Request, token, 'x-csrf-token');

      expect(result).toBe(true);
    });

    it('should handle very long token strings', () => {
      const token = 'a'.repeat(10000);
      mockReq.headers = { 'x-csrf-token': token };

      const result = isValidCsrf(mockReq as Request, token, 'x-csrf-token');

      expect(result).toBe(true);
    });

    it('should return false for whitespace-only differences', () => {
      mockReq.headers = { 'x-csrf-token': 'token ' };

      const result = isValidCsrf(mockReq as Request, 'token', 'x-csrf-token');

      expect(result).toBe(false);
    });
  });

  describe('sendAuthFailureResponse', () => {
    let mockRes: Partial<Response>;
    let statusMock: jest.Mock;
    let jsonMock: jest.Mock;

    beforeEach(() => {
      jsonMock = jest.fn();
      statusMock = jest.fn().mockReturnValue({ json: jsonMock });
      mockRes = {
        status: statusMock,
      };
    });

    it('should send 401 for not_authenticated', () => {
      sendAuthFailureResponse(mockRes as Response, 'not_authenticated');

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ error: 'Unauthorized' });
    });

    it('should send 401 for token_refresh_failed', () => {
      sendAuthFailureResponse(mockRes as Response, 'token_refresh_failed');

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ error: 'Unauthorized' });
    });

    it('should send 403 for csrf_failed', () => {
      sendAuthFailureResponse(mockRes as Response, 'csrf_failed');

      expect(statusMock).toHaveBeenCalledWith(403);
      expect(jsonMock).toHaveBeenCalledWith({ error: 'Forbidden' });
    });

    it('should send 500 for unexpected_error', () => {
      sendAuthFailureResponse(mockRes as Response, 'unexpected_error');

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({ error: 'Internal Server Error' });
    });

    it('should default to 401 for unknown reason', () => {
      sendAuthFailureResponse(mockRes as Response, 'unknown_reason' as any);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ error: 'Unauthorized' });
    });

    it('should handle multiple sequential calls', () => {
      sendAuthFailureResponse(mockRes as Response, 'not_authenticated');
      sendAuthFailureResponse(mockRes as Response, 'csrf_failed');
      sendAuthFailureResponse(mockRes as Response, 'unexpected_error');

      expect(statusMock).toHaveBeenCalledTimes(3);
      expect(jsonMock).toHaveBeenCalledTimes(3);
      expect(statusMock).toHaveBeenNthCalledWith(1, 401);
      expect(statusMock).toHaveBeenNthCalledWith(2, 403);
      expect(statusMock).toHaveBeenNthCalledWith(3, 500);
    });
  });
});
