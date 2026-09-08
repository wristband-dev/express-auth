import { Response } from 'express';

import { createWristbandAuth } from '../../src/index';
import { sendAuthFailureResponse } from '../../src/utils/middleware';
import { AuthMiddlewareConfig } from '../../src/types';

const AUTH_CONFIG = {
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  wristbandApplicationVanityDomain: 'auth.example.com',
};

describe('Middleware Utils', () => {
  describe('createAuthMiddleware config validation', () => {
    const wristbandAuth = createWristbandAuth(AUTH_CONFIG);

    it('should throw when authStrategies is empty array', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: [],
      };

      expect(() => {
        return wristbandAuth.createAuthMiddleware(config);
      }).toThrow('authStrategies must contain at least one strategy');
    });

    it('should throw when authStrategies is undefined', () => {
      const config = {} as AuthMiddlewareConfig;

      expect(() => {
        return wristbandAuth.createAuthMiddleware(config);
      }).toThrow('authStrategies must contain at least one strategy');
    });

    it('should throw when authStrategies contains invalid strategy', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['INVALID' as any],
      };

      expect(() => {
        return wristbandAuth.createAuthMiddleware(config);
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
        return wristbandAuth.createAuthMiddleware(config);
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
        return wristbandAuth.createAuthMiddleware(config);
      }).toThrow("authStrategies contains duplicate strategy: 'SESSION'");
    });

    it('should throw when authStrategies contains duplicate JWT', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['JWT', 'JWT'],
      };

      expect(() => {
        return wristbandAuth.createAuthMiddleware(config);
      }).toThrow("authStrategies contains duplicate strategy: 'JWT'");
    });

    it('should throw when SESSION strategy is used without sessionConfig', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
      };

      expect(() => {
        return wristbandAuth.createAuthMiddleware(config);
      }).toThrow('sessionConfig is required when using SESSION strategy');
    });

    it('should throw when SESSION strategy is used without sessionOptions', () => {
      const config: AuthMiddlewareConfig = {
        authStrategies: ['SESSION'],
        sessionConfig: {} as any,
      };

      expect(() => {
        return wristbandAuth.createAuthMiddleware(config);
      }).toThrow('sessionConfig.sessionOptions is required when using SESSION strategy');
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
