import { Request, Response, NextFunction } from 'express';
import { Session, SessionData, getSessionSync } from '@wristband/typescript-session';

import { createWristbandSession } from '../../../src/session';

jest.mock('@wristband/typescript-session', () => {
  return { getSessionSync: jest.fn() };
});

const mockGetSessionSync = getSessionSync as jest.MockedFunction<typeof getSessionSync>;

const createMockSession = (): Session<SessionData> & SessionData => {
  const session: any = {
    enableDeferredMode: jest.fn(),
    flushSync: jest.fn(),
    save: jest.fn().mockResolvedValue(undefined),
    destroy: jest.fn(),

    isAuthenticated: false,
    accessToken: undefined,
    expiresAt: undefined,
    refreshToken: undefined,
    csrfToken: undefined,
    userId: undefined,
    tenantId: undefined,
    tenantName: undefined,
  };
  return session;
};

const createMockRequest = (): Partial<Request> => {
  return { headers: {}, cookies: {}, get: jest.fn() };
};

const createMockResponse = (): Partial<Response> => {
  const res: any = {
    writeHead: jest.fn(function (this: any) {
      return this;
    }),
    setHeader: jest.fn(),
    getHeader: jest.fn(),
    headersSent: false,
  };
  return res;
};

const createMockNext = (): NextFunction => {
  return jest.fn();
};

describe('createWristbandSession', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Basic Middleware Functionality', () => {
    test('Should attach session to request object', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      expect(req.session).toBeDefined();
      expect(req.session).toBe(mockSession);
      expect(next).toHaveBeenCalledWith();
      expect(next).toHaveBeenCalledTimes(1);
    });

    test('Should call getSessionSync with correct arguments', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const sessionOptions = {
        secrets: 'test-secret-key-min-32-chars-long',
        cookieName: 'custom-session',
        maxAge: 7200,
      };

      const middleware = createWristbandSession(sessionOptions);

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      expect(mockGetSessionSync).toHaveBeenCalledWith(req, res, sessionOptions);
      expect(mockGetSessionSync).toHaveBeenCalledTimes(1);
    });

    test('Should enable deferred mode on session', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      expect(mockSession.enableDeferredMode).toHaveBeenCalled();
      expect(mockSession.enableDeferredMode).toHaveBeenCalledTimes(1);
    });

    test('Should call next() to continue middleware chain', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(next).toHaveBeenCalledTimes(1);
    });
  });

  describe('Deferred Session Flush', () => {
    test('Should flush session when writeHead is called', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      // Simulate response being sent
      res.writeHead!(200, { 'Content-Type': 'application/json' });

      expect(mockSession.flushSync).toHaveBeenCalled();
      expect(mockSession.flushSync).toHaveBeenCalledTimes(1);
    });

    test('Should not flush session if headers already sent', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      res.headersSent = true; // Headers already sent
      const next = createMockNext();

      middleware(req, res, next);

      // Try to call writeHead
      res.writeHead!(200, { 'Content-Type': 'application/json' });

      expect(mockSession.flushSync).not.toHaveBeenCalled();
    });

    test('Should restore original writeHead after first call', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      // First call
      res.writeHead!(200, { 'Content-Type': 'application/json' });
      expect(mockSession.flushSync).toHaveBeenCalledTimes(1);

      // Second call - should not trigger flush again
      res.writeHead!(200, { 'Content-Type': 'application/json' });
      expect(mockSession.flushSync).toHaveBeenCalledTimes(1);
    });

    test('Should handle flushSync errors silently', () => {
      const mockSession = createMockSession();
      mockSession.flushSync = jest.fn(() => {
        throw new Error('Flush failed');
      });
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      // Should not throw even though flushSync throws
      expect(() => {
        res.writeHead!(200, { 'Content-Type': 'application/json' });
      }).not.toThrow();

      expect(mockSession.flushSync).toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    test('Should call next with error if getSessionSync throws', () => {
      const error = new Error('Session initialization failed');
      mockGetSessionSync.mockImplementation(() => {
        throw error;
      });

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      expect(next).toHaveBeenCalledWith(error);
      expect(next).toHaveBeenCalledTimes(1);
    });

    test('Should call next with error if enableDeferredMode throws', () => {
      const mockSession = createMockSession();
      const error = new Error('Deferred mode failed');
      mockSession.enableDeferredMode = jest.fn(() => {
        throw error;
      });
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      expect(next).toHaveBeenCalledWith(error);
      expect(next).toHaveBeenCalledTimes(1);
    });

    test('Should handle onHeaders listener errors silently', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;

      // Make flushSync throw in the onHeaders listener
      mockSession.flushSync = jest.fn(() => {
        throw new Error('Flush error in onHeaders');
      });

      const next = createMockNext();

      middleware(req, res, next);

      // Should not throw when writeHead is called
      expect(() => {
        res.writeHead!(200);
      }).not.toThrow();
    });
  });

  describe('Session Options', () => {
    test('Should work with minimal options (only secrets)', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      expect(req.session).toBeDefined();
      expect(next).toHaveBeenCalledWith();
    });

    test('Should pass all custom options to getSessionSync', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const customOptions = {
        secrets: 'test-secret-key-min-32-chars-long',
        cookieName: 'my-custom-session',
        domain: 'example.com',
        maxAge: 7200,
        path: '/app',
        sameSite: 'Strict' as const,
        secure: true,
        enableCsrfProtection: true,
        csrfCookieName: 'XSRF-TOKEN',
      };

      const middleware = createWristbandSession(customOptions);

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      expect(mockGetSessionSync).toHaveBeenCalledWith(req, res, customOptions);
    });

    test('Should work with array of secrets for key rotation', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const optionsWithMultipleSecrets = {
        secrets: ['new-secret-key-min-32-chars-long', 'old-secret-key-min-32-chars-long'],
      };

      const middleware = createWristbandSession(optionsWithMultipleSecrets);

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      expect(mockGetSessionSync).toHaveBeenCalledWith(req, res, optionsWithMultipleSecrets);
      expect(req.session).toBeDefined();
    });
  });

  describe('Multiple Requests', () => {
    test('Should create independent sessions for different requests', () => {
      const mockSession1 = createMockSession();
      const mockSession2 = createMockSession();

      mockGetSessionSync.mockReturnValueOnce(mockSession1).mockReturnValueOnce(mockSession2);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      // First request
      const req1 = createMockRequest() as Request;
      const res1 = createMockResponse() as Response;
      const next1 = createMockNext();

      middleware(req1, res1, next1);

      // Second request
      const req2 = createMockRequest() as Request;
      const res2 = createMockResponse() as Response;
      const next2 = createMockNext();

      middleware(req2, res2, next2);

      expect(req1.session).toBe(mockSession1);
      expect(req2.session).toBe(mockSession2);
      expect(req1.session).not.toBe(req2.session);
    });

    test('Should handle concurrent requests independently', () => {
      const mockSession1 = createMockSession();
      const mockSession2 = createMockSession();

      mockGetSessionSync.mockReturnValueOnce(mockSession1).mockReturnValueOnce(mockSession2);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      // Simulate concurrent requests
      const req1 = createMockRequest() as Request;
      const res1 = createMockResponse() as Response;
      const next1 = createMockNext();

      const req2 = createMockRequest() as Request;
      const res2 = createMockResponse() as Response;
      const next2 = createMockNext();

      middleware(req1, res1, next1);
      middleware(req2, res2, next2);

      // Trigger writeHead on both
      res1.writeHead!(200);
      res2.writeHead!(200);

      expect(mockSession1.flushSync).toHaveBeenCalledTimes(1);
      expect(mockSession2.flushSync).toHaveBeenCalledTimes(1);
    });
  });

  describe('Integration with Session Data', () => {
    test('Should allow access to session data properties', () => {
      const mockSession = createMockSession();
      mockSession.userId = 'user-123';
      mockSession.tenantId = 'tenant-456';
      mockSession.isAuthenticated = true;
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      expect(req.session.userId).toBe('user-123');
      expect(req.session.tenantId).toBe('tenant-456');
      expect(req.session.isAuthenticated).toBe(true);
    });

    test('Should allow modification of session data', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      // Modify session data
      req.session.userId = 'new-user-id';
      req.session.isAuthenticated = true;

      expect(req.session.userId).toBe('new-user-id');
      expect(req.session.isAuthenticated).toBe(true);
    });
  });

  describe('WriteHead Interception', () => {
    test('Should intercept writeHead with status code only', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      res.writeHead!(200);

      expect(mockSession.flushSync).toHaveBeenCalled();
    });

    test('Should intercept writeHead with status code and headers object', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      res.writeHead!(200, { 'Content-Type': 'application/json' });

      expect(mockSession.flushSync).toHaveBeenCalled();
    });

    test('Should intercept writeHead with status code, status message, and headers', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      res.writeHead!(200, 'OK', { 'Content-Type': 'text/plain' });

      expect(mockSession.flushSync).toHaveBeenCalled();
    });

    test('Should return response object from writeHead', () => {
      const mockSession = createMockSession();
      mockGetSessionSync.mockReturnValue(mockSession);

      const middleware = createWristbandSession({
        secrets: 'test-secret-key-min-32-chars-long',
      });

      const req = createMockRequest() as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);

      const result = res.writeHead!(200);

      expect(result).toBe(res);
    });
  });
});
