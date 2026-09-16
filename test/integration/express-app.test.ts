import http from 'http';
import type { AddressInfo } from 'net';
import express, { type NextFunction, type Request, type Response } from 'express';

import { createWristbandAuth, createWristbandSession, WristbandError } from '../../src/index';

/**
 * Black-box integration tests: a real Express 5 app served over a real HTTP socket and driven with fetch.
 *
 * These complement the node-mocks-http unit tests by exercising genuine Express request/response objects
 * (query parsing, Set-Cookie handling, redirects, error middleware) end to end through the
 * @wristband/typescript-auth core. Every request below is chosen so that no call to Wristband is made.
 */

const LOGIN_STATE_SECRET = 'a'.repeat(32);
const SESSION_SECRET = 'b'.repeat(32);
const sessionOptions = { secrets: SESSION_SECRET, cookieName: 'sess', secure: false };

const wristbandAuth = createWristbandAuth({
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  wristbandApplicationVanityDomain: 'auth.example.wristband.dev',
  autoConfigureEnabled: false,
  loginUrl: 'http://localhost/auth/login',
  redirectUri: 'http://localhost/auth/callback',
  loginStateSecret: LOGIN_STATE_SECRET,
  dangerouslyDisableSecureCookies: true,
});

function createApp() {
  const app = express();
  const requireSession = wristbandAuth.createAuthMiddleware({
    authStrategies: ['SESSION'],
    sessionConfig: { sessionOptions },
  });
  const requireJwt = wristbandAuth.createAuthMiddleware({ authStrategies: ['JWT'] });
  const requireEither = wristbandAuth.createAuthMiddleware({
    authStrategies: ['SESSION', 'JWT'],
    sessionConfig: { sessionOptions },
  });

  // Registered before the session middleware on purpose to exercise the session_not_configured path.
  app.get('/api/nosession', requireSession, (req: Request, res: Response) => {
    res.json({ ok: true });
  });

  app.use(createWristbandSession(sessionOptions));

  app.get('/auth/login', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const authorizeUrl = await wristbandAuth.login(req, res);
      res.redirect(authorizeUrl);
    } catch (error) {
      next(error);
    }
  });

  app.get('/auth/callback', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await wristbandAuth.callback(req, res);
      if (result.type === 'redirect_required') {
        res.redirect(result.redirectUrl);
      } else {
        res.json(result.callbackData);
      }
    } catch (error) {
      next(error);
    }
  });

  app.get('/auth/logout', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const logoutUrl = await wristbandAuth.logout(req, res, { tenantName: 'acme' });
      res.redirect(logoutUrl);
    } catch (error) {
      next(error);
    }
  });

  // Test-only route that establishes an authenticated session without talking to Wristband.
  app.get('/fake-login', async (req: Request, res: Response, next: NextFunction) => {
    try {
      req.session.isAuthenticated = true;
      req.session.userId = 'user-1';
      await req.session.save();
      res.json({ ok: true });
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/session', requireSession, (req: Request, res: Response) => {
    res.json({ ok: true, userId: req.session.userId });
  });
  app.get('/api/jwt', requireJwt, (req: Request, res: Response) => {
    res.json({ ok: true });
  });
  app.get('/api/either', requireEither, (req: Request, res: Response) => {
    res.json({ ok: true });
  });

  app.use((error: Error, req: Request, res: Response, _next: NextFunction) => {
    res.status(500).json({
      message: error.message,
      isWristbandError: error instanceof WristbandError,
      code: error instanceof WristbandError ? error.code : undefined,
    });
  });

  return app;
}

let server: http.Server;
let baseUrl: string;

function get(path: string, headers: Record<string, string> = {}): Promise<globalThis.Response> {
  return fetch(`${baseUrl}${path}`, { headers, redirect: 'manual' });
}

async function startLogin() {
  const response = await get('/auth/login?tenant_name=acme');
  const authorizeUrl = new URL(response.headers.get('location') ?? '');
  const loginCookie =
    response.headers.getSetCookie().find((cookie) => {
      return cookie.startsWith('login#');
    }) ?? '';
  return { response, authorizeUrl, loginCookie, state: authorizeUrl.searchParams.get('state') ?? '' };
}

async function establishSession(): Promise<string> {
  const response = await get('/fake-login');
  const sessionCookie = response.headers.getSetCookie().find((cookie) => {
    return cookie.startsWith('sess=');
  });
  expect(sessionCookie).toBeDefined();
  return (sessionCookie ?? '').split(';')[0];
}

beforeAll(async () => {
  server = http.createServer(createApp());
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
});

describe('Express integration (real HTTP server)', () => {
  describe('login()', () => {
    test('redirects to the tenant authorize URL with PKCE and no-store caching', async () => {
      const { response, authorizeUrl } = await startLogin();

      expect(response.status).toBe(302);
      expect(authorizeUrl.host).toBe('acme-auth.example.wristband.dev');
      expect(authorizeUrl.pathname).toBe('/api/v1/oauth2/authorize');
      expect(authorizeUrl.searchParams.get('client_id')).toBe('test-client-id');
      expect(authorizeUrl.searchParams.get('redirect_uri')).toBe('http://localhost/auth/callback');
      expect(authorizeUrl.searchParams.get('code_challenge_method')).toBe('S256');
      expect(authorizeUrl.searchParams.get('state')).toHaveLength(43);
      expect(response.headers.get('cache-control')).toBe('no-store');
      expect(response.headers.get('pragma')).toBe('no-cache');
    });

    test('sets an HttpOnly login state cookie scoped to the request state', async () => {
      const { loginCookie, state } = await startLogin();

      expect(loginCookie.startsWith(`login#${state}#`)).toBe(true);
      expect(loginCookie).toMatch(/; HttpOnly; Path=\/; Max-Age=3600; SameSite=Lax$/);
      expect(loginCookie).not.toContain('Secure');
    });

    test('redirects to the application login page when no tenant can be resolved', async () => {
      const response = await get('/auth/login');

      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe(
        'https://auth.example.wristband.dev/login?client_id=test-client-id'
      );
    });
  });

  describe('callback()', () => {
    test('redirects back to the login endpoint when the login state cookie is missing', async () => {
      const response = await get('/auth/callback?state=any-state&code=abc&tenant_name=acme');

      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe('http://localhost/auth/login?tenant_name=acme');
    });

    test('redirects back to the login endpoint when the state does not match the cookie', async () => {
      const { loginCookie } = await startLogin();

      const response = await get('/auth/callback?state=WRONG&code=abc&tenant_name=acme', {
        cookie: loginCookie.split(';')[0],
      });

      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe('http://localhost/auth/login?tenant_name=acme');
    });

    test('clears the login state cookie and redirects on login_required', async () => {
      const { loginCookie, state } = await startLogin();

      const response = await get(`/auth/callback?state=${state}&error=login_required&tenant_name=acme`, {
        cookie: loginCookie.split(';')[0],
      });

      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe('http://localhost/auth/login?tenant_name=acme');
      const cleared = response.headers.getSetCookie().find((cookie) => {
        return cookie.startsWith('login#') && cookie.includes('Max-Age=0');
      });
      expect(cleared).toBeDefined();
    });
  });

  describe('createAuthMiddleware()', () => {
    test('surfaces session_not_configured through Express error middleware', async () => {
      const response = await get('/api/nosession');
      const body = await response.json();

      expect(response.status).toBe(500);
      expect(body).toEqual({
        message: 'The Wristband session middleware must be used before any auth middleware.',
        isWristbandError: true,
        code: 'session_not_configured',
      });
    });

    test('rejects an unauthenticated session with 401 JSON', async () => {
      const response = await get('/api/session');

      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: 'Unauthorized' });
    });

    test('accepts an authenticated session and re-issues the session cookie', async () => {
      const sessionCookie = await establishSession();

      const response = await get('/api/session', { cookie: sessionCookie });

      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ ok: true, userId: 'user-1' });
      const reissued = response.headers.getSetCookie().find((cookie) => {
        return cookie.startsWith('sess=');
      });
      expect(reissued).toBeDefined();
    });

    test('rejects a JWT request with no Authorization header', async () => {
      const response = await get('/api/jwt');

      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: 'Unauthorized' });
    });

    test('rejects a JWT request whose Authorization header is not a Bearer token', async () => {
      const response = await get('/api/jwt', { authorization: 'Basic abc' });

      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: 'Unauthorized' });
    });

    test('multi-strategy accepts an authenticated session', async () => {
      const sessionCookie = await establishSession();

      const response = await get('/api/either', { cookie: sessionCookie });

      expect(response.status).toBe(200);
    });

    test('multi-strategy rejects a request with neither session nor bearer token', async () => {
      const response = await get('/api/either');

      expect(response.status).toBe(401);
    });
  });

  describe('logout()', () => {
    test('redirects to the tenant logout URL', async () => {
      const response = await get('/auth/logout');

      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe(
        'https://acme-auth.example.wristband.dev/api/v1/logout?client_id=test-client-id'
      );
    });
  });
});
