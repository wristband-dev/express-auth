import { NextFunction, Request, Response } from 'express';
import {
  createWristbandJwtValidator,
  WristbandJwtValidatorConfig,
  WristbandJwtValidator,
} from '@wristband/typescript-jwt';
import { createWristbandAuth as createCoreAuth, WristbandAuth as CoreWristbandAuth } from '@wristband/typescript-auth';

import {
  AuthConfig,
  AuthMiddlewareConfig,
  AuthStrategy,
  AuthStrategyResult,
  CallbackResult,
  LoginConfig,
  LogoutConfig,
  NormalizedAuthMiddlewareConfig,
  TokenData,
} from './types';
import { WristbandError } from './error';
import { isValidCsrf, normalizeAuthMiddlewareConfig, sendAuthFailureResponse } from './utils/middleware';
import { parseCookies } from './utils/cookies';
import { toCoreRequest } from './utils/urls';

/**
 * Service class that handles Wristband authentication operations.
 * Login, callback, logout, and token refresh are implemented by @wristband/typescript-auth; this class adapts Express
 * requests to it and implements the Express auth middleware.
 */
export class AuthService {
  private readonly core: CoreWristbandAuth;
  private readonly wristbandApplicationVanityDomain: string;
  private jwtValidator?: WristbandJwtValidator;

  /**
   * Creates an instance of AuthService.
   *
   * @param {AuthConfig} authConfig - Configuration for Wristband authentication.
   * @param {CoreWristbandAuth} [core] - An already created core instance (used by discovery).
   */
  constructor(authConfig: AuthConfig, core?: CoreWristbandAuth) {
    this.core = core ?? createCoreAuth(authConfig);
    this.wristbandApplicationVanityDomain = authConfig.wristbandApplicationVanityDomain;
  }

  /**
   * Initiates a login request by constructing a redirect URL to Wristband's authorization endpoint.
   *
   * @param {Request} req - The Express request object.
   * @param {Response} res - The Express response object.
   * @param {LoginConfig} [config={}] - Optional configuration for the login flow.
   * @returns {Promise<string>} A Promise containing the redirect URL to Wristband's Authorize Endpoint.
   */
  async login(req: Request, res: Response, config: LoginConfig = {}): Promise<string> {
    return this.core.login(toCoreRequest(req), res, config);
  }

  /**
   * Handles the OAuth callback from Wristband, exchanging the authorization code for tokens
   * and retrieving user information.
   *
   * @param {Request} req - The Express request object containing query parameters from Wristband.
   * @param {Response} res - The Express response object.
   * @returns {Promise<CallbackResult>} A Promise containing the callback result with token data and userinfo,
   *   or a redirect URL if re-authentication is required.
   * @throws {TypeError} When required query parameters are invalid or missing.
   * @throws {WristbandError} When an error occurs during the OAuth flow.
   */
  async callback(req: Request, res: Response): Promise<CallbackResult> {
    return this.core.callback(toCoreRequest(req), res);
  }

  /**
   * Initiates logout by revoking the refresh token and constructing a redirect URL
   * to Wristband's logout endpoint.
   *
   * @param {Request} req - The Express request object.
   * @param {Response} res - The Express response object.
   * @param {LogoutConfig} [config={ tenantCustomDomain: '' }] - Optional configuration for logout.
   * @returns {Promise<string>} A Promise containing the redirect URL to Wristband's Logout Endpoint.
   * @throws {TypeError} When query parameters are invalid or state exceeds the max allowed characters.
   */
  async logout(req: Request, res: Response, config: LogoutConfig = { tenantCustomDomain: '' }): Promise<string> {
    return this.core.logout(toCoreRequest(req), res, config);
  }

  /**
   * Checks if the access token is expired and refreshes it if necessary.
   * Implements retry logic for transient failures.
   *
   * @param {string} refreshToken - The refresh token to use for obtaining a new access token.
   * @param {number} expiresAt - Unix timestamp in milliseconds when the current token expires.
   * @returns {Promise<TokenData | null>} A Promise with new token data if refresh occurred, or null if token is still valid.
   * @throws {TypeError} When refreshToken is invalid or expiresAt is missing or negative.
   * @throws {WristbandError} When token refresh fails due to invalid credentials or unexpected errors.
   */
  async refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null> {
    return this.core.refreshTokenIfExpired(refreshToken, expiresAt);
  }

  /**
   * Create middleware that ensures authenticated session using multiple strategies.
   * Supports both SESSION and JWT auth.
   *
   * Strategies are checked in order. A strategy is skipped when the request doesn't carry its credential:
   * no session cookie for SESSION, or no Authorization header for JWT. When a credential is present but
   * fails, the request is rejected right away, and later strategies aren't tried.
   *
   * @param {AuthMiddlewareConfig} config - Configuration for the auth middleware.
   * @returns {Function} Express middleware function that validates authentication.
   *
   * @example
   * ```typescript
   * // SESSION only
   * const requireAuth = authService.createAuthMiddleware({
   *   authStrategies: ['SESSION'],
   *   sessionConfig: {
   *     sessionOptions: {
   *       secrets: process.env.SESSION_SECRET!,
   *       cookieName: 'my-session',
   *       maxAge: 24 * 60 * 60, // 24 hours
   *       enableCsrfProtection: true,
   *     }
   *   }
   * });
   * app.use('/api/protected', requireAuth);
   *
   * // JWT only
   * const requireJwtAuth = authService.createAuthMiddleware({
   *   authStrategies: ['JWT']
   * });
   * app.use('/api/protected', requireJwtAuth);
   *
   * // SESSION or JWT, whichever credential the request carries
   * const requireAuth = authService.createAuthMiddleware({
   *   authStrategies: ['SESSION', 'JWT'],
   *   sessionConfig: {
   *     sessionOptions: {
   *       secrets: process.env.SESSION_SECRET!,
   *       enableCsrfProtection: true,
   *     }
   *   }
   * });
   * app.use('/api/protected', requireAuth);
   *
   * // Apply at router level
   * const protectedRouter = express.Router();
   * protectedRouter.use(requireAuth);
   * protectedRouter.get('/orders', (req, res) => { //... });
   * ```
   */
  createAuthMiddleware(
    config: AuthMiddlewareConfig
  ): (req: Request, res: Response, next: NextFunction) => Promise<void> {
    const normalizedConfig = normalizeAuthMiddlewareConfig(config);

    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      // Initialize req.auth at the very beginning regardless of strategy.
      // Cast via any (not module augmentation) since this SDK is published and consumers
      // may already type/augment Request.auth themselves - globally extending their Request
      // type from within this package would risk colliding with their own code.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).auth = {};

      // Check the auth strategies in sequential order
      for (let i = 0; i < normalizedConfig.authStrategies.length; i += 1) {
        const strategy = normalizedConfig.authStrategies[i];

        // Check if session middleware is configured
        // In Express, the session is attached to req.session by the session middleware
        if (strategy === 'SESSION' && (!req.session || typeof req.session.save !== 'function')) {
          const error = new WristbandError(
            'session_not_configured',
            'The Wristband session middleware must be used before any auth middleware.'
          );
          next(error);
          return;
        }

        // Skip to the next strategy when the request doesn't carry this strategy's credential.
        if (!this.hasCredential(req, strategy, normalizedConfig)) {
          continue;
        }

        // The credential is present, so its result is final: later strategies aren't tried.
        // eslint-disable-next-line no-await-in-loop
        const result: AuthStrategyResult = await this.tryAuthStrategy(req, strategy, normalizedConfig);
        if (!result.authenticated) {
          sendAuthFailureResponse(res, result.reason);
          return;
        }

        // Authentication succeeded - continue
        next();
        return;
      }

      // Every strategy was skipped because the request carried no credentials.
      sendAuthFailureResponse(res, 'not_authenticated');
    };
  }

  /**
   * Checks whether the request carries the credential for an auth strategy: a session cookie for SESSION,
   * or an Authorization header for JWT. Only presence is checked, not validity.
   *
   * @param req - The incoming Express request.
   * @param strategy - The auth strategy to check.
   * @param config - The fully normalized middleware configuration.
   * @returns True if the credential is present, otherwise false.
   */
  private hasCredential(req: Request, strategy: AuthStrategy, config: NormalizedAuthMiddlewareConfig): boolean {
    if (strategy === 'SESSION') {
      // Matches typescript-session's default session cookie name.
      const cookieName = config.sessionConfig.sessionOptions?.cookieName ?? 'session';
      return !!parseCookies(req)[cookieName];
    }

    if (strategy === 'JWT') {
      return !!req.headers.authorization;
    }

    return false;
  }

  /**
   * Attempts to authenticate a request using a single configured auth strategy.
   *
   * This evaluates the provided strategy in isolation and reports whether it
   * succeeded or failed with a specific reason. Normal authentication failures
   * are returned as structured results rather than thrown.
   *
   * @param req - The incoming Express request to authenticate.
   * @param strategy - The auth strategy to apply for this attempt.
   * @param config - The fully normalized middleware configuration.
   * @returns A structured result describing authentication outcome, session (if successful), strategy used, and failure reason (if failed).
   */
  private async tryAuthStrategy(
    req: Request,
    strategy: AuthStrategy,
    config: NormalizedAuthMiddlewareConfig
  ): Promise<AuthStrategyResult> {
    if (strategy === 'SESSION') {
      const { sessionOptions, csrfTokenHeaderName } = config.sessionConfig;

      try {
        const { csrfToken, expiresAt, isAuthenticated, refreshToken } = req.session;

        // Check if user has an authenticated session
        if (!isAuthenticated) {
          return { authenticated: false, reason: 'not_authenticated' };
        }

        // Validate CSRF token if protection is enabled
        if (sessionOptions?.enableCsrfProtection && !isValidCsrf(req, csrfToken, csrfTokenHeaderName)) {
          return { authenticated: false, reason: 'csrf_failed' };
        }

        // Try to refresh token if expired
        if (refreshToken && expiresAt !== undefined) {
          try {
            const tokenData = await this.refreshTokenIfExpired(refreshToken, expiresAt);
            if (tokenData) {
              req.session.accessToken = tokenData.accessToken;
              req.session.expiresAt = tokenData.expiresAt;
              req.session.refreshToken = tokenData.refreshToken;
            }
          } catch {
            return { authenticated: false, reason: 'token_refresh_failed' };
          }
        }

        // Save session (for rolling expiration)
        await req.session.save();
        return { authenticated: true, usedStrategy: 'SESSION' };
      } catch {
        return { authenticated: false, reason: 'unexpected_error' };
      }
    }

    if (strategy === 'JWT') {
      let jwtValidator;
      try {
        jwtValidator = this.getJwtValidator(config.jwtConfig);
      } catch {
        return { authenticated: false, reason: 'unexpected_error' };
      }

      let bearerToken: string;
      try {
        bearerToken = jwtValidator.extractBearerToken(req.headers.authorization);
      } catch {
        return { authenticated: false, reason: 'not_authenticated' };
      }

      if (!bearerToken) {
        return { authenticated: false, reason: 'not_authenticated' };
      }

      try {
        const validationResult = await jwtValidator.validate(bearerToken);
        const { isValid, payload } = validationResult;
        if (!isValid) {
          return { authenticated: false, reason: 'not_authenticated' };
        }

        // Attach JWT and decoded payload to req.auth. Cast via any for the same reason as
        // above: avoiding a global Request augmentation that would leak into consumer projects.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (req as any).auth = payload;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (req as any).auth.jwt = bearerToken;

        return { authenticated: true, usedStrategy: 'JWT' };
      } catch {
        return { authenticated: false, reason: 'unexpected_error' };
      }
    }

    // Should never reach here
    return { authenticated: false, reason: 'unexpected_error' };
  }

  /**
   * Lazily initializes and returns the JWT validator instance.
   * Only creates the validator on first use if JWT strategy is configured.
   */
  private getJwtValidator(
    jwtConfig: Pick<WristbandJwtValidatorConfig, 'jwksCacheMaxSize' | 'jwksCacheTtl'>
  ): WristbandJwtValidator {
    if (!this.jwtValidator) {
      this.jwtValidator = createWristbandJwtValidator({
        wristbandApplicationVanityDomain: this.wristbandApplicationVanityDomain,
        jwksCacheMaxSize: jwtConfig?.jwksCacheMaxSize,
        jwksCacheTtl: jwtConfig?.jwksCacheTtl,
      });
    }
    return this.jwtValidator;
  }
}
