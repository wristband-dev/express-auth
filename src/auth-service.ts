import { NextFunction, Request, Response } from 'express';
import { AxiosError } from 'axios';
import {
  createWristbandJwtValidator,
  WristbandJwtValidatorConfig,
  WristbandJwtValidator,
} from '@wristband/typescript-jwt';

import {
  LOGIN_REQUIRED_ERROR,
  MAX_REFRESH_ATTEMPT_DELAY_MS,
  MAX_REFRESH_ATTEMPTS,
  TENANT_PLACEHOLDER_REGEX,
} from './utils/constants';
import {
  clearOldestLoginStateCookie,
  createLoginState,
  createLoginStateCookie,
  decryptLoginState,
  encryptLoginState,
  getAndClearLoginStateCookie,
  getOAuthAuthorizeUrl,
  isExpired,
  resolveTenantCustomDomainParam,
  resolveTenantName,
} from './utils';
import { WristbandService } from './wristband-service';
import {
  AuthConfig,
  AuthMiddlewareConfig,
  AuthStrategy,
  AuthStrategyResult,
  CallbackData,
  CallbackResult,
  LoginConfig,
  LoginState,
  LogoutConfig,
  NormalizedAuthMiddlewareConfig,
  TokenData,
  UserInfo,
  WristbandTokenResponse,
} from './types';
import { InvalidGrantError, WristbandError } from './error';
import { ConfigResolver } from './config-resolver';
import { isValidCsrf, normalizeAuthMiddlewareConfig, sendAuthFailureResponse } from './utils/middleware';

/**
 * Core service class that handles Wristband authentication operations.
 * Manages login flows, token exchanges, session validation, and logout functionality.
 */
export class AuthService {
  private wristbandService: WristbandService;
  private configResolver: ConfigResolver;
  private jwtValidator?: WristbandJwtValidator;

  /**
   * Creates an instance of AuthService.
   *
   * @param {AuthConfig} authConfig - Configuration for Wristband authentication.
   */
  constructor(authConfig: AuthConfig) {
    this.configResolver = new ConfigResolver(authConfig);
    this.wristbandService = new WristbandService(
      this.configResolver.getWristbandApplicationVanityDomain(),
      this.configResolver.getClientId(),
      this.configResolver.getClientSecret()
    );
  }

  /**
   * Force load all auto-configurable fields to cache them. This will trigger the API call
   * and cache the results. Any validation errors will be thrown here (fail-fast).
   *
   * @returns {Promise<void>} A Promise that resolves when configuration is preloaded.
   * @throws {WristbandError} When autoConfigureEnabled is false or auto-configuration fails.
   */
  async preloadConfig(): Promise<void> {
    if (!this.configResolver.getAutoConfigureEnabled()) {
      throw new WristbandError(
        'Cannot preload configs when autoConfigureEnabled is false. Use createWristbandAuth() instead.'
      );
    }
    await this.configResolver.preloadSdkConfig();
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
    res.header('Cache-Control', 'no-store');
    res.header('Pragma', 'no-cache');

    // Fetch our SDK configs
    const clientId = this.configResolver.getClientId();
    const customApplicationLoginPageUrl = await this.configResolver.getCustomApplicationLoginPageUrl();
    const dangerouslyDisableSecureCookies = this.configResolver.getDangerouslyDisableSecureCookies();
    const isApplicationCustomDomainActive = await this.configResolver.getIsApplicationCustomDomainActive();
    const loginStateSecret = this.configResolver.getLoginStateSecret();
    const parseTenantFromRootDomain = await this.configResolver.getParseTenantFromRootDomain();
    const redirectUri = await this.configResolver.getRedirectUri();
    const scopes = this.configResolver.getScopes();
    const wristbandApplicationVanityDomain = this.configResolver.getWristbandApplicationVanityDomain();

    // Determine which domain-related values are present as it will be needed for the authorize URL.
    const tenantCustomDomain: string = resolveTenantCustomDomainParam(req);
    const tenantName: string = resolveTenantName(req, parseTenantFromRootDomain);
    const defaultTenantCustomDomain: string = config.defaultTenantCustomDomain || '';
    const defaultTenantName: string = config.defaultTenantName || '';

    // In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
    if (!tenantCustomDomain && !tenantName && !defaultTenantCustomDomain && !defaultTenantName) {
      const apploginUrl = customApplicationLoginPageUrl || `https://${wristbandApplicationVanityDomain}/login`;
      return `${apploginUrl}?client_id=${clientId}`;
    }

    // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
    const customState =
      !!config.customState && !!Object.keys(config.customState).length ? config.customState : undefined;
    const loginState: LoginState = createLoginState(req, redirectUri, { customState, returnUrl: config.returnUrl });

    // Clear any stale login state cookies and add a new one fo rthe current request.
    clearOldestLoginStateCookie(req, res, dangerouslyDisableSecureCookies);
    const encryptedLoginState: string = await encryptLoginState(loginState, loginStateSecret);
    createLoginStateCookie(res, loginState.state, encryptedLoginState, dangerouslyDisableSecureCookies);

    // Return the Wristband Authorize Endpoint URL which the user will get redirectd to.
    return getOAuthAuthorizeUrl(req, {
      wristbandApplicationVanityDomain,
      isApplicationCustomDomainActive,
      clientId,
      redirectUri,
      state: loginState.state,
      codeVerifier: loginState.codeVerifier,
      scopes,
      tenantCustomDomain,
      tenantName,
      defaultTenantCustomDomain,
      defaultTenantName,
    });
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
    res.header('Cache-Control', 'no-store');
    res.header('Pragma', 'no-cache');

    // Fetch our SDK configs
    const dangerouslyDisableSecureCookies = this.configResolver.getDangerouslyDisableSecureCookies();
    const loginStateSecret = this.configResolver.getLoginStateSecret();
    const loginUrl = await this.configResolver.getLoginUrl();
    const parseTenantFromRootDomain = await this.configResolver.getParseTenantFromRootDomain();
    const tokenExpirationBuffer = this.configResolver.getTokenExpirationBuffer();

    // Safety checks -- Wristband backend should never send bad query params
    const {
      code,
      state: paramState,
      error,
      error_description: errorDescription,
      tenant_custom_domain: tenantCustomDomainParam,
    } = req.query;
    if (!paramState || typeof paramState !== 'string') {
      throw new TypeError('Invalid query parameter [state] passed from Wristband during callback');
    }
    if (!!code && typeof code !== 'string') {
      throw new TypeError('Invalid query parameter [code] passed from Wristband during callback');
    }
    if (!!error && typeof error !== 'string') {
      throw new TypeError('Invalid query parameter [error] passed from Wristband during callback');
    }
    if (!!errorDescription && typeof errorDescription !== 'string') {
      throw new TypeError('Invalid query parameter [error_description] passed from Wristband during callback');
    }
    if (!!tenantCustomDomainParam && typeof tenantCustomDomainParam !== 'string') {
      throw new TypeError('Invalid query parameter [tenant_custom_domain] passed from Wristband during callback');
    }

    // Resolve and validate the tenant name
    const resolvedTenantName: string = resolveTenantName(req, parseTenantFromRootDomain);
    if (!resolvedTenantName) {
      throw new WristbandError(
        parseTenantFromRootDomain ? 'missing_tenant_subdomain' : 'missing_tenant_name',
        parseTenantFromRootDomain
          ? 'Callback request URL is missing a tenant subdomain'
          : 'Callback request is missing the [tenant_name] query parameter from Wristband'
      );
    }

    // Construct the tenant login URL in the event we have to redirect to the login endpoint
    let tenantLoginUrl: string = parseTenantFromRootDomain
      ? loginUrl.replace(TENANT_PLACEHOLDER_REGEX, resolvedTenantName)
      : `${loginUrl}?tenant_name=${resolvedTenantName}`;
    if (tenantCustomDomainParam) {
      tenantLoginUrl = `${tenantLoginUrl}${parseTenantFromRootDomain ? '?' : '&'}tenant_custom_domain=${tenantCustomDomainParam}`;
    }

    // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
    const loginStateCookie: string = getAndClearLoginStateCookie(req, res, dangerouslyDisableSecureCookies);
    if (!loginStateCookie) {
      return { type: 'redirect_required', redirectUrl: tenantLoginUrl, reason: 'missing_login_state' };
    }
    const loginState: LoginState = await decryptLoginState(loginStateCookie, loginStateSecret);
    const { codeVerifier, customState, redirectUri, returnUrl, state: cookieState } = loginState;

    // Check for any potential error conditions
    if (paramState !== cookieState) {
      return { type: 'redirect_required', redirectUrl: tenantLoginUrl, reason: 'invalid_login_state' };
    }
    if (error) {
      if (error.toLowerCase() === LOGIN_REQUIRED_ERROR) {
        return { type: 'redirect_required', redirectUrl: tenantLoginUrl, reason: 'login_required' };
      }
      throw new WristbandError(error, errorDescription);
    }

    // Exchange the authorization code for tokens
    if (!code) {
      throw new TypeError('Invalid query parameter [code] passed from Wristband during callback');
    }

    let tokenResponse: WristbandTokenResponse;
    try {
      tokenResponse = await this.wristbandService.getTokens(code, redirectUri, codeVerifier);
    } catch (err: unknown) {
      if (err instanceof InvalidGrantError) {
        return { type: 'redirect_required', redirectUrl: tenantLoginUrl, reason: 'invalid_grant' };
      }
      throw new WristbandError('unexpected_error', 'Unexpected error', err instanceof Error ? err : undefined);
    }

    const {
      access_token: accessToken,
      id_token: idToken,
      refresh_token: refreshToken,
      expires_in: expiresIn,
    } = tokenResponse;

    // Fetch the userinfo for the user logging in.
    let userinfo: UserInfo;
    try {
      userinfo = await this.wristbandService.getUserInfo(accessToken);
    } catch (err: unknown) {
      throw new WristbandError('unexpected_error', 'Unexpected error', err instanceof Error ? err : undefined);
    }

    const resolvedExpiresIn = expiresIn - (tokenExpirationBuffer || 0);
    const resolvedExpiresAt = Date.now() + resolvedExpiresIn * 1000;

    const callbackData: CallbackData = {
      accessToken,
      ...(!!customState && { customState }),
      expiresAt: resolvedExpiresAt,
      expiresIn: resolvedExpiresIn,
      idToken,
      ...(!!refreshToken && { refreshToken }),
      ...(!!returnUrl && { returnUrl }),
      ...(!!tenantCustomDomainParam && { tenantCustomDomain: tenantCustomDomainParam }),
      tenantName: resolvedTenantName,
      userinfo,
    };

    return { type: 'completed', callbackData };
  }

  /**
   * Initiates logout by revoking the refresh token and constructing a redirect URL
   * to Wristband's logout endpoint.
   *
   * @param {Request} req - The Express request object.
   * @param {Response} res - The Express response object.
   * @param {LogoutConfig} [config={ tenantCustomDomain: '' }] - Optional configuration for logout.
   * @returns {Promise<string>} A Promise containing the redirect URL to Wristband's Logout Endpoint.
   * @throws {TypeError} When query parameters are invalid or state exceeds 512 characters.
   */
  async logout(req: Request, res: Response, config: LogoutConfig = { tenantCustomDomain: '' }): Promise<string> {
    res.header('Cache-Control', 'no-store');
    res.header('Pragma', 'no-cache');

    // Fetch our SDK configs
    const clientId = this.configResolver.getClientId();
    const customApplicationLoginPageUrl = await this.configResolver.getCustomApplicationLoginPageUrl();
    const isApplicationCustomDomainActive = await this.configResolver.getIsApplicationCustomDomainActive();
    const parseTenantFromRootDomain = await this.configResolver.getParseTenantFromRootDomain();
    const wristbandApplicationVanityDomain = this.configResolver.getWristbandApplicationVanityDomain();

    // Revoke the refresh token only if present.
    if (config.refreshToken) {
      try {
        await this.wristbandService.revokeRefreshToken(config.refreshToken);
      } catch (error) {
        // No need to block logout execution if revoking fails
        // Silently continue - the refresh token will eventually expire and can be revoked by admin
      }
    }

    if (config.state && config.state.length > 512) {
      throw new TypeError('The [state] logout config cannot exceed 512 characters.');
    }

    // The client ID is always required by the Wristband Logout Endpoint.
    const logoutRedirectUrl: string = config.redirectUrl ? `&redirect_url=${config.redirectUrl}` : '';
    const state: string = config.state ? `&state=${config.state}` : '';
    const logoutPath: string = `/api/v1/logout?client_id=${clientId}${logoutRedirectUrl}${state}`;
    const separator = isApplicationCustomDomainActive ? '.' : '-';
    const tenantCustomDomainParam: string = resolveTenantCustomDomainParam(req);
    const tenantName: string = resolveTenantName(req, parseTenantFromRootDomain);

    // 4a) If tenant subdomains are enabled, get the tenant name from the host.
    // 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_name query param.

    // Domain priority order resolution:
    // 1) If the LogoutConfig has a tenant custom domain explicitly defined, use that.
    if (config.tenantCustomDomain) {
      return `https://${config.tenantCustomDomain}${logoutPath}`;
    }

    // 2) If the LogoutConfig has a tenant name defined, then use that.
    if (config.tenantName) {
      return `https://${config.tenantName}${separator}${wristbandApplicationVanityDomain}${logoutPath}`;
    }

    // 3) If the tenant_custom_domain query param exists, then use that.
    if (tenantCustomDomainParam) {
      return `https://${tenantCustomDomainParam}${logoutPath}`;
    }

    // 4a) If tenant subdomains are enabled, get the tenant name from the host.
    // 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_name query param.
    if (tenantName) {
      return `https://${tenantName}${separator}${wristbandApplicationVanityDomain}${logoutPath}`;
    }

    // Fallback to the appropriate Application-Level Login or Redirect URL if tenant cannot be resolved.
    const appLoginUrl: string = customApplicationLoginPageUrl || `https://${wristbandApplicationVanityDomain}/login`;
    return config.redirectUrl || `${appLoginUrl}?client_id=${clientId}`;
  }

  /**
   * Checks if the access token is expired and refreshes it if necessary.
   * Implements retry logic for transient failures.
   *
   * @param {string} refreshToken - The refresh token to use for obtaining a new access token.
   * @param {number} expiresAt - Unix timestamp in milliseconds when the current token expires.
   * @returns {Promise<TokenData | null>} A Promise with new token data if refresh occurred, or null if token is still valid.
   * @throws {TypeError} When refreshToken is invalid or expiresAt is not a positive integer.
   * @throws {WristbandError} When token refresh fails due to invalid credentials or unexpected errors.
   */
  async refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null> {
    // Fetch our SDK configs
    const tokenExpirationBuffer = this.configResolver.getTokenExpirationBuffer();

    // Safety checks
    if (!refreshToken) {
      throw new TypeError('Refresh token must be a valid string');
    }
    if (!expiresAt || expiresAt < 0) {
      throw new TypeError('The expiresAt field must be an integer greater than 0');
    }

    // Nothing to do here if the access token is still valid.
    if (!isExpired(expiresAt)) {
      return null;
    }

    // Try up to 3 times to perform a token refresh.
    for (let attempt = 1; attempt <= MAX_REFRESH_ATTEMPTS; attempt += 1) {
      try {
        // eslint-disable-next-line no-await-in-loop
        const tokenResponse = await this.wristbandService.refreshToken(refreshToken);
        const {
          access_token: accessToken,
          id_token: idToken,
          expires_in: expiresIn,
          refresh_token: responseRefreshToken,
        } = tokenResponse;

        const resolvedExpiresIn = expiresIn - (tokenExpirationBuffer || 0);
        const resolvedExpiresAt = Date.now() + resolvedExpiresIn * 1000;

        return {
          accessToken,
          idToken,
          refreshToken: responseRefreshToken,
          expiresAt: resolvedExpiresAt,
          expiresIn: resolvedExpiresIn,
        };
      } catch (error: unknown) {
        // Specifically handle invalid_grant errors
        if (error instanceof InvalidGrantError) {
          throw error;
        }

        // Only 4xx errors should short-circuit the retry loop early.
        if (
          error instanceof AxiosError &&
          error.response &&
          error.response.status >= 400 &&
          error.response.status < 500
        ) {
          const errorDescription = error.response.data?.error_description ?? 'Invalid Refresh Token';
          throw new WristbandError('invalid_refresh_token', errorDescription);
        }

        // Last attempt failed
        if (attempt === MAX_REFRESH_ATTEMPTS) {
          throw new WristbandError('unexpected_error', 'Unexpected Error');
        }

        // Wait before next retry (only for 5xx errors or network failures)
        // eslint-disable-next-line no-await-in-loop
        await new Promise<void>((resolve) => {
          setTimeout(resolve, MAX_REFRESH_ATTEMPT_DELAY_MS);
        });
      }
    }

    // This is merely a safety check, but this should never happen.
    throw new WristbandError('unexpected_error', 'Unexpected Error');
  }

  /**
   * Create middleware that ensures authenticated session using multiple strategies.
   * Tries strategies in order until one succeeds. Supports both SESSION and JWT auth.
   *
   * @param {AuthMiddlewareConfig} config - Configuration for the auth middleware.
   * @returns {Function} Express middleware function that validates authentication.
   *
   * @example
   * ```typescript
   * // SESSION only
   * const requireAuth = authService.createMiddlewareAuth({
   *   authStrategies: ['SESSION'],
   *   sessionConfig: {
   *     sessionOptions: {
   *       secrets: process.env.SESSION_SECRET!,
   *       cookieName: 'my-session',
   *       maxAge: 24 * 60 * 60 * 1000, // 24 hours
   *       enableCsrfProtection: true,
   *     }
   *   }
   * });
   * app.use('/api/protected', requireAuth);
   *
   * // JWT only
   * const requireJwtAuth = authService.createMiddlewareAuth({
   *   authStrategies: ['JWT']
   * });
   * app.use('/api/protected', requireJwtAuth);
   *
   * // Try SESSION first, fallback to JWT
   * const requireAuth = authService.createMiddlewareAuth({
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
      // Initialize req.auth at the very beginning regardless of strategy
      (req as any).auth = {};

      let result: AuthStrategyResult = { authenticated: false, reason: 'not_authenticated' };

      // Try all auth strategies in sequential order
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

        // eslint-disable-next-line no-await-in-loop
        result = await this.tryAuthStrategy(req, strategy, normalizedConfig);

        if (result.authenticated) {
          break;
        }
      }

      // If no strategy succeeded, return appropriate error
      if (!result.authenticated) {
        sendAuthFailureResponse(res, result.reason);
        return;
      }

      // Authentication succeeded - continue
      next();
    };
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
          } catch (error) {
            return { authenticated: false, reason: 'token_refresh_failed' };
          }
        }

        // Save session (for rolling expiration)
        await req.session.save();
        return { authenticated: true, usedStrategy: 'SESSION' };
      } catch (error) {
        return { authenticated: false, reason: 'unexpected_error' };
      }
    }

    if (strategy === 'JWT') {
      try {
        const jwtValidator = this.getJwtValidator(config.jwtConfig);

        const bearerToken = jwtValidator.extractBearerToken(req.headers.authorization);
        if (!bearerToken) {
          return { authenticated: false, reason: 'not_authenticated' };
        }

        const validationResult = await jwtValidator.validate(bearerToken);
        const { isValid, payload } = validationResult;
        if (!isValid) {
          return { authenticated: false, reason: 'not_authenticated' };
        }

        // Attach JWT and decoded payload to req.auth
        (req as any).auth = payload;
        (req as any).auth.jwt = bearerToken;

        return { authenticated: true, usedStrategy: 'JWT' };
      } catch (error) {
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
      const wristbandApplicationVanityDomain = this.configResolver.getWristbandApplicationVanityDomain();
      this.jwtValidator = createWristbandJwtValidator({
        wristbandApplicationVanityDomain,
        jwksCacheMaxSize: jwtConfig?.jwksCacheMaxSize,
        jwksCacheTtl: jwtConfig?.jwksCacheTtl,
      });
    }
    return this.jwtValidator;
  }
}
