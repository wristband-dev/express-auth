import { NextFunction, Request, Response } from 'express';
import {
  createWristbandJwtValidator,
  WristbandJwtValidatorConfig,
  WristbandJwtValidator,
} from '@wristband/typescript-jwt';

import { LOGIN_REQUIRED_ERROR, STATE_PARAM_MAX_CHAR_LENGTH, TENANT_PLACEHOLDER_REGEX } from './utils/constants';
import {
  getAppLevelAuthorizationUrl,
  getAppLevelLoginUrl,
  getAuthorizationUrlParams,
  getTenantLevelAuthorizationUrl,
  resolveReturnUrl,
  resolveTenantCustomDomainParam,
  resolveTenantName,
  toSafeDomainName,
  toSafeTenantName,
  validateReturnUrl,
} from './utils/urls';
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
import { FetchError, InvalidGrantError, WristbandError } from './error';
import { ConfigResolver } from './config-resolver';
import { isValidCsrf, normalizeAuthMiddlewareConfig, sendAuthFailureResponse } from './utils/middleware';
import { clearCookie, parseCookies } from './utils/cookies';
import {
  clearOldestLoginStateCookie,
  createLoginState,
  createLoginStateCookie,
  decryptLoginState,
  encryptLoginState,
  getLoginStateCookie,
} from './utils/login-state';

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
    const applicationAuthorizationRequestsEnabled =
      await this.configResolver.getApplicationAuthorizationRequestsEnabled();
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
    const tenantCustomDomain: string = await this.resolveValidTenantCustomDomain(resolveTenantCustomDomainParam(req));
    const tenantName: string = resolveTenantName(req, parseTenantFromRootDomain);
    const defaultTenantCustomDomain: string = toSafeDomainName(config.defaultTenantCustomDomain);
    const defaultTenantName: string = toSafeTenantName(config.defaultTenantName);

    // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
    const resolvedReturnUrl = resolveReturnUrl(req, config);
    const loginState: LoginState = createLoginState(redirectUri, {
      customState: config.customState,
      returnUrl: resolvedReturnUrl,
    });

    // Create the authorization request params needed, regardless if using app-level or tenant-level Authorize Endpoint.
    const { codeVerifier, state } = loginState;
    const authorizationParamConfig = { clientId, codeVerifier, redirectUri, scopes, state };

    // Determine whether to use the root domain for the login state cookie.
    const cookieDomain =
      applicationAuthorizationRequestsEnabled && parseTenantFromRootDomain
        ? `.${parseTenantFromRootDomain}`
        : undefined;

    // In the event we cannot determine either a tenant custom domain or subdomain, deduce the right app-level URL.
    if (!tenantCustomDomain && !tenantName && !defaultTenantCustomDomain && !defaultTenantName) {
      if (applicationAuthorizationRequestsEnabled) {
        // Clear any stale login state cookies and add a new one for the current request.
        clearOldestLoginStateCookie(req, res, dangerouslyDisableSecureCookies, cookieDomain);
        const encryptedLoginState: string = await encryptLoginState(loginState, loginStateSecret);
        createLoginStateCookie(
          res,
          loginState.state,
          encryptedLoginState,
          dangerouslyDisableSecureCookies,
          cookieDomain
        );

        // Send users to the app-level Authorize Endpoint with a login state cookie instead of going to login URL.
        const authorizationParams = await getAuthorizationUrlParams(req, authorizationParamConfig);
        return getAppLevelAuthorizationUrl(wristbandApplicationVanityDomain, authorizationParams);
      }

      // For the login URL scenario, we don't actually want to touch any login state cookies.
      return getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, {
        customApplicationLoginPageUrl,
        returnUrl: resolvedReturnUrl,
      });
    }

    // Clear any stale login state cookies and add a new one for the current request.
    clearOldestLoginStateCookie(req, res, dangerouslyDisableSecureCookies, cookieDomain);
    const encryptedLoginState: string = await encryptLoginState(loginState, loginStateSecret);
    createLoginStateCookie(res, loginState.state, encryptedLoginState, dangerouslyDisableSecureCookies, cookieDomain);

    // Return the tenant-level Wristband Authorize Endpoint URL which the user will get redirected to.
    const authorizationParams = await getAuthorizationUrlParams(req, authorizationParamConfig);
    return getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, authorizationParams, {
      isApplicationCustomDomainActive,
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
    const applicationAuthorizationRequestsEnabled =
      await this.configResolver.getApplicationAuthorizationRequestsEnabled();
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

    // An invalid tenant custom domain is skipped over rather than failing the callback.
    const tenantCustomDomain: string = await this.resolveValidTenantCustomDomain(
      typeof tenantCustomDomainParam === 'string' ? tenantCustomDomainParam : ''
    );

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
    if (tenantCustomDomain) {
      tenantLoginUrl = `${tenantLoginUrl}${parseTenantFromRootDomain ? '?' : '&'}tenant_custom_domain=${tenantCustomDomain}`;
    }

    // Make sure the login state cookie exists.
    const { cookieName, loginStateCookie } = getLoginStateCookie(req);
    if (!cookieName || !loginStateCookie) {
      return { type: 'redirect_required', redirectUrl: tenantLoginUrl, reason: 'missing_login_state' };
    }

    // Determine whether to use the root domain for clearing the login state cookie.
    const cookieDomain =
      applicationAuthorizationRequestsEnabled && parseTenantFromRootDomain
        ? `.${parseTenantFromRootDomain}`
        : undefined;
    clearCookie(res, cookieName, dangerouslyDisableSecureCookies, cookieDomain);

    // Extract the login state from the cookie.
    const loginState: LoginState | null = await decryptLoginState(loginStateCookie, loginStateSecret);
    if (!loginState) {
      return { type: 'redirect_required', redirectUrl: tenantLoginUrl, reason: 'invalid_login_state' };
    }
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

    // Prevent open redirects by validating the returnUrl against allowed hosts.
    const validatedReturnUrl = validateReturnUrl(
      req,
      returnUrl,
      resolvedTenantName,
      applicationAuthorizationRequestsEnabled,
      parseTenantFromRootDomain
    );

    const callbackData: CallbackData = {
      accessToken,
      ...(!!customState && { customState }),
      expiresAt: resolvedExpiresAt,
      expiresIn: resolvedExpiresIn,
      idToken,
      ...(!!refreshToken && { refreshToken }),
      ...(!!validatedReturnUrl && { returnUrl: validatedReturnUrl }),
      ...(!!tenantCustomDomain && { tenantCustomDomain }),
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
   * @throws {TypeError} When query parameters are invalid or state exceeds the max allowed characters.
   */
  async logout(req: Request, res: Response, config: LogoutConfig = { tenantCustomDomain: '' }): Promise<string> {
    res.header('Cache-Control', 'no-store');
    res.header('Pragma', 'no-cache');

    // Fetch our SDK configs
    const applicationAuthorizationRequestsEnabled =
      await this.configResolver.getApplicationAuthorizationRequestsEnabled();
    const clientId = this.configResolver.getClientId();
    const customApplicationLoginPageUrl = await this.configResolver.getCustomApplicationLoginPageUrl();
    const fallbackLoginUrl = await this.configResolver.getFallbackLoginUrl();
    const isApplicationCustomDomainActive = await this.configResolver.getIsApplicationCustomDomainActive();
    const loginUrl = await this.configResolver.getLoginUrl();
    const parseTenantFromRootDomain = await this.configResolver.getParseTenantFromRootDomain();
    const wristbandApplicationVanityDomain = this.configResolver.getWristbandApplicationVanityDomain();

    if (config.state && config.state.length > STATE_PARAM_MAX_CHAR_LENGTH) {
      throw new TypeError(`The [state] logout config cannot exceed ${STATE_PARAM_MAX_CHAR_LENGTH} characters.`);
    }

    // Revoke the refresh token only if present.
    if (config.refreshToken) {
      try {
        await this.wristbandService.revokeRefreshToken(config.refreshToken);
      } catch {
        // No need to block logout execution if revoking fails
        // Silently continue - the refresh token will eventually expire and can be revoked by admin
      }
    }

    // The client ID is always required by the Wristband Logout Endpoint.
    const logoutRedirectUrl: string = config.redirectUrl
      ? `&redirect_url=${encodeURIComponent(config.redirectUrl)}`
      : '';
    const state: string = config.state ? `&state=${encodeURIComponent(config.state)}` : '';

    const logoutPath: string = `/api/v1/logout?client_id=${clientId}${logoutRedirectUrl}${state}`;
    const separator = isApplicationCustomDomainActive ? '.' : '-';
    const tenantCustomDomainParam: string = await this.resolveValidTenantCustomDomain(
      resolveTenantCustomDomainParam(req)
    );
    const tenantName: string = resolveTenantName(req, parseTenantFromRootDomain);
    const configTenantCustomDomain: string = toSafeDomainName(config.tenantCustomDomain);
    const configTenantName: string = toSafeTenantName(config.tenantName);

    // Domain priority order resolution:
    // 1) If the LogoutConfig has a tenant custom domain explicitly defined, use that.
    if (configTenantCustomDomain) {
      return `https://${configTenantCustomDomain}${logoutPath}`;
    }

    // 2) If the LogoutConfig has a tenant name defined, then use that.
    if (configTenantName) {
      return `https://${configTenantName}${separator}${wristbandApplicationVanityDomain}${logoutPath}`;
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

    // 5) First try falling back to the Logout Redirect URL (if the LogoutConfig has it) when tenant cannot be resolved.
    if (config.redirectUrl) {
      return config.redirectUrl;
    }

    // 6) If app-level authorization requests are enabled, then redirect to appropriate app-level Login Endpoint
    // to start a new app-level Authorize Endpoint flow.
    if (applicationAuthorizationRequestsEnabled) {
      return TENANT_PLACEHOLDER_REGEX.test(loginUrl) ? fallbackLoginUrl : loginUrl;
    }

    // 7a) If a custom page URL is set, fallback to that appropriate Application-Level Login when tenant cannot be resolved.
    // 7b) Finally, fallback to the Wristband-hosted Application-Level Login Page when tenant cannot be resolved.
    return getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, { customApplicationLoginPageUrl });
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
    // Fetch our SDK configs
    const tokenExpirationBuffer = this.configResolver.getTokenExpirationBuffer();

    // Safety checks
    if (!refreshToken) {
      throw new TypeError('Refresh token must be a valid string');
    }
    if (expiresAt === undefined || expiresAt === null || expiresAt < 0) {
      throw new TypeError('The expiresAt field must be an integer greater than or equal to 0');
    }

    // Nothing to do here if the access token is still valid.
    if (Date.now() < expiresAt) {
      return null;
    }

    // Retrying on transient failures (5xx errors, network errors) is already handled one layer
    // down by WristbandService -- see withRetry() in utils/retry.ts. By the time an error
    // surfaces here, retries (if any applied) have already been exhausted.
    try {
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
        throw new WristbandError('invalid_refresh_token', error.errorDescription, error);
      }

      // Any remaining 4xx error also indicates an invalid refresh token.
      if (
        error instanceof FetchError &&
        error.response &&
        error.response.status >= 400 &&
        error.response.status < 500
      ) {
        const errorDescription =
          // @ts-expect-error - body is unknown, error_description access not type-checked
          error.body && error.body.error_description ? error.body.error_description : 'Invalid Refresh Token';
        throw new WristbandError('invalid_refresh_token', errorDescription, error);
      }

      throw new WristbandError('unexpected_error', 'Unexpected Error', error instanceof Error ? error : undefined);
    }
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
   * Resolves a tenant custom domain to itself when it is verified and belongs to your Wristband
   * application. Resolves to an empty string otherwise, so the caller skips over it and falls through
   * to the next domain in its resolution precedence order.
   *
   * @param {string} tenantCustomDomain - The tenant custom domain to validate.
   * @returns {Promise<string>} The tenant custom domain when valid, otherwise an empty string.
   */
  private async resolveValidTenantCustomDomain(tenantCustomDomain: string): Promise<string> {
    // Skip the API call for anything that isn't a valid domain name.
    if (!toSafeDomainName(tenantCustomDomain)) {
      return '';
    }

    const isValid = await this.wristbandService.validateTenantCustomDomain(tenantCustomDomain);
    return isValid ? tenantCustomDomain : '';
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
