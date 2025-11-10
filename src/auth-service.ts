import { NextFunction, Request, Response } from 'express';
import retry from 'async-retry';
import { AxiosError } from 'axios';

import { LOGIN_REQUIRED_ERROR, TENANT_DOMAIN_PLACEHOLDER } from './utils/constants';
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
  CallbackData,
  CallbackResult,
  CallbackResultType,
  LoginConfig,
  LoginState,
  LogoutConfig,
  RequireSessionAuthConfig,
  TokenData,
  TokenResponse,
  UserInfo,
} from './types';
import { InvalidGrantError, WristbandError } from './error';
import { ConfigResolver } from './config-resolver';

const DEFAULT_ENABLE_CSRF_PROTECTION = false;
const DEFAULT_CSRF_HEADER_NAME = 'x-csrf-token';

/**
 * Core service class that handles Wristband authentication operations.
 * Manages login flows, token exchanges, session validation, and logout functionality.
 */
export class AuthService {
  private wristbandService: WristbandService;
  private configResolver: ConfigResolver;

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
        parseTenantFromRootDomain ? 'missing_tenant_subdomain' : 'missing_tenant_domain',
        parseTenantFromRootDomain
          ? 'Callback request URL is missing a tenant subdomain'
          : 'Callback request is missing the [tenant_domain] query parameter from Wristband'
      );
    }

    // Construct the tenant login URL in the event we have to redirect to the login endpoint
    let tenantLoginUrl: string = parseTenantFromRootDomain
      ? loginUrl.replace(TENANT_DOMAIN_PLACEHOLDER, resolvedTenantName)
      : `${loginUrl}?tenant_domain=${resolvedTenantName}`;
    if (tenantCustomDomainParam) {
      tenantLoginUrl = `${tenantLoginUrl}${parseTenantFromRootDomain ? '?' : '&'}tenant_custom_domain=${tenantCustomDomainParam}`;
    }

    // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
    const loginStateCookie: string = getAndClearLoginStateCookie(req, res, dangerouslyDisableSecureCookies);
    if (!loginStateCookie) {
      return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
    }
    const loginState: LoginState = await decryptLoginState(loginStateCookie, loginStateSecret);
    const { codeVerifier, customState, redirectUri, returnUrl, state: cookieState } = loginState;

    // Check for any potential error conditions
    if (paramState !== cookieState) {
      return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
    }
    if (error) {
      if (error.toLowerCase() === LOGIN_REQUIRED_ERROR) {
        return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
      }
      throw new WristbandError(error, errorDescription);
    }

    // Exchange the authorization code for tokens
    if (!code) {
      throw new TypeError('Invalid query parameter [code] passed from Wristband during callback');
    }
    try {
      const tokenResponse: TokenResponse = await this.wristbandService.getTokens(code, redirectUri, codeVerifier);
      const {
        access_token: accessToken,
        id_token: idToken,
        refresh_token: refreshToken,
        expires_in: expiresIn,
      } = tokenResponse;

      // Fetch the userinfo for the user logging in.
      const userinfo: UserInfo = await this.wristbandService.getUserInfo(accessToken);

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
      return { type: CallbackResultType.COMPLETED, callbackData };
    } catch (ex) {
      if (ex instanceof InvalidGrantError) {
        return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
      }
      throw ex;
    }
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

    const { host } = req.headers;
    const { tenant_custom_domain: tenantCustomDomainParam, tenant_domain: tenantDomainParam } = req.query;

    if (!!tenantCustomDomainParam && typeof tenantCustomDomainParam !== 'string') {
      throw new TypeError('More than one [tenant_custom_domain] query parameter was encountered during logout');
    }
    if (!!tenantDomainParam && typeof tenantDomainParam !== 'string') {
      throw new TypeError('More than one [tenant_domain] query parameter was encountered during logout');
    }

    // Revoke the refresh token only if present.
    if (config.refreshToken) {
      try {
        await this.wristbandService.revokeRefreshToken(config.refreshToken);
      } catch (error) {
        // No need to block logout execution if revoking fails
        console.debug(`Revoking the refresh token failed during logout`);
      }
    }

    if (config.state && config.state.length > 512) {
      throw new TypeError('The [state] logout config cannot exceed 512 characters.');
    }

    // The client ID is always required by the Wristband Logout Endpoint.
    const redirectUrl = config.redirectUrl ? `&redirect_url=${config.redirectUrl}` : '';
    const state = config.state ? `&state=${config.state}` : '';
    const query = `client_id=${clientId}${redirectUrl}${state}`;
    const separator = isApplicationCustomDomainActive ? '.' : '-';

    // Domain priority order resolution:
    // 1) If the LogoutConfig has a tenant custom domain explicitly defined, use that.
    // 2) If the LogoutConfig has a tenant name defined, then use that.
    // 3) If the tenant_custom_domain query param exists, then use that.
    // 4a) If tenant subdomains are enabled, get the tenant name from the host.
    // 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_domain query param.
    let tenantDomainToUse = '';
    if (config.tenantCustomDomain) {
      tenantDomainToUse = config.tenantCustomDomain;
    } else if (config.tenantName) {
      tenantDomainToUse = `${config.tenantName}${separator}${wristbandApplicationVanityDomain}`;
    } else if (tenantCustomDomainParam) {
      tenantDomainToUse = tenantCustomDomainParam;
    } else if (
      parseTenantFromRootDomain &&
      host &&
      host!.substring(host!.indexOf('.') + 1) === parseTenantFromRootDomain
    ) {
      const tenantNameFromHost = host!.substring(0, host!.indexOf('.'));
      tenantDomainToUse = `${tenantNameFromHost}${separator}${wristbandApplicationVanityDomain}`;
    } else if (tenantDomainParam) {
      tenantDomainToUse = `${tenantDomainParam}${separator}${wristbandApplicationVanityDomain}`;
    } else {
      // Construct the appropriate fallback URL that the user will get redirected to.
      const appLoginUrl: string = customApplicationLoginPageUrl || `https://${wristbandApplicationVanityDomain}/login`;
      return config.redirectUrl || `${appLoginUrl}?client_id=${clientId}`;
    }

    return `https://${tenantDomainToUse}/api/v1/logout?${query}`;
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
    let tokenResponse: TokenResponse | null = null;
    await retry(
      async (bail) => {
        try {
          tokenResponse = await this.wristbandService.refreshToken(refreshToken);
        } catch (error: unknown) {
          if (error instanceof InvalidGrantError) {
            // Specifically handle invalid_grant errors
            bail(error);
            return;
          }
          if (
            error instanceof AxiosError &&
            error.response &&
            error.response.status >= 400 &&
            error.response.status < 500
          ) {
            const errorDescription =
              error.response.data && error.response.data.error_description
                ? error.response.data.error_description
                : 'Invalid Refresh Token';
            // Only 4xx errors should short-circuit the retry loop early.
            bail(new WristbandError('invalid_refresh_token', errorDescription));
            return;
          }

          // Retry any 5xx errors.
          throw new WristbandError('unexpected_error', 'Unexpected Error');
        }
      },
      { retries: 2, minTimeout: 100, maxTimeout: 100 }
    );

    if (tokenResponse) {
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
    }

    // This is merely a safety check, but this should never happen.
    throw new WristbandError('unexpected_error', 'Unexpected Error');
  }

  /**
   * Create middleware that ensures authenticated session and optionally validates CSRF tokens.
   * Automatically refreshes access token, if expired, using the refresh token.
   *
   * NOTE: Token refresh only occurs when both `refreshToken` and `expiresAt` are present in the session.
   *
   * @param {RequireSessionAuthConfig} [config] - Optional configuration for the session auth middleware.
   * @returns {Function} Express middleware function that validates session authentication.
   *
   * @example
   * ```typescript
   * // Basic usage - no CSRF protection
   * app.use('/api/protected', authService.createRequireSessionAuth());
   *
   * // With CSRF protection enabled
   * app.use('/api/protected', authService.createRequireSessionAuth({
   *   enableCsrfProtection: true,
   *   csrfTokenHeaderName: 'custom-csrf-name'
   * }));
   * ```
   */
  createRequireSessionAuth(
    config?: RequireSessionAuthConfig
  ): (req: Request, res: Response, next: NextFunction) => Promise<void> {
    const enableCsrfProtection = config?.enableCsrfProtection ?? DEFAULT_ENABLE_CSRF_PROTECTION;
    const csrfTokenHeaderName = config?.csrfTokenHeaderName ?? DEFAULT_CSRF_HEADER_NAME;

    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      // Check if session middleware is configured
      if (!req.session || typeof req.session.save !== 'function') {
        const error = new WristbandError(
          'SESSION_NOT_CONFIGURED',
          'Ensure you have added the Wristband session middleware before this auth middleware.'
        );
        next(error);
        return;
      }

      const { csrfToken, expiresAt, isAuthenticated, refreshToken } = req.session;

      // Check if user has an authenticated session
      if (!isAuthenticated) {
        res.status(401).send();
        return;
      }

      // Validate CSRF token if protection is enabled
      if (enableCsrfProtection && (!csrfToken || csrfToken !== req.headers[csrfTokenHeaderName])) {
        res.status(403).send();
        return;
      }

      try {
        // Only attempt a token refresh if they actually have a refresh token in the session.
        if (refreshToken && expiresAt !== undefined) {
          const tokenData = await this.refreshTokenIfExpired(refreshToken, expiresAt);
          if (tokenData) {
            req.session.accessToken = tokenData.accessToken;
            req.session.expiresAt = tokenData.expiresAt;
            req.session.refreshToken = tokenData.refreshToken;
          }
        }

        // "Touch" the session for rolling session expiration.
        await req.session.save();
        next();
      } catch (error) {
        res.status(401).send();
      }
    };
  }
}
