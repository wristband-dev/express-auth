import { NextFunction, Request, Response } from 'express';

import { AuthService } from './auth-service';
import { AuthConfig, CallbackResult, LoginConfig, LogoutConfig, RequireSessionAuthConfig, TokenData } from './types';

/**
 * WristbandAuth is a utility interface providing methods for seamless interaction with Wristband for authenticating
 * application users. It can handle the following:
 * - Initiate a login request by redirecting to Wristband.
 * - Receive callback requests from Wristband to complete a login request.
 * - Retrive all necessary JWT tokens and userinfo to start an application session.
 * - Logout a user from the application by revoking refresh tokens and redirecting to Wristband.
 * - Checking for expired access tokens and refreshing them automatically, if necessary.
 */
export interface WristbandAuth {
  /**
   * Initiates a login request by redirecting to Wristband. An authorization request is constructed
   * for the user attempting to login in order to start the Authorization Code flow.
   *
   * Your Express request can contain Wristband-specific query parameters:
   * - login_hint: A hint to Wristband about user's preferred login identifier. This can be appended as a query
   * parameter in the redirect request to the Authorize URL.
   * - return_url: The location of where to send users after authenticating.
   * - tenant_custom_domain: The tenant custom domain for the tenant that the user belongs to, if applicable. Should be
   * used as the domain of the authorize URL when present.
   * - tenant_domain: The domain name of the tenant the user belongs to. Should be used in the tenant vanity domain of
   * the authorize URL when not utilizing tenant subdomains nor tenant custom domains.
   *
   * @param {Request} req The Express request object.
   * @param {Response} res The Express response object.
   * @param {LoginConfig} [config] Additional configuration for creating an auth request to Wristband.
   * @returns {Promise<string>} A Promise containing a redirect URL to Wristband's Authorize Endpoint.
   * @throws {Error} If an error occurs during the login process.
   */
  login(req: Request, res: Response, config?: LoginConfig): Promise<string>;

  /**
   * Receives incoming requests from Wristband with an authorization code. It will then proceed to exchange the auth
   * code for an access token as well as fetch the userinfo for the user attempting to login.
   *
   * Your Express request can contain Wristband-specific query parameters:
   * - code: The authorization code to use for exchanging for an access token.
   * - error: An error code indicating that some an issue occurred during the login process.
   * - error_description: A plaintext description giving more detail around the issue that occurred during the login
   * process.
   * - state: The state value that was originally sent to the Authorize URL.
   * - tenant_custom_domain: If the tenant has a tenant custom domain defined, then this query parameter will be part
   * of the incoming request to the Callback Endpoint. n the event a redirect to the Login Endpoint is required, then
   * this should be appended as a query parameter when redirecting to the Login Endpoint.
   * - tenant_domain: The domain name of the tenant the user belongs to. In the event a redirect to the Login Endpoint
   * is required and neither tenant subdomains nor tenant custom domains are not being utilized, then this should be
   * appended as a query parameter when redirecting to the Login Endpoint.
   *
   * @param {Request} req The Express request object.
   * @param {Response} res The Express response object.
   * @returns {Promise<CallbackResult>} A Promise containing the result of what happened during callback execution
   * as well as any accompanying data.
   * @throws {Error} If an error occurs during the callback handling.
   */
  callback(req: Request, res: Response): Promise<CallbackResult>;

  /**
   * Revokes the user's refresh token and returns a redirect URL to Wristband's Logout Endpoint.
   *
   * @param {Request} req The Express request object.
   * @param {Response} res The Express response object.
   * @param {LogoutConfig} [config] Additional configuration for logging out the user.
   * @returns {Promise<string>} A Promise of type string containing a redirect URL to Wristband's Logout Endpoint.
   * @throws {Error} If an error occurs during the logout process.
   */
  logout(req: Request, res: Response, config?: LogoutConfig): Promise<string>;

  /**
   * Checks if the user's access token is expired and refreshed the token, if necessary.
   *
   * @param {string} refreshToken The refresh token.
   * @param {number} expiresAt Unix timestamp in milliseconds at which the token expires.
   * @returns {Promise<TokenData | null>} A Promise with the data from the token endpoint if the token was refreshed.
   * Otherwise, a Promise with null value is returned.
   * @throws {Error} If an error occurs during the token refresh process.
   */
  refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null>;

  /**
   * Create middleware that ensures authenticated session and optionally validates CSRF tokens.
   * Automatically refreshes access token, if expired, using the refresh token.
   *
   * NOTE: Token refresh only occurs when both `refreshToken` and `expiresAt` are present in the session.
   *
   * @param config - Optional configuration for the session auth middleware
   * @param config.enableCsrfProtection - Enable CSRF protection for API requests.
   *         Default: false (relies on sameSite cookie protection)
   * @param config.csrfTokenHeaderName - CSRF token header name. Default: 'x-csrf-token'
   * @returns Express middleware function that validates session authentication
   * @throws {401} If user is not authenticated or token refresh fails
   * @throws {403} If CSRF token is missing or invalid (when CSRF protection is enabled)
   *
   * @example
   * ```typescript
   * // Basic usage - no CSRF protection
   * const requireWristbandAuth = wristbandAuth.createRequireSessionAuth();
   * app.use('/api/protected', requireWristbandAuth);
   *
   * // With CSRF protection enabled
   * const requireWristbandAuth = wristbandAuth.createRequireSessionAuth({
   *   enableCsrfProtection: true,
   *   csrfTokenHeaderName: 'custom-csrf-name'
   * });
   * app.use('/api/protected', requireWristbandAuth);
   * ```
   */
  createRequireSessionAuth(
    config?: RequireSessionAuthConfig
  ): (req: Request, res: Response, next: NextFunction) => Promise<void>;
}

/**
 * WristbandAuth is a utility class providing methods for seamless interaction with the Wristband authentication service.
 * @implements {WristbandAuth}
 */
export class WristbandAuthImpl implements WristbandAuth {
  private authService: AuthService;

  /**
   * Creates an instance of WristbandAuth.
   *
   * @param {AuthConfig} authConfig The configuration for Wristband authentication.
   */
  constructor(authConfig: AuthConfig) {
    this.authService = new AuthService(authConfig);
  }

  /**
   * Internal method to eagerly fetch and cache all auto-configurable values from the
   * Wristband SDK Configuration Endpoint. This triggers the API call and caches results,
   * allowing any validation errors to be thrown early (fail-fast).
   *
   * @private
   * @returns {Promise<void>} A Promise that resolves when configuration is preloaded.
   * @throws {WristbandError} When auto-configuration endpoint is unreachable or returns invalid data.
   * @throws {TypeError} When required configuration values cannot be resolved.
   */
  private async discover(): Promise<void> {
    await this.authService.preloadConfig();
  }

  /**
   * Static factory method to create a WristbandAuth instance with eager auto-configuration.
   *
   * This method immediately fetches and resolves all auto-configuration values from the
   * Wristband SDK Configuration Endpoint during initialization. Unlike the standard constructor,
   * this ensures all configuration is loaded and validated upfront, allowing the application to
   * fail fast if auto-configuration is unavailable.
   *
   * @static
   * @param {AuthConfig} authConfig - Configuration for Wristband authentication. Required fields:
   *   clientId, clientSecret, wristbandApplicationVanityDomain.
   * @returns {Promise<WristbandAuthImpl>} A Promise that resolves to an instance of WristbandAuthImpl
   *   with all configuration values already resolved and validated.
   * @throws {WristbandError} When auto-configuration endpoint is unreachable or returns invalid data.
   * @throws {TypeError} When required configuration values cannot be resolved.
   *
   * @example
   * ```typescript
   * // Create with eager auto-configuration
   * const wristbandAuth = await WristbandAuthImpl.createWithDiscovery({
   *   clientId: "your-client-id",
   *   clientSecret: "your-secret",
   *   wristbandApplicationVanityDomain: "auth.yourapp.io"
   * });
   * // All configuration is now resolved and ready to use
   * ```
   */
  static async createWithDiscovery(authConfig: AuthConfig): Promise<WristbandAuthImpl> {
    const auth = new WristbandAuthImpl(authConfig);
    await auth.discover();
    return auth;
  }

  /**
   * @inheritdoc
   * @see {@link WristbandAuth.login}
   */
  login(req: Request, res: Response, config?: LoginConfig): Promise<string> {
    return this.authService.login(req, res, config);
  }

  /**
   * @inheritdoc
   * @see {@link WristbandAuth.callback}
   */
  callback(req: Request, res: Response): Promise<CallbackResult> {
    return this.authService.callback(req, res);
  }

  /**
   * @inheritdoc
   * @see {@link WristbandAuth.logout}
   */
  logout(req: Request, res: Response, config?: LogoutConfig): Promise<string> {
    return this.authService.logout(req, res, config);
  }

  /**
   * @inheritdoc
   * @see {@link WristbandAuth.refreshTokenIfExpired}
   */
  refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null> {
    return this.authService.refreshTokenIfExpired(refreshToken, expiresAt);
  }

  /**
   * @inheritdoc
   * @see {@link WristbandAuth.createRequireSessionAuth}
   */
  createRequireSessionAuth(
    config?: RequireSessionAuthConfig
  ): (req: Request, res: Response, next: NextFunction) => Promise<void> {
    return this.authService.createRequireSessionAuth(config);
  }
}
