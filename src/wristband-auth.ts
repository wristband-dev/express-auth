import { Request, Response } from 'express';

import { AuthService } from './auth-service';
import { AuthConfig, CallbackData, LoginConfig, LogoutConfig, TokenData } from './types';

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
   * - return_url: The location of where to send users after authenticating. (Optional)
   * - login_hint: A hint to Wristband about user's preferred login identifier. (Optional)
   *
   * @param {Request} req - The Express request object.
   * @param {Response} res - The Express response object.
   * @param {LoginConfig} [config] - Additional configuration for creating an auth request to Wristband.
   * @returns {Promise<void>} - A Promise as a result of a URL redirect to Wristband.
   * @throws {Error} - If an error occurs during the login process.
   */
  login(req: Request, res: Response, config?: LoginConfig): Promise<void>;

  /**
   * Receives incoming requests from Wristband with an authorization code. It will then proceed to exchange the auth
   * code for an access token as well as fetch the userinfo for the user attempting to login.
   *
   * @param {Request} req - The Express request object.
   * @param {Response} res - The Express response object.
   * @returns {Promise<CallbackData | void>} - A Promise with all token data, userinfo, custom state, and return URL,
   * assuming the exchange of an auth code for a token succeeds (response contents depend on what inputs were given
   * to the login endpoint during the auth request). Otherwise, a Promise of type void is returned as a result of a
   * URL redirect in the event of certain error scenarios.
   * @throws {Error} - If an error occurs during the callback handling.
   */
  callback(req: Request, res: Response): Promise<CallbackData | void>;

  /**
   * Revokes the user's refresh token and redirects them to the Wristband logout endpoint to destroy
   * their authenticated session in Wristband.
   *
   * @param {Request} req - The Express request object.
   * @param {Response} res - The Express response object.
   * @param {LogoutConfig} [config] - Additional configuration for logging out the user.
   * @returns {Promise<void>} - A Promise of type void as a result of a URL redirect to Wristband.
   * @throws {Error} - If an error occurs during the logout process.
   */
  logout(req: Request, res: Response, config?: LogoutConfig): Promise<void>;

  /**
   * Checks if the user's access token is expired and refreshed the token, if necessary.
   *
   * @param {string} refreshToken - The refresh token.
   * @param {number} expiresAt - Unix timestamp in milliseconds at which the token expires.
   * @returns {Promise<TokenData | null>} - A Promise with the data from the token endpoint if the token was refreshed.
   * Otherwise, a Promise with null value is returned.
   * @throws {Error} - If an error occurs during the token refresh process.
   */
  refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null>;
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
   * @param {AuthConfig} authConfig - The configuration for Wristband authentication.
   */
  constructor(authConfig: AuthConfig) {
    this.authService = new AuthService(authConfig);
  }

  login(req: Request, res: Response, config?: LoginConfig): Promise<void> {
    return this.authService.login(req, res, config);
  }

  callback(req: Request, res: Response): Promise<CallbackData | void> {
    return this.authService.callback(req, res);
  }

  logout(req: Request, res: Response, config?: LogoutConfig): Promise<void> {
    return this.authService.logout(req, res, config);
  }

  refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null> {
    return this.authService.refreshTokenIfExpired(refreshToken, expiresAt);
  }
}
