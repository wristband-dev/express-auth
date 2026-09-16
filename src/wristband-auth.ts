import { NextFunction, Request, Response } from 'express';
import {
  createWristbandAuth as createCoreWristbandAuth,
  discoverWristbandAuth as discoverCoreWristbandAuth,
  normalizeAuthMiddlewareConfig,
  type AuthConfig,
  type AuthMiddlewareConfig,
  type CallbackResult,
  type LoginConfig,
  type LogoutConfig,
  type TokenData,
  type WristbandAuth as CoreWristbandAuth,
} from '@wristband/typescript-auth';

import { sendAuthFailureResponse } from './utils/middleware';

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
   * @param {Request} req The Express request object.
   * @param {Response} res The Express response object.
   * @param {LoginConfig} [config] Additional configuration for creating an auth request to Wristband.
   * @returns {Promise<string>} A Promise containing a redirect URL to Wristband's Authorize Endpoint.
   */
  login(req: Request, res: Response, config?: LoginConfig): Promise<string>;

  /**
   * Receives incoming requests from Wristband with an authorization code.
   *
   * @param {Request} req The Express request object.
   * @param {Response} res The Express response object.
   * @returns {Promise<CallbackResult>} A Promise containing the result of callback execution.
   */
  callback(req: Request, res: Response): Promise<CallbackResult>;

  /**
   * Revokes the user's refresh token and returns a redirect URL to Wristband's Logout Endpoint.
   *
   * @param {Request} req The Express request object.
   * @param {Response} res The Express response object.
   * @param {LogoutConfig} [config] Additional configuration for logging out the user.
   * @returns {Promise<string>} A Promise of type string containing a redirect URL to Wristband's Logout Endpoint.
   */
  logout(req: Request, res: Response, config?: LogoutConfig): Promise<string>;

  /**
   * Checks if the user's access token is expired and refreshes the token, if necessary.
   *
   * @param {string} refreshToken The refresh token.
   * @param {number} expiresAt Unix timestamp in milliseconds at which the token expires.
   * @returns {Promise<TokenData | null>} Token data if refreshed, otherwise null.
   */
  refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null>;

  /**
   * Create middleware that validates authentication using configurable strategies (SESSION, JWT, or both).
   */
  createAuthMiddleware(
    config: AuthMiddlewareConfig
  ): (req: Request, res: Response, next: NextFunction) => Promise<void>;
}

/**
 * Express adapter over `@wristband/typescript-auth`.
 *
 * @internal
 */
export class WristbandAuthImpl implements WristbandAuth {
  private core: CoreWristbandAuth;

  constructor(authConfig: AuthConfig, core?: CoreWristbandAuth) {
    this.core = core ?? createCoreWristbandAuth(authConfig);
  }

  static async createWithDiscovery(authConfig: AuthConfig): Promise<WristbandAuthImpl> {
    const core = await discoverCoreWristbandAuth(authConfig);
    return new WristbandAuthImpl(authConfig, core);
  }

  login(req: Request, res: Response, config?: LoginConfig): Promise<string> {
    return this.core.login(req, res, config);
  }

  callback(req: Request, res: Response): Promise<CallbackResult> {
    return this.core.callback(req, res);
  }

  logout(req: Request, res: Response, config?: LogoutConfig): Promise<string> {
    return this.core.logout(req, res, config);
  }

  refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null> {
    return this.core.refreshTokenIfExpired(refreshToken, expiresAt);
  }

  createAuthMiddleware(
    config: AuthMiddlewareConfig
  ): (req: Request, res: Response, next: NextFunction) => Promise<void> {
    normalizeAuthMiddlewareConfig(config);

    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).auth = {};

      try {
        const result = await this.core.authenticate(req, config, req.session);

        if (!result.authenticated) {
          sendAuthFailureResponse(res, result.reason);
          return;
        }

        if (result.usedStrategy === 'JWT') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (req as any).auth = { ...result.jwtPayload, jwt: result.jwt };
        }

        next();
      } catch (error) {
        next(error);
      }
    };
  }
}
