import { Request, Response } from 'express';

import { AuthMiddlewareConfig, NormalizedAuthMiddlewareConfig, AuthStrategy, AuthFailureReason } from '../types';

const DEFAULT_CSRF_HEADER_NAME: string = 'x-csrf-token';
const VALID_AUTH_STRATEGIES = new Set<AuthStrategy>(['SESSION', 'JWT']);

/**
 * Validates authentication middleware configuration.
 *
 * @param config - User-provided middleware configuration
 * @throws {TypeError} If authStrategies is empty
 * @throws {TypeError} If authStrategies contains invalid values
 * @throws {TypeError} If authStrategies contains duplicates
 * @throws {TypeError} If authStrategies contains too many strategies
 * @throws {TypeError} If SESSION strategy is used but sessionConfig or sessionOptions is missing
 */
function validateAuthMiddlewareConfig(config: AuthMiddlewareConfig): void {
  // Validate authStrategies is not empty
  if (!config.authStrategies || config.authStrategies.length === 0) {
    throw new TypeError('authStrategies must contain at least one strategy');
  }

  // Validate in one pass: no invalid values, no duplicates
  const seen = new Set<AuthStrategy>();
  const invalidStrategies: string[] = [];

  config.authStrategies.forEach((strategy) => {
    // Check for invalid strategy
    if (!VALID_AUTH_STRATEGIES.has(strategy as AuthStrategy)) {
      invalidStrategies.push(strategy);
      return; // Skip to next iteration
    }

    // Check for duplicate
    if (seen.has(strategy)) {
      throw new TypeError(`authStrategies contains duplicate strategy: '${strategy}'`);
    }

    seen.add(strategy);
  });

  // Report all invalid strategies at once
  if (invalidStrategies.length > 0) {
    throw new TypeError(
      `Invalid auth strategies: '${invalidStrategies.join("', '")}'. Valid strategies are: 'SESSION', 'JWT'`
    );
  }

  // Validate sessionConfig is provided if SESSION strategy is used
  if (config.authStrategies.includes('SESSION')) {
    if (!config.sessionConfig) {
      throw new TypeError('sessionConfig is required when using SESSION strategy');
    }
    if (!config.sessionConfig?.sessionOptions) {
      throw new TypeError('sessionConfig.sessionOptions is required when using SESSION strategy');
    }
  }
}

/**
 * Normalizes authentication middleware configuration by applying default values for optional fields.
 *
 * @param config - User-provided middleware configuration with nested strategy configs
 * @returns Normalized configuration with all strategy configs in nested objects and defaults applied
 * @throws {TypeError} If configuration validation fails
 *
 * @example
 * ```typescript
 * const normalized = normalizeAuthMiddlewareConfig({
 *   authStrategies: ['SESSION'],
 *   sessionConfig: {
 *     sessionOptions: { secrets: 'my-secret', enableCsrfProtection: true },
 *   },
 * });
 * // Returns config with sessionConfig and jwtConfig objects, all defaults applied
 * ```
 */
export function normalizeAuthMiddlewareConfig(config: AuthMiddlewareConfig): NormalizedAuthMiddlewareConfig {
  // Validate config first
  validateAuthMiddlewareConfig(config);

  return {
    authStrategies: config.authStrategies,
    sessionConfig: {
      sessionOptions: config.sessionConfig?.sessionOptions || undefined,
      csrfTokenHeaderName: config.sessionConfig?.csrfTokenHeaderName || DEFAULT_CSRF_HEADER_NAME,
    },
    jwtConfig: {
      jwksCacheMaxSize: config.jwtConfig?.jwksCacheMaxSize || undefined,
      jwksCacheTtl: config.jwtConfig?.jwksCacheTtl || undefined,
    },
  };
}

/**
 * Validates the CSRF token for API requests to prevent cross-site request forgery attacks.
 *
 * Compares the CSRF token stored in the session against the token provided in the
 * request header. Both must exist and match exactly for validation to pass.
 *
 * @param req - The Request object containing headers
 * @param csrfToken - The CSRF token stored in the session (from session.csrfToken)
 * @param csrfHeaderName - The header name to check for the token (default: 'X-CSRF-TOKEN')
 * @returns True if the CSRF token is valid, false otherwise
 *
 * @example
 * ```typescript
 * const isValid = isValidCsrf(req, session.csrfToken, 'X-CSRF-TOKEN');
 * if (!isValid) {
 *   return new NextResponse(null, { status: 403 });
 * }
 * ```
 */
export function isValidCsrf(req: Request, csrfToken: string | undefined, csrfHeaderName: string): boolean {
  if (!csrfToken) {
    return false;
  }

  const headerValue = req.headers[csrfHeaderName];
  if (typeof headerValue !== 'string') {
    return false;
  }

  return csrfToken === headerValue;
}

/**
 * Sends appropriate error response based on failure reason.
 */
export function sendAuthFailureResponse(res: Response, reason: AuthFailureReason): void {
  let status: number;
  let errorMessage: string;

  switch (reason) {
    case 'unexpected_error':
      status = 500;
      errorMessage = 'Internal Server Error';
      break;
    case 'csrf_failed':
      status = 403;
      errorMessage = 'Forbidden';
      break;
    case 'not_authenticated':
    case 'token_refresh_failed':
    default:
      status = 401;
      errorMessage = 'Unauthorized';
  }

  res.status(status).json({ error: errorMessage });
}
