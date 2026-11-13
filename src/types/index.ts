import type { SessionOptions } from '@wristband/typescript-session';
import type {
  AuthConfig as CoreAuthConfig,
  CallbackData,
  CallbackFailureReason,
  CallbackResultType,
  LoginConfig,
  LogoutConfig,
  NodeCallbackResult,
  TokenData,
  UserInfo,
  UserInfoRole,
} from '@wristband/typescript-auth';

// ==================================================== //
// ================== PUBLIC TYPES ==================== //
// ==================================================== //

// Login, callback, logout, and token types are shared with @wristband/typescript-auth, which implements those flows.
export type {
  CallbackData,
  CallbackFailureReason,
  CallbackResultType,
  LoginConfig,
  LogoutConfig,
  TokenData,
  UserInfo,
  UserInfoRole,
};

/**
 * Represents the configuration for Wristband authentication.
 *
 * Same as `AuthConfig` from `@wristband/typescript-auth`, except `trustProxyHeaders`: Express decides which proxy
 * headers to trust through the app's "trust proxy" setting.
 */
export type AuthConfig = Omit<CoreAuthConfig, 'trustProxyHeaders'>;

/**
 * Represents the result of the callback execution after authentication. It can contain the set of callback data
 * necessary for creating an authenticated session.
 *
 * This is a discriminated union type based on the `type` field:
 * - When `type` is `'completed'`, `callbackData` is present and `redirectUrl` is never present
 * - When `type` is `'redirect_required'`, `redirectUrl` is present and `callbackData` is never present
 */
export type CallbackResult = NodeCallbackResult;

/**
 * Authentication strategy for Wristband auth.
 *
 * Available strategies:
 * - `'SESSION'` - Session-based authentication using cookies
 * - `'JWT'` - JWT bearer token authentication
 */
export type AuthStrategy =
  /** Session-based authentication using cookies */
  | 'SESSION'
  /** JWT bearer token authentication */
  | 'JWT';

/**
 * Configuration for Wristband authentication middleware
 */
export interface AuthMiddlewareConfig {
  /**
   * Authentication strategies to use, in order of precedence.
   * At least one strategy is required.
   *
   * - ['SESSION']: Only session-based auth
   * - ['JWT']: Only JWT bearer token auth
   * - ['SESSION', 'JWT']: Try session first, fallback to JWT
   * - ['JWT', 'SESSION']: Try JWT first, fallback to session
   *
   * @example
   * ```typescript
   * authStrategies: [SESSION, JWT]
   * ```
   */
  authStrategies: AuthStrategy[];

  /**
   * Configuration specific to SESSION authentication strategy.
   * Required if SESSION is included in authStrategies.
   */
  sessionConfig?: {
    /**
     * Session configuration options including secrets and cookie settings.
     *
     * NOTE: If you set `enableCsrfProtection` to true in these options, the middleware will validate
     * CSRF tokens for all authenticated requests using the SESSION strategy. The CSRF token must be
     * present in the request header specified by `csrfTokenHeaderName` (default: 'X-CSRF-TOKEN').
     * JWT strategy does not perform CSRF validation.
     *
     * @example
     * ```typescript
     * sessionOptions: {
     *   secrets: process.env.SESSION_SECRET!,
     *   cookieName: 'my-session',
     *   maxAge: 24 * 60 * 60, // 24 hours
     * }
     * ```
     */
    sessionOptions: SessionOptions;

    /**
     * CSRF token header name (only used if `sessionOptions.enableCsrfProtection` is true).
     * Default: 'X-CSRF-TOKEN'
     */
    csrfTokenHeaderName?: string;
  };

  /**
   * Configuration specific to JWT strategy.
   * Optional (all settings rely on @wristband/typescript-jwt SDK defaults).
   */
  jwtConfig?: {
    /**
     * Maximum number of JWKs to cache.
     * Default: 20
     */
    jwksCacheMaxSize?: number;
    /**
     * Time-to-live for cached JWKs in milliseconds.
     * Default: Infinite (until evicted due to LRU cache eviction)
     */
    jwksCacheTtl?: number;
  };
}

// ====================================================== //
// ================== INTERNAL TYPES ==================== //
// ====================================================== //
/**
 * Reason why authentication failed during auth middleware execution.
 *
 * Available strategies:
 * - `'not_authenticated'` - No valid session or JWT token found
 * - `'csrf_failed'` - CSRF token validation failed (SESSION strategy only)
 * - `'token_refresh_failed'` - Token refresh attempt failed (SESSION strategy only)
 * - `'unexpected_error'` - Unexpected error occurred during authentication
 */
export type AuthFailureReason =
  /** No valid session or JWT token found */
  | 'not_authenticated'
  /** CSRF token validation failed (SESSION strategy only) */
  | 'csrf_failed'
  /** Token refresh attempt failed (SESSION strategy only) */
  | 'token_refresh_failed'
  /** Unexpected error occurred during authentication */
  | 'unexpected_error';

/**
 * Describes the outcome of running a single authentication strategy.
 *
 * A discriminated union that captures whether authentication succeeded or failed,
 * and provides specific failure reasons to enable proper error handling and HTTP
 * status code selection.
 *
 * @internal
 */
export type AuthStrategyResult =
  | {
      /** Authentication succeeded */
      authenticated: true;
      /** The strategy that produced successful authentication */
      usedStrategy: AuthStrategy;
      /** Never present on success */
      reason?: never;
    }
  | {
      /** Authentication failed */
      authenticated: false;
      /** Never present on failure */
      usedStrategy?: never;
      /** Why authentication failed */
      reason: AuthFailureReason;
    };

/**
 * Normalized auth middleware configuration with all defaults applied.
 * This is the internal configuration format used by the middleware after
 * processing the user-provided AuthMiddlewareConfig.
 *
 * @internal
 */
export interface NormalizedAuthMiddlewareConfig {
  /** Authentication strategies to use, in order of precedence */
  authStrategies: AuthStrategy[];
  /** Session authentication strategy configuration */
  sessionConfig: {
    /** Session options - only defined when SESSION strategy is used */
    sessionOptions?: SessionOptions;
    /** CSRF token header name (default: 'X-CSRF-TOKEN') */
    csrfTokenHeaderName: string;
  };
  /** JWT authentication strategy configuration */
  jwtConfig: {
    /** Maximum JWKs to cache - uses library default (20) when undefined */
    jwksCacheMaxSize?: number;
    /** JWK cache TTL in ms - uses library default of infinite when undefined */
    jwksCacheTtl?: number;
  };
}
