import type { JWTPayload } from '@wristband/typescript-jwt';

/**
 * JWT type augmentation for Express.
 *
 * Import this module to enable TypeScript support for `req.auth` when using JWT authentication strategy.
 * This augments the Express Request type to include the decoded JWT payload and bearer token.
 *
 * @example
 * ```typescript
 * // At the top of your wristband.ts setup file
 * import '@wristband/express-auth/jwt';
 *
 * // In your route handlers protected by JWT auth middleware
 * app.get('/api/orders', requireAuth, (req, res) => {
 *   // req.auth is always defined after requireAuth middleware
 *   const userId = req.auth.sub;
 *   const tenantId = req.auth.tnt_id;
 *   const token = req.auth.jwt;
 *
 *   // Validate required claims
 *   if (!userId || !tenantId) {
 *     return res.status(401).json({ error: 'Invalid token' });
 *   }
 *
 *   res.json({ userId, tenantId });
 * });
 * ```
 */
declare module 'express-serve-static-core' {
  interface Request {
    /**
     * Decoded JWT payload and bearer token.
     *
     * Always defined as an object (initialized by auth middleware). In routes protected by JWT
     * authentication middleware, this contains the decoded JWT claims and the bearer token string.
     * In unprotected routes or before authentication, this will be an empty object.
     *
     * **Standard JWT Claims** (all optional):
     * - `sub` - Subject identifier (typically user ID)
     * - `iss` - Issuer (who created the token)
     * - `aud` - Audience (who the token is intended for)
     * - `exp` - Expiration time (Unix timestamp)
     * - `iat` - Issued at time (Unix timestamp)
     * - `jti` - JWT ID (unique identifier)
     *
     * **Wristband-Specific Claims**:
     * - `tnt_id` - Tenant ID
     * - `app_id` - Application ID
     * - `idp_name` - Identity provider name
     *
     * **Additional Properties**:
     * - `jwt` - The bearer token string (only present after successful JWT authentication)
     * - Any custom claims included in your JWT
     *
     * @see https://github.com/wristband-dev/express-auth#jwt-authentication
     *
     * @example
     * ```typescript
     * // Accessing claims in a protected route
     * if (!req.auth.sub) {
     *   return res.status(401).json({ error: 'Missing user ID' });
     * }
     * const userId: string = req.auth.sub;
     * ```
     */
    auth: JWTPayload & { jwt?: string };
  }
}

// Required for module augmentation to work
export {};
