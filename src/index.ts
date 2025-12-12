import { WristbandError } from './error';
import { createWristbandAuth, discoverWristbandAuth } from './factory';
import type {
  AuthConfig,
  AuthMiddlewareConfig,
  AuthStrategy,
  CallbackData,
  CallbackResult,
  CallbackResultType,
  LoginConfig,
  LogoutConfig,
  TokenData,
  UserInfo,
  UserInfoRole,
} from './types';
import { WristbandAuth } from './wristband-auth';

/**
 * Public auth exports
 */
export {
  createWristbandAuth,
  discoverWristbandAuth,
  WristbandError,
  type AuthConfig,
  type AuthMiddlewareConfig,
  type AuthStrategy,
  type CallbackData,
  type CallbackResult,
  type CallbackResultType,
  type LoginConfig,
  type LogoutConfig,
  type TokenData,
  type UserInfo,
  type UserInfoRole,
  type WristbandAuth,
};

/**
 * Session middleware export
 *
 * NOTE: This export uses inline re-export syntax to ensure the session module
 * is only loaded when explicitly imported. This prevents the Express.Request type
 * augmentation from being applied to users who only use auth features without session
 * middleware, avoiding type conflicts with other session libraries.
 *
 * When imported, this automatically augments Express.Request with the `session` property.
 */
export { createWristbandSession } from './session';

/**
 * Re-export session types from typescript-session (type-only, safe)
 */
export type {
  SameSiteOption,
  Session,
  SessionData,
  SessionOptions,
  SessionResponse,
  TokenResponse,
} from '@wristband/typescript-session';

/**
 * Session error class exports
 *
 * ⚠️ WARNING: These are runtime value exports. Importing them will load the
 * @wristband/typescript-session module and trigger Express.Request augmentation.
 *
 * Only import these if you're using createWristbandSession() middleware.
 */
export { SessionError, SessionErrorCode } from '@wristband/typescript-session';

/**
 * Re-export JWT types and utilities from typescript-jwt (type-only, safe)
 */
export type {
  JWTPayload,
  JwtValidationResult,
  WristbandJwtValidator,
  WristbandJwtValidatorConfig,
} from '@wristband/typescript-jwt';

/**
 * Re-export JWT validator factory from typescript-jwt (runtime value)
 */
export { createWristbandJwtValidator } from '@wristband/typescript-jwt';
