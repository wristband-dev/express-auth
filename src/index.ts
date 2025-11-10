import { InvalidGrantError, WristbandError } from './error';
import { createWristbandAuth, discoverWristbandAuth } from './factory';
import {
  AuthConfig,
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
  CallbackResultType,
  InvalidGrantError,
  WristbandError,
  type AuthConfig,
  type CallbackData,
  type CallbackResult,
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
 * Re-export session types from typescript-session
 *
 * These types are needed for session configuration and custom session data definitions.
 */
export {
  SessionError,
  SessionErrorCode,
  type SameSiteOption,
  type SessionData,
  type SessionOptions,
  type SessionResponse,
  type TokenResponse,
} from '@wristband/typescript-session';
