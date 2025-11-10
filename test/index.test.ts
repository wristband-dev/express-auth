/* eslint-disable import/no-extraneous-dependencies */

import {
  createWristbandAuth,
  discoverWristbandAuth,
  CallbackResultType,
  InvalidGrantError,
  WristbandError,
  createWristbandSession,
  SessionError,
  SessionErrorCode,
  type AuthConfig,
  type CallbackData,
  type CallbackResult,
  type LoginConfig,
  type LogoutConfig,
  type TokenData,
  type UserInfo,
  type UserInfoRole,
  type WristbandAuth,
  type SameSiteOption,
  type SessionData,
  type SessionOptions,
  type SessionResponse,
  type TokenResponse,
} from '../src/index';

describe('Public API Exports', () => {
  test('All factory functions are exported', () => {
    expect(typeof createWristbandAuth).toBe('function');
    expect(typeof discoverWristbandAuth).toBe('function');
    expect(typeof createWristbandSession).toBe('function');
  });

  test('All error classes are exported', () => {
    expect(typeof WristbandError).toBe('function');
    expect(typeof InvalidGrantError).toBe('function');
    expect(typeof SessionError).toBe('function');
  });

  test('All enums are exported', () => {
    expect(typeof CallbackResultType).toBe('object');
    expect(CallbackResultType.COMPLETED).toBe('COMPLETED');
    expect(CallbackResultType.REDIRECT_REQUIRED).toBe('REDIRECT_REQUIRED');
    expect(typeof SessionErrorCode).toBe('object');
  });

  test('All type exports are importable', () => {
    // Just verify TypeScript compilation succeeds with these type imports
    const authConfig: AuthConfig = null as any;
    const callbackData: CallbackData = null as any;
    const callbackResult: CallbackResult = null as any;
    const loginConfig: LoginConfig = null as any;
    const logoutConfig: LogoutConfig = null as any;
    const tokenData: TokenData = null as any;
    const userInfo: UserInfo = null as any;
    const userInfoRole: UserInfoRole = null as any;
    const wristbandAuth: WristbandAuth = null as any;
    const sameSiteOption: SameSiteOption = null as any;
    const sessionData: SessionData = null as any;
    const sessionOptions: SessionOptions = null as any;
    const sessionResponse: SessionResponse = null as any;
    const tokenResponse: TokenResponse = null as any;

    expect(authConfig).toBeDefined();
    expect(callbackData).toBeDefined();
    expect(callbackResult).toBeDefined();
    expect(loginConfig).toBeDefined();
    expect(logoutConfig).toBeDefined();
    expect(tokenData).toBeDefined();
    expect(userInfo).toBeDefined();
    expect(userInfoRole).toBeDefined();
    expect(wristbandAuth).toBeDefined();
    expect(sameSiteOption).toBeDefined();
    expect(sessionData).toBeDefined();
    expect(sessionOptions).toBeDefined();
    expect(sessionResponse).toBeDefined();
    expect(tokenResponse).toBeDefined();
  });
});
