import { defaults, seal, unseal } from 'iron-webcrypto';
import * as crypto from 'uncrypto';

/**
 * Test-only login-state helpers. Not part of the public SDK.
 */
export type LoginState = {
  codeVerifier: string;
  customState?: Record<string, unknown>;
  redirectUri: string;
  returnUrl?: string;
  state: string;
};

export async function encryptLoginState(loginState: unknown, loginStateSecret: string): Promise<string> {
  // @ts-expect-error iron-webcrypto v1 seal typing
  return seal(crypto, loginState, loginStateSecret, defaults);
}

export async function decryptLoginState<T = LoginState>(
  loginStateCookie: string,
  loginStateSecret: string
): Promise<T> {
  // @ts-expect-error iron-webcrypto v1 unseal typing
  return unseal(crypto, loginStateCookie, loginStateSecret, defaults) as Promise<T>;
}

export const LOGIN_STATE_COOKIE_SEPARATOR = '#';
