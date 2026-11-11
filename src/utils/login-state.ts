import { Request, Response } from 'express';

import { LOGIN_STATE_COOKIE_MAX_AGE_SEC, LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from './constants';
import { clearCookie, parseCookies, setCookie } from './cookies';
import { CookieCrypto, generateRandomString } from './crypto';
import { CryptoError } from '../error/crypto-error';
import { LoginState, LoginStateMapConfig } from '../types';

export function createLoginState(redirectUri: string, config: LoginStateMapConfig = {}): LoginState {
  return {
    state: generateRandomString(32),
    codeVerifier: generateRandomString(32),
    redirectUri,
    ...(!!config.returnUrl && typeof config.returnUrl === 'string' ? { returnUrl: config.returnUrl } : {}),
    ...(!!config.customState && !!Object.keys(config.customState).length ? { customState: config.customState } : {}),
  };
}

export async function encryptLoginState(loginState: LoginState, loginStateSecret: string): Promise<string> {
  try {
    return await CookieCrypto.encrypt(loginState, loginStateSecret);
  } catch (error) {
    if (error instanceof CryptoError && error.code === 'DATA_TOO_LARGE') {
      throw new TypeError(
        'Login state cookie exceeds 4kB in size. Ensure your [customState] and [returnUrl] values are a reasonable size.'
      );
    }
    if (
      error instanceof CryptoError &&
      error.code === 'ENCRYPTION_FAILED' &&
      error.message === 'Data must be JSON-serializable'
    ) {
      throw new TypeError('The [customState] value must be JSON-serializable.');
    }
    throw error;
  }
}

export async function decryptLoginState(
  loginStateCookie: string,
  loginStateSecret: string
): Promise<LoginState | null> {
  try {
    // The max age matches the login state cookie's Max-Age (1 hour)
    return await CookieCrypto.decrypt(loginStateCookie, loginStateSecret, LOGIN_STATE_COOKIE_MAX_AGE_SEC);
  } catch (error) {
    // Any crypto failure (tampered, expired, malformed, legacy format, or encrypted with a different secret)
    // means the cookie can't be trusted. Return null so the callback can redirect to login instead of failing.
    if (error instanceof CryptoError) {
      return null;
    }
    throw error;
  }
}

export function getLoginStateCookie(req: Request): { cookieName: string; loginStateCookie: string } {
  const { state } = req.query;
  const paramState = state ? state.toString() : '';
  const cookies = parseCookies(req);

  // This should always resolve to a single cookie with this prefix, or possibly no cookie at all
  // if it got cleared or expired before the callback was triggered.
  const matchingLoginCookieNames = Object.keys(cookies).filter((cookieName) => {
    return cookieName.startsWith(`${LOGIN_STATE_COOKIE_PREFIX}${paramState}${LOGIN_STATE_COOKIE_SEPARATOR}`);
  });

  if (matchingLoginCookieNames.length > 0) {
    const cookieName = matchingLoginCookieNames[0];
    return { cookieName, loginStateCookie: cookies[cookieName] };
  }

  return { cookieName: '', loginStateCookie: '' };
}

export function clearOldestLoginStateCookie(
  req: Request,
  res: Response,
  dangerouslyDisableSecureCookies: boolean,
  domain?: string
): void {
  const cookies = parseCookies(req);

  // The max amount of concurrent login state cookies we allow is 3.  If there are already 3 cookies,
  // then we clear the one with the oldest creation timestamp to make room for the new one.
  const allLoginCookieNames: string[] = Object.keys(cookies).filter((cookieName: string) => {
    return cookieName.startsWith(`${LOGIN_STATE_COOKIE_PREFIX}`);
  });

  // Retain only the 2 cookies with the most recent timestamps.
  if (allLoginCookieNames.length >= 3) {
    const mostRecentTimestamps: string[] = allLoginCookieNames
      .map((cookieName: string) => {
        return cookieName.split(LOGIN_STATE_COOKIE_SEPARATOR)[2];
      })
      .sort()
      .reverse()
      .slice(0, 2);

    allLoginCookieNames.forEach((cookieName: string) => {
      const timestamp: string = cookieName.split(LOGIN_STATE_COOKIE_SEPARATOR)[2];
      if (!mostRecentTimestamps.includes(timestamp)) {
        clearCookie(res, cookieName, dangerouslyDisableSecureCookies, domain);
      }
    });
  }
}

export function createLoginStateCookie(
  res: Response,
  state: string,
  encryptedLoginState: string,
  dangerouslyDisableSecureCookies: boolean,
  domain?: string
): void {
  // Add the new login state cookie (1 hour max age).
  const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}${state}${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now().valueOf()}`;
  setCookie(res, cookieName, encryptedLoginState, { maxAge: 3600, dangerouslyDisableSecureCookies, domain });
}
