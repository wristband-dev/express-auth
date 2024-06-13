/* eslint-disable import/no-extraneous-dependencies */
import { createHash, randomBytes } from 'crypto';
import { Request, Response } from 'express';
import { defaults, seal, unseal } from 'iron-webcrypto';
import * as crypto from 'uncrypto';

import { LOGIN_STATE_COOKIE_PREFIX } from './constants';
import { LoginState, LoginStateMapConfig } from '../types';

export function generateRandomString(length: number): string {
  return randomBytes(length).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function base64URLEncode(str: string): string {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export async function encryptLoginState(loginState: LoginState, loginStateSecret: string): Promise<string> {
  const encryptedLoginState: string = await seal(crypto, loginState, loginStateSecret, defaults);

  if (encryptedLoginState.length > 4096) {
    throw new TypeError(
      'Login state cookie exceeds 4kB in size. Ensure your [customState] and [returnUrl] values are a reasonable size.'
    );
  }

  return encryptedLoginState;
}

export async function decryptLoginState(loginStateCookie: string, loginStateSecret: string): Promise<LoginState> {
  const loginState: unknown = await unseal(crypto, loginStateCookie, loginStateSecret, defaults);
  return loginState as LoginState;
}

export function getAndClearLoginStateCookie(req: Request, res: Response): string {
  const { state } = req.query;
  const paramState = state ? state.toString() : '';

  // This should always resolve to a single cookie with this prefix, or possibly no cookie at all
  // if it got cleared or expired before the callback was triggered.
  const matchingLoginCookieNames = Object.keys(req.cookies).filter((cookieName) => {
    return cookieName.startsWith(`${LOGIN_STATE_COOKIE_PREFIX}${paramState}:`);
  });

  let loginStateCookie = '';

  if (matchingLoginCookieNames.length > 0) {
    const cookieName = matchingLoginCookieNames[0];
    loginStateCookie = req.cookies[cookieName];
    res.clearCookie(cookieName);
  }

  return loginStateCookie;
}

export function parseTenantSubdomain(req: Request, rootDomain: string): string {
  const { host } = req.headers;
  return host!.substring(host!.indexOf('.') + 1) === rootDomain ? host!.substring(0, host!.indexOf('.')) : '';
}

export function resolveTenantDomain(req: Request, useTenantSubdomains: boolean, rootDomain: string): string {
  if (useTenantSubdomains) {
    return parseTenantSubdomain(req, rootDomain);
  }

  const { tenant_domain: tenantDomainParam } = req.query;

  if (!!tenantDomainParam && typeof tenantDomainParam !== 'string') {
    throw new TypeError('More than one [tenant_domain] query parameter was passed to the login endpoint');
  }

  return tenantDomainParam || '';
}

export function createLoginState(req: Request, redirectUri: string, config: LoginStateMapConfig = {}): LoginState {
  const { return_url: returnUrl } = req.query;

  if (!!returnUrl && typeof returnUrl !== 'string') {
    throw new TypeError('More than one [return_url] query parameter was passed to the login endpoint');
  }

  const loginStateData = {
    state: generateRandomString(32),
    codeVerifier: generateRandomString(32),
    redirectUri,
    ...(!!config.tenantDomainName && { tenantDomainName: config.tenantDomainName }),
    ...(!!returnUrl && typeof returnUrl === 'string' ? { returnUrl } : {}),
    ...(!!config.customState && !!Object.keys(config.customState).length ? { customState: config.customState } : {}),
  };

  return config.customState ? { ...loginStateData, customState: config.customState } : loginStateData;
}

export function clearOldestLoginStateCookie(req: Request, res: Response): void {
  const { cookies } = req;

  // The max amount of concurrent login state cookies we allow is 3.  If there are already 3 cookies,
  // then we clear the one with the oldest creation timestamp to make room for the new one.
  const allLoginCookieNames: string[] = Object.keys(cookies).filter((cookieName: string) => {
    return cookieName.startsWith(`${LOGIN_STATE_COOKIE_PREFIX}`);
  });

  // Retain only the 2 cookies with the most recent timestamps.
  if (allLoginCookieNames.length >= 3) {
    const mostRecentTimestamps: string[] = allLoginCookieNames
      .map((cookieName: string) => {
        return cookieName.split(':')[2];
      })
      .sort()
      .reverse()
      .slice(0, 2);

    allLoginCookieNames.forEach((cookieName: string) => {
      const timestamp: string = cookieName.split(':')[2];
      if (!mostRecentTimestamps.includes(timestamp)) {
        res.clearCookie(cookieName);
      }
    });
  }
}

export function createLoginStateCookie(
  res: Response,
  state: string,
  encryptedLoginState: string,
  dangerouslyDisableSecureCookies: boolean
): void {
  // Add the new login state cookie (1 hour max age).
  res.cookie(`${LOGIN_STATE_COOKIE_PREFIX}${state}:${Date.now().valueOf()}`, encryptedLoginState, {
    httpOnly: true,
    maxAge: 3600000,
    path: '/',
    sameSite: 'lax',
    secure: !dangerouslyDisableSecureCookies,
  });
}

export function getOAuthAuthorizeUrl(
  req: Request,
  config: {
    clientId: string;
    codeVerifier: string;
    redirectUri: string;
    scopes: string[];
    state: string;
    tenantDomainName?: string;
    useCustomDomains?: boolean;
    wristbandApplicationDomain: string;
  }
): string {
  const { login_hint: loginHint } = req.query;

  if (!!loginHint && typeof loginHint !== 'string') {
    throw new TypeError('More than one [login_hint] query parameter was passed to the login endpoint');
  }

  const queryParams = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    state: config.state,
    scope: config.scopes.join(' '),
    code_challenge: base64URLEncode(createHash('sha256').update(config.codeVerifier).digest('base64')),
    code_challenge_method: 'S256',
    nonce: generateRandomString(32),
    ...(!!loginHint && typeof loginHint === 'string' ? { login_hint: loginHint } : {}),
  });

  const separator = config.useCustomDomains ? '.' : '-';
  const authorizeUrl = `${config.tenantDomainName}${separator}${config.wristbandApplicationDomain}/api/v1/oauth2/authorize`;
  return `https://${authorizeUrl}?${queryParams.toString()}`;
}

export function isExpired(expiresAt: number): boolean {
  const currentTime = Date.now().valueOf();
  return currentTime >= expiresAt;
}
