import { createHash, randomBytes } from 'crypto';
import { Request, Response } from 'express';
import { defaults, seal, unseal } from 'iron-webcrypto';
import * as crypto from 'uncrypto';

import { LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from './constants';
import { LoginState, LoginStateMapConfig } from '../types';
import { clearCookie, parseCookies, setCookie } from './cookies';

export function parseTenantSubdomain(req: Request, parseTenantFromRootDomain: string): string {
  const { host } = req.headers;

  // Should never happen (defensive measure)
  if (!host) {
    return '';
  }

  // Strip off the port if it exists
  const hostname = host.split(':')[0];

  return hostname.substring(hostname.indexOf('.') + 1) === parseTenantFromRootDomain
    ? hostname.substring(0, hostname.indexOf('.'))
    : '';
}

export function generateRandomString(length: number): string {
  return randomBytes(length).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function base64URLEncode(str: string): string {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export async function encryptLoginState(loginState: LoginState, loginStateSecret: string): Promise<string> {
  // @ts-ignore
  const encryptedLoginState: string = await seal(crypto, loginState, loginStateSecret, defaults);

  if (encryptedLoginState.length > 4096) {
    throw new TypeError(
      'Login state cookie exceeds 4kB in size. Ensure your [customState] and [returnUrl] values are a reasonable size.'
    );
  }

  return encryptedLoginState;
}

export async function decryptLoginState(loginStateCookie: string, loginStateSecret: string): Promise<LoginState> {
  // @ts-ignore
  const loginState: unknown = await unseal(crypto, loginStateCookie, loginStateSecret, defaults);
  return loginState as LoginState;
}

export function getAndClearLoginStateCookie(
  req: Request,
  res: Response,
  dangerouslyDisableSecureCookies: boolean
): string {
  const { state } = req.query;
  const paramState = state ? state.toString() : '';
  const cookies = parseCookies(req);

  // This should always resolve to a single cookie with this prefix, or possibly no cookie at all
  // if it got cleared or expired before the callback was triggered.
  const matchingLoginCookieNames = Object.keys(cookies).filter((cookieName) => {
    return cookieName.startsWith(`${LOGIN_STATE_COOKIE_PREFIX}${paramState}${LOGIN_STATE_COOKIE_SEPARATOR}`);
  });

  let loginStateCookie = '';

  if (matchingLoginCookieNames.length > 0) {
    const cookieName = matchingLoginCookieNames[0];
    loginStateCookie = cookies[cookieName];
    clearCookie(res, cookieName, dangerouslyDisableSecureCookies);
  }

  return loginStateCookie;
}

export function resolveTenantName(req: Request, parseTenantFromRootDomain: string): string {
  if (parseTenantFromRootDomain) {
    return parseTenantSubdomain(req, parseTenantFromRootDomain) || '';
  }

  const { tenant_name: tenantNameParam } = req.query;

  if (!!tenantNameParam && typeof tenantNameParam !== 'string') {
    throw new TypeError('More than one [tenant_name] query parameter was encountered');
  }

  return tenantNameParam || '';
}

export function resolveTenantCustomDomainParam(req: Request): string {
  const { tenant_custom_domain: tenantCustomDomainParam } = req.query;

  if (!!tenantCustomDomainParam && typeof tenantCustomDomainParam !== 'string') {
    throw new TypeError('More than one [tenant_custom_domain] query parameter was encountered');
  }

  return tenantCustomDomainParam || '';
}

export function createLoginState(req: Request, redirectUri: string, config: LoginStateMapConfig = {}): LoginState {
  const { return_url: returnUrlParam } = req.query;

  if (!!returnUrlParam && typeof returnUrlParam !== 'string') {
    throw new TypeError('More than one [return_url] query parameter was encountered');
  }

  const returnUrl = config.returnUrl ?? returnUrlParam;

  const loginStateData = {
    state: generateRandomString(32),
    codeVerifier: generateRandomString(32),
    redirectUri,
    ...(!!returnUrl && typeof returnUrl === 'string' ? { returnUrl } : {}),
    ...(!!config.customState && !!Object.keys(config.customState).length ? { customState: config.customState } : {}),
  };

  return config.customState ? { ...loginStateData, customState: config.customState } : loginStateData;
}

export function clearOldestLoginStateCookie(
  req: Request,
  res: Response,
  dangerouslyDisableSecureCookies: boolean
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
        clearCookie(res, cookieName, dangerouslyDisableSecureCookies);
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
  const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}${state}${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now().valueOf()}`;
  setCookie(res, cookieName, encryptedLoginState, { maxAge: 3600, dangerouslyDisableSecureCookies });
}

export function getOAuthAuthorizeUrl(
  req: Request,
  config: {
    clientId: string;
    codeVerifier: string;
    defaultTenantCustomDomain?: string;
    defaultTenantName?: string;
    redirectUri: string;
    scopes: string[];
    state: string;
    tenantCustomDomain?: string;
    tenantName?: string;
    isApplicationCustomDomainActive?: boolean;
    wristbandApplicationVanityDomain: string;
  }
): string {
  const { login_hint: loginHint } = req.query;

  if (!!loginHint && typeof loginHint !== 'string') {
    throw new TypeError('More than one [login_hint] query parameter was encountered');
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

  const separator = config.isApplicationCustomDomainActive ? '.' : '-';

  // Domain priority order resolution:
  // 1)  tenant_custom_domain query param
  // 2a) tenant subdomain
  // 2b) tenant_name query param
  // 3)  defaultTenantCustomDomain login config
  // 4)  defaultTenantName login config
  if (config.tenantCustomDomain) {
    return `https://${config.tenantCustomDomain}/api/v1/oauth2/authorize?${queryParams.toString()}`;
  }
  if (config.tenantName) {
    return `https://${config.tenantName}${separator}${config.wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?${queryParams.toString()}`;
  }
  if (config.defaultTenantCustomDomain) {
    return `https://${config.defaultTenantCustomDomain}/api/v1/oauth2/authorize?${queryParams.toString()}`;
  }
  return `https://${config.defaultTenantName}${separator}${config.wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?${queryParams.toString()}`;
}

export function isExpired(expiresAt: number): boolean {
  const currentTime = Date.now().valueOf();
  return currentTime >= expiresAt;
}
