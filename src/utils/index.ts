import { createHash, randomBytes } from 'crypto';
import { Request, Response } from 'express';
import { defaults, seal, unseal } from 'iron-webcrypto';
import * as crypto from 'uncrypto';

import {
  LEADING_TENANT_PLACEHOLDER_REGEX,
  LOGIN_STATE_COOKIE_PREFIX,
  LOGIN_STATE_COOKIE_SEPARATOR,
  STATE_PARAM_MAX_CHAR_LENGTH,
  TENANT_NAME_PLACEHOLDER,
  TENANT_PLACEHOLDER_REGEX,
} from './constants';
import { LoginConfig, LoginState, LoginStateMapConfig } from '../types';
import { clearCookie, parseCookies, setCookie } from './cookies';
import { WristbandError } from '../error';

export function encodeBase64(input: string) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  let binary = '';
  data.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

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
  // @ts-expect-error - TODO: use our own encryption lib
  const encryptedLoginState: string = await seal(crypto, loginState, loginStateSecret, defaults);

  if (encryptedLoginState.length > 4096) {
    throw new TypeError(
      'Login state cookie exceeds 4kB in size. Ensure your [customState] and [returnUrl] values are a reasonable size.'
    );
  }

  return encryptedLoginState;
}

export async function decryptLoginState(loginStateCookie: string, loginStateSecret: string): Promise<LoginState> {
  // @ts-expect-error - TODO: use our own encryption lib
  const loginState: unknown = await unseal(crypto, loginStateCookie, loginStateSecret, defaults);
  return loginState as LoginState;
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

export function resolveRedirectUrl(req: Request, config: LoginConfig = {}): string | undefined {
  // The return URL from the LoginConfig takes priority over the query param.
  if (config.returnUrl) {
    return config.returnUrl;
  }

  const { return_url: returnUrlParam } = req.query;

  // If no return URL in either location, return undefined.
  if (!returnUrlParam) {
    return undefined;
  }

  if (typeof returnUrlParam !== 'string') {
    throw new TypeError('More than one [return_url] query parameter was encountered');
  }

  return returnUrlParam;
}

export function createLoginState(redirectUri: string, config: LoginStateMapConfig = {}): LoginState {
  return {
    state: generateRandomString(32),
    codeVerifier: generateRandomString(32),
    redirectUri,
    ...(!!config.returnUrl && typeof config.returnUrl === 'string' ? { returnUrl: config.returnUrl } : {}),
    ...(!!config.customState && !!Object.keys(config.customState).length ? { customState: config.customState } : {}),
  };
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

export function getAppLevelLoginUrl(
  wristbandApplicationVanityDomain: string,
  clientId: string,
  options: {
    customApplicationLoginPageUrl?: string;
    returnUrl?: string;
  } = {}
): string {
  // Safety check: this should never happen.
  if (!wristbandApplicationVanityDomain) {
    throw new Error('wristbandApplicationVanityDomain cannot be null or undefined');
  }
  if (!clientId) {
    throw new Error('clientId cannot be null or undefined');
  }

  const { customApplicationLoginPageUrl, returnUrl } = options;

  const apploginUrl = customApplicationLoginPageUrl || `https://${wristbandApplicationVanityDomain}/login`;
  const stateParam =
    returnUrl && returnUrl.length <= STATE_PARAM_MAX_CHAR_LENGTH ? `&state=${encodeURIComponent(returnUrl)}` : '';
  return `${apploginUrl}?client_id=${clientId}${stateParam}`;
}

export function getAuthorizationUrlParams(
  req: Request,
  config: {
    clientId: string;
    codeVerifier: string;
    redirectUri: string;
    scopes: string[];
    state: string;
  }
): URLSearchParams {
  const { idp_hint: idpHint, login_hint: loginHint } = req.query;

  if (!!idpHint && typeof idpHint !== 'string') {
    throw new TypeError('More than one [idp_hint] query parameter was encountered');
  }

  if (!!loginHint && typeof loginHint !== 'string') {
    throw new TypeError('More than one [login_hint] query parameter was encountered');
  }

  return new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    state: config.state,
    scope: config.scopes.join(' '),
    code_challenge: base64URLEncode(createHash('sha256').update(config.codeVerifier).digest('base64')),
    code_challenge_method: 'S256',
    nonce: generateRandomString(32),
    ...(!!idpHint && typeof idpHint === 'string' ? { idp_hint: idpHint } : {}),
    ...(!!loginHint && typeof loginHint === 'string' ? { login_hint: loginHint } : {}),
  });
}

export function getAppLevelAuthorizationUrl(
  wristbandApplicationVanityDomain: string,
  authorizationParams: URLSearchParams
): string {
  // Safety check: this should never happen.
  if (!wristbandApplicationVanityDomain) {
    throw new Error('wristbandApplicationVanityDomain cannot be null or undefined');
  }
  if (!authorizationParams || authorizationParams.size === 0) {
    throw new Error('authorizationParams cannot be null or empty');
  }

  return `https://${wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?${authorizationParams.toString()}`;
}

export function getTenantLevelAuthorizationUrl(
  wristbandApplicationVanityDomain: string,
  authorizationParams: URLSearchParams,
  config: {
    defaultTenantCustomDomain?: string;
    defaultTenantName?: string;
    tenantCustomDomain?: string;
    tenantName?: string;
    isApplicationCustomDomainActive?: boolean;
  }
): string {
  // Safety check: this should never happen.
  if (!wristbandApplicationVanityDomain) {
    throw new Error('wristbandApplicationVanityDomain cannot be null or undefined');
  }
  if (!authorizationParams || authorizationParams.size === 0) {
    throw new Error('authorizationParams cannot be null or empty');
  }

  // Safety check: this should never happen.
  if (
    !config.defaultTenantCustomDomain &&
    !config.defaultTenantName &&
    !config.tenantCustomDomain &&
    !config.tenantName
  ) {
    throw new Error('No tenant name or tenant custom domain was provided');
  }

  const queryString = authorizationParams.toString();
  const separator = config.isApplicationCustomDomainActive ? '.' : '-';

  // Domain priority order resolution:
  // 1)  tenant_custom_domain query param
  // 2a) tenant subdomain
  // 2b) tenant_name query param
  // 3)  defaultTenantCustomDomain login config
  // 4)  defaultTenantName login config
  if (config.tenantCustomDomain) {
    return `https://${config.tenantCustomDomain}/api/v1/oauth2/authorize?${queryString}`;
  }
  if (config.tenantName) {
    return `https://${config.tenantName}${separator}${wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?${queryString}`;
  }
  if (config.defaultTenantCustomDomain) {
    return `https://${config.defaultTenantCustomDomain}/api/v1/oauth2/authorize?${queryString}`;
  }
  return `https://${config.defaultTenantName}${separator}${wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?${queryString}`;
}

export function isExpired(expiresAt: number): boolean {
  const currentTime = Date.now().valueOf();
  return currentTime >= expiresAt;
}

/**
 * Validates a user-supplied returnUrl to prevent open redirects. Without this,
 * an attacker could craft a login link with returnUrl=https://evil.com so that
 * a legitimate login ends with the user being sent to a site they don't control.
 *
 * Returns the validated URL, or undefined if the returnUrl is missing,
 * malformed, or points to a host that isn't allowed.
 */
export function validateReturnUrl(
  req: Request,
  returnUrl: string | undefined,
  tenantName: string,
  applicationAuthorizationRequestsEnabled: boolean,
  parseTenantFromRootDomain?: string
): string | undefined {
  // Safety check: should never happen.
  if (!tenantName) {
    throw new WristbandError('missing_tenant_name', 'Tenant name is required to validate returnUrl');
  }

  // Return URL is optional during login
  if (!returnUrl) {
    return undefined;
  }

  try {
    // Resolve against the current request's origin so relative paths like "/settings"
    // land on the user's current host. Absolute URLs ignore the base, and the parser
    // normalizes tricks like "//evil.com" or "/\\evil.com" the same way the browser
    // will, so the hostname check below runs against the real redirect target.
    const url = new URL(returnUrl, `${req.protocol}://${req.get('host')}`);

    // Only allow redirects to the root domain or the exact host that served
    // this request, over the same protocol. Anything else is treated as
    // untrusted and discarded. The protocol check blocks downgrades like
    // https -> http.
    if (
      url.protocol !== `${req.protocol}:` ||
      (url.hostname !== parseTenantFromRootDomain && url.hostname !== req.hostname)
    ) {
      return undefined;
    }

    if (
      parseTenantFromRootDomain &&
      applicationAuthorizationRequestsEnabled &&
      url.hostname === parseTenantFromRootDomain
    ) {
      // The returnUrl points at the bare root domain, but the app expects
      // tenant subdomains. Prepend the resolved tenant so the user lands on
      // their tenant's host (e.g. myapp.com -> acme.myapp.com). Path, query,
      // and port are preserved by the URL object.
      url.hostname = `${tenantName}.${url.hostname}`;
      return url.toString();
    }

    // Allowed host and no tenant rewrite needed, so pass the returnUrl through unchanged.
    return returnUrl;
  } catch {
    // new URL() throws on malformed input. Treat anything unparseable as unsafe.
    return undefined;
  }
}

/**
 * Derives the fallback login URL from a login URL that uses the {tenant_name} placeholder.
 *
 * The placeholder must be the leftmost part of the hostname, e.g. https://{tenant_name}.example.com/auth/login.
 * The fallback login URL is the login URL with the placeholder removed, e.g. https://example.com/auth/login.
 * When the login URL has no placeholder, the result is an empty string.
 *
 * @param {string} loginUrl The application's login URL.
 * @returns {string} The derived fallback login URL, or an empty string.
 */
export function deriveFallbackLoginUrl(loginUrl: string): string {
  if (!loginUrl || !TENANT_PLACEHOLDER_REGEX.test(loginUrl)) {
    return '';
  }
  return loginUrl.replace(`${TENANT_NAME_PLACEHOLDER}.`, '');
}

/**
 * Derives the root domain used for parsing tenant subdomains from a login URL that uses the {tenant_name}
 * placeholder.
 *
 * The placeholder must be the leftmost part of the hostname, e.g. https://{tenant_name}.example.com/auth/login.
 * The root domain is the hostname with the placeholder removed, without any port, e.g. example.com.
 * When the login URL has no placeholder, the result is an empty string.
 *
 * @param {string} loginUrl The application's login URL.
 * @returns {string} The derived root domain, or an empty string.
 */
export function deriveTenantRootDomain(loginUrl: string): string {
  const fallbackLoginUrl = deriveFallbackLoginUrl(loginUrl);
  return fallbackLoginUrl ? new URL(fallbackLoginUrl).hostname : '';
}

/**
 * Checks that a URL containing the {tenant_name} placeholder has it exactly once, as the leftmost part of the
 * hostname. URLs without the placeholder are always considered valid.
 *
 * @param {string} url The URL to check.
 * @returns {boolean} True if the placeholder is absent or correctly positioned.
 */
export function isTenantPlaceholderPositionValid(url: string): boolean {
  if (!TENANT_PLACEHOLDER_REGEX.test(url)) {
    return true;
  }

  // The placeholder must be at the start of the hostname (e.g. https://{tenant_name}.example.com), and it must
  // be the only one. Removing that leading placeholder should leave no other {tenant_name} anywhere in the URL.
  return (
    LEADING_TENANT_PLACEHOLDER_REGEX.test(url) &&
    !TENANT_PLACEHOLDER_REGEX.test(url.replace(`${TENANT_NAME_PLACEHOLDER}.`, ''))
  );
}
