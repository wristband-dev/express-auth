import { Request, Response } from 'express';
import retry from 'async-retry';

import { LOGIN_REQUIRED_ERROR, TENANT_DOMAIN_TOKEN } from './utils/constants';
import {
  clearOldestLoginStateCookie,
  createLoginState,
  createLoginStateCookie,
  decryptLoginState,
  encryptLoginState,
  getAndClearLoginStateCookie,
  getOAuthAuthorizeUrl,
  isExpired,
  parseTenantSubdomain,
  resolveTenantDomain,
} from './utils';
import { WristbandService } from './wristband-service';
import {
  AuthConfig,
  CallbackConfig,
  CallbackData,
  LoginConfig,
  LoginState,
  LogoutConfig,
  TokenData,
  TokenResponse,
  Userinfo,
} from './types';
import { WristbandError } from './error';

export class AuthService {
  private wristbandService: WristbandService;
  private clientId: string;
  private customApplicationLoginPageUrl?: string;
  private dangerouslyDisableSecureCookies: boolean;
  private loginStateSecret: string;
  private loginUrl: string;
  private redirectUri: string;
  private rootDomain: string;
  private scopes: string[];
  private useCustomDomains: boolean;
  private useTenantSubdomains: boolean;
  private wristbandApplicationDomain: string;

  constructor(authConfig: AuthConfig) {
    if (!authConfig.clientId) {
      throw new TypeError('The [clientId] config must have a value.');
    }
    if (!authConfig.clientSecret) {
      throw new TypeError('The [clientSecret] config must have a value.');
    }
    if (!authConfig.loginStateSecret || authConfig.loginStateSecret.length < 32) {
      throw new TypeError('The [loginStateSecret] config must have a value of at least 32 characters.');
    }
    if (!authConfig.loginUrl) {
      throw new TypeError('The [loginUrl] config must have a value.');
    }
    if (!authConfig.redirectUri) {
      throw new TypeError('The [redirectUri] config must have a value.');
    }
    if (!authConfig.wristbandApplicationDomain) {
      throw new TypeError('The [wristbandApplicationDomain] config must have a value.');
    }
    if (authConfig.useTenantSubdomains) {
      if (!authConfig.rootDomain) {
        throw new TypeError('The [rootDomain] config must have a value when using tenant subdomains.');
      }
      if (!authConfig.loginUrl.includes(TENANT_DOMAIN_TOKEN)) {
        throw new TypeError('The [loginUrl] must contain the "{tenant_domain}" token when using tenant subdomains.');
      }
      if (!authConfig.redirectUri.includes(TENANT_DOMAIN_TOKEN)) {
        throw new TypeError('The [redirectUri] must contain the "{tenant_domain}" token when using tenant subdomains.');
      }
    } else {
      if (authConfig.loginUrl.includes(TENANT_DOMAIN_TOKEN)) {
        throw new TypeError(
          'The [loginUrl] cannot contain the "{tenant_domain}" token when tenant subdomains are not used.'
        );
      }
      if (authConfig.redirectUri.includes(TENANT_DOMAIN_TOKEN)) {
        throw new TypeError(
          'The [redirectUri] cannot contain the "{tenant_domain}" token when tenant subdomains are not used.'
        );
      }
    }

    this.wristbandService = new WristbandService(
      authConfig.wristbandApplicationDomain,
      authConfig.clientId,
      authConfig.clientSecret
    );
    this.clientId = authConfig.clientId;
    this.customApplicationLoginPageUrl = authConfig.customApplicationLoginPageUrl || '';
    this.dangerouslyDisableSecureCookies =
      typeof authConfig.dangerouslyDisableSecureCookies !== 'undefined'
        ? authConfig.dangerouslyDisableSecureCookies
        : false;
    this.loginStateSecret = authConfig.loginStateSecret;
    this.loginUrl = authConfig.loginUrl;
    this.redirectUri = authConfig.redirectUri;
    this.rootDomain = authConfig.rootDomain || '';
    this.scopes =
      !!authConfig.scopes && !!authConfig.scopes.length ? authConfig.scopes : ['openid', 'offline_access', 'email'];
    this.useCustomDomains = typeof authConfig.useCustomDomains !== 'undefined' ? authConfig.useCustomDomains : false;
    this.useTenantSubdomains =
      typeof authConfig.useTenantSubdomains !== 'undefined' ? authConfig.useTenantSubdomains : false;
    this.wristbandApplicationDomain = authConfig.wristbandApplicationDomain;
  }

  async login(req: Request, res: Response, config: LoginConfig = {}): Promise<void> {
    res.header('Cache-Control', 'no-store');
    res.header('Pragma', 'no-cache');

    // Make sure a valid tenantDomainName exists for multi-tenant apps.
    let tenantDomainName: string = '';
    tenantDomainName = resolveTenantDomain(req, this.useTenantSubdomains, this.rootDomain, config.defaultTenantDomain);
    if (!tenantDomainName) {
      const apploginUrl = this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationDomain}/login`;
      return res.redirect(`${apploginUrl}?client_id=${this.clientId}`);
    }

    // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
    const customState =
      !!config.customState && !!Object.keys(config.customState).length ? config.customState : undefined;
    const loginState: LoginState = createLoginState(req, this.redirectUri, { tenantDomainName, customState });

    // Clear any stale login state cookies and add a new one fo rthe current request.
    clearOldestLoginStateCookie(req, res);
    const encryptedLoginState: string = await encryptLoginState(loginState, this.loginStateSecret);
    createLoginStateCookie(res, loginState.state, encryptedLoginState, this.dangerouslyDisableSecureCookies);

    // Create the Wristband Authorize Endpoint URL which the user will get redirectd to.
    const authorizeUrl: string = getOAuthAuthorizeUrl(req, {
      wristbandApplicationDomain: this.wristbandApplicationDomain,
      useCustomDomains: this.useCustomDomains,
      clientId: this.clientId,
      redirectUri: this.redirectUri,
      state: loginState.state,
      codeVerifier: loginState.codeVerifier,
      scopes: this.scopes,
      tenantDomainName,
    });

    // Perform the redirect to Wristband's Authorize Endpoint.
    return res.redirect(authorizeUrl);
  }

  async callback(req: Request, res: Response, config: CallbackConfig = {}): Promise<CallbackData | void> {
    res.header('Cache-Control', 'no-store');
    res.header('Pragma', 'no-cache');

    // Safety checks -- Wristband backend should never send bad query params
    const { code, state: paramState, error, error_description: errorDescription } = req.query;
    if (!paramState || typeof paramState !== 'string') {
      throw new TypeError('Invalid query parameter [state] passed from Wristband during callback');
    }
    if (!!code && typeof code !== 'string') {
      throw new TypeError('Invalid query parameter [code] passed from Wristband during callback');
    }
    if (!!error && typeof error !== 'string') {
      throw new TypeError('Invalid query parameter [error] passed from Wristband during callback');
    }
    if (!!errorDescription && typeof errorDescription !== 'string') {
      throw new TypeError('Invalid query parameter [error_description] passed from Wristband during callback');
    }

    const appLoginLocation: string =
      this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationDomain}/login`;
    const appLoginUrl = `${appLoginLocation}?client_id=${this.clientId}`;
    const tenantSubdomain: string = this.useTenantSubdomains ? parseTenantSubdomain(req, this.rootDomain) : '';
    const defaultTenantDomain: string = config.defaultTenantDomain || '';

    let tenantLoginUrl: string = '';
    if (this.useTenantSubdomains) {
      tenantLoginUrl =
        !!tenantSubdomain || !!defaultTenantDomain
          ? this.loginUrl.replace(TENANT_DOMAIN_TOKEN, tenantSubdomain || defaultTenantDomain)
          : '';
    } else {
      tenantLoginUrl = defaultTenantDomain ? `${this.loginUrl}?tenant_domain=${defaultTenantDomain}` : '';
    }

    // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
    const loginStateCookie: string = getAndClearLoginStateCookie(req, res);
    if (!loginStateCookie) {
      return res.redirect(tenantLoginUrl || appLoginUrl);
    }
    const loginState: LoginState = await decryptLoginState(loginStateCookie, this.loginStateSecret);
    const { codeVerifier, customState, redirectUri, returnUrl, state: cookieState, tenantDomainName } = loginState;

    // Ensure there is a proper tenantDomain
    if (!this.useTenantSubdomains && !tenantDomainName) {
      return res.redirect(tenantLoginUrl || appLoginUrl);
    }
    if (this.useTenantSubdomains && tenantSubdomain !== tenantDomainName) {
      return res.redirect(tenantLoginUrl);
    }

    tenantLoginUrl = this.useTenantSubdomains ? tenantLoginUrl : `${this.loginUrl}?tenant_domain=${tenantDomainName}`;

    // Check for any potential error conditions
    if (paramState !== cookieState) {
      return res.redirect(tenantLoginUrl);
    }
    if (error) {
      if (error.toLowerCase() === LOGIN_REQUIRED_ERROR) {
        return res.redirect(tenantLoginUrl);
      }
      throw new WristbandError(error, errorDescription);
    }

    // Exchange the authorization code for tokens
    if (!code) {
      throw new TypeError('Invalid query parameter [code] passed from Wristband during callback');
    }
    const tokenResponse: TokenResponse = await this.wristbandService.getTokens(code, redirectUri, codeVerifier);
    const {
      access_token: accessToken,
      id_token: idToken,
      refresh_token: refreshToken,
      expires_in: expiresIn,
    } = tokenResponse;

    // Fetch the userinfo for the user logging in.
    const userinfo: Userinfo = await this.wristbandService.getUserinfo(accessToken);

    return {
      accessToken,
      ...(!!customState && { customState }),
      idToken,
      expiresIn,
      ...(!!refreshToken && { refreshToken }),
      ...(!!returnUrl && { returnUrl }),
      tenantDomainName,
      userinfo,
    };
  }

  async logout(req: Request, res: Response, config: LogoutConfig = {}): Promise<void> {
    res.header('Cache-Control', 'no-store');
    res.header('Pragma', 'no-cache');

    const { host } = req.headers;

    // Revoke the refresh token only if present.
    if (config.refreshToken) {
      try {
        await this.wristbandService.revokeRefreshToken(config.refreshToken);
      } catch (error) {
        // No need to block logout execution if revoking fails
        console.debug(`Revoking the refresh token failed during logout`);
      }
    }

    // The client ID is always required by the Wristband Logout Endpoint.
    const redirectUrl = config.redirectUrl ? `&redirect_url=${config.redirectUrl}` : '';
    const query = `client_id=${this.clientId}${redirectUrl}`;

    // Construct the appropriate Logout Endpoint URL that the user will get redirected to.
    const appLoginUrl: string =
      this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationDomain}/login`;
    if (this.useTenantSubdomains && host!.substring(host!.indexOf('.') + 1) !== this.rootDomain) {
      return res.redirect(`${appLoginUrl}?client_id=${this.clientId}`);
    }
    if (!this.useTenantSubdomains && !config.tenantDomainName) {
      return res.redirect(`${appLoginUrl}?client_id=${this.clientId}`);
    }

    // Always perform logout redirect to the Wristband logout endpoint.
    const tenantDomain = this.useTenantSubdomains ? host!.substring(0, host!.indexOf('.')) : config.tenantDomainName;
    const separator = this.useCustomDomains ? '.' : '-';
    const logoutUrl = `https://${tenantDomain}${separator}${this.wristbandApplicationDomain}/api/v1/logout?${query}`;
    return res.redirect(logoutUrl);
  }

  async refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null> {
    // Safety checks
    if (!refreshToken) {
      throw new TypeError('Refresh token must be a valid string');
    }
    if (!expiresAt || expiresAt < 0) {
      throw new TypeError('The expiresAt field must be an integer greater than 0');
    }

    // Nothing to do here if the access token is still valid.
    if (!isExpired(expiresAt)) {
      return null;
    }

    // Try up to 3 times to perform a token refresh.
    let tokenResponse: TokenResponse | null = null;
    await retry(
      async () => {
        tokenResponse = await this.wristbandService.refreshToken(refreshToken);
      },
      { retries: 2, minTimeout: 100, maxTimeout: 100 }
    );

    if (tokenResponse) {
      const {
        access_token: accessToken,
        id_token: idToken,
        expires_in: expiresIn,
        refresh_token: responseRefreshToken,
      } = tokenResponse;
      return { accessToken, idToken, refreshToken: responseRefreshToken, expiresIn };
    }

    // [Safety check] Errors during the refresh API call should bubble up, so this should never happen.
    throw new Error('Token response was null');
  }
}
