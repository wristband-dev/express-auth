import { Request, Response } from 'express';
import retry from 'async-retry';
import { AxiosError } from 'axios';

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
  resolveTenantCustomDomainParam,
  resolveTenantDomainName,
} from './utils';
import { WristbandService } from './wristband-service';
import {
  AuthConfig,
  CallbackData,
  CallbackResult,
  CallbackResultType,
  LoginConfig,
  LoginState,
  LogoutConfig,
  TokenData,
  TokenResponse,
  Userinfo,
} from './types';
import { InvalidGrantError, WristbandError } from './error';

export class AuthService {
  private wristbandService: WristbandService;
  private clientId: string;
  private customApplicationLoginPageUrl?: string;
  private dangerouslyDisableSecureCookies: boolean;
  private isApplicationCustomDomainActive: boolean;
  private loginStateSecret: string;
  private loginUrl: string;
  private parseTenantFromRootDomain: string;
  private redirectUri: string;
  private scopes: string[];
  private wristbandApplicationVanityDomain: string;

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
    if (!authConfig.wristbandApplicationVanityDomain) {
      throw new TypeError('The [wristbandApplicationVanityDomain] config must have a value.');
    }
    if (authConfig.parseTenantFromRootDomain) {
      if (!authConfig.loginUrl.includes(TENANT_DOMAIN_TOKEN)) {
        throw new TypeError(
          'The [loginUrl] must contain the "{tenant_domain}" token when using the [parseTenantFromRootDomain] config.'
        );
      }
      if (!authConfig.redirectUri.includes(TENANT_DOMAIN_TOKEN)) {
        throw new TypeError(
          'The [redirectUri] must contain the "{tenant_domain}" token when using the [parseTenantFromRootDomain] config.'
        );
      }
    } else {
      if (authConfig.loginUrl.includes(TENANT_DOMAIN_TOKEN)) {
        throw new TypeError(
          'The [loginUrl] cannot contain the "{tenant_domain}" token when the [parseTenantFromRootDomain] is absent.'
        );
      }
      if (authConfig.redirectUri.includes(TENANT_DOMAIN_TOKEN)) {
        throw new TypeError(
          'The [redirectUri] cannot contain the "{tenant_domain}" token when the [parseTenantFromRootDomain] is absent.'
        );
      }
    }

    this.wristbandService = new WristbandService(
      authConfig.wristbandApplicationVanityDomain,
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
    this.parseTenantFromRootDomain = authConfig.parseTenantFromRootDomain || '';
    this.scopes =
      !!authConfig.scopes && !!authConfig.scopes.length ? authConfig.scopes : ['openid', 'offline_access', 'email'];
    this.isApplicationCustomDomainActive =
      typeof authConfig.isApplicationCustomDomainActive !== 'undefined'
        ? authConfig.isApplicationCustomDomainActive
        : false;
    this.wristbandApplicationVanityDomain = authConfig.wristbandApplicationVanityDomain;
  }

  async login(req: Request, res: Response, config: LoginConfig = {}): Promise<string> {
    res.header('Cache-Control', 'no-store');
    res.header('Pragma', 'no-cache');

    // Determine which domain-related values are present as it will be needed for the authorize URL.
    const tenantCustomDomain: string = resolveTenantCustomDomainParam(req);
    const tenantDomainName: string = resolveTenantDomainName(req, this.parseTenantFromRootDomain);
    const defaultTenantCustomDomain: string = config.defaultTenantCustomDomain || '';
    const defaultTenantDomainName: string = config.defaultTenantDomainName || '';

    // In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
    if (!tenantCustomDomain && !tenantDomainName && !defaultTenantCustomDomain && !defaultTenantDomainName) {
      const apploginUrl =
        this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationVanityDomain}/login`;
      return `${apploginUrl}?client_id=${this.clientId}`;
    }

    // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
    const customState =
      !!config.customState && !!Object.keys(config.customState).length ? config.customState : undefined;
    const loginState: LoginState = createLoginState(req, this.redirectUri, { customState });

    // Clear any stale login state cookies and add a new one fo rthe current request.
    clearOldestLoginStateCookie(req, res, this.dangerouslyDisableSecureCookies);
    const encryptedLoginState: string = await encryptLoginState(loginState, this.loginStateSecret);
    createLoginStateCookie(res, loginState.state, encryptedLoginState, this.dangerouslyDisableSecureCookies);

    // Return the Wristband Authorize Endpoint URL which the user will get redirectd to.
    return getOAuthAuthorizeUrl(req, {
      wristbandApplicationVanityDomain: this.wristbandApplicationVanityDomain,
      isApplicationCustomDomainActive: this.isApplicationCustomDomainActive,
      clientId: this.clientId,
      redirectUri: this.redirectUri,
      state: loginState.state,
      codeVerifier: loginState.codeVerifier,
      scopes: this.scopes,
      tenantCustomDomain,
      tenantDomainName,
      defaultTenantDomainName,
      defaultTenantCustomDomain,
    });
  }

  async callback(req: Request, res: Response): Promise<CallbackResult> {
    res.header('Cache-Control', 'no-store');
    res.header('Pragma', 'no-cache');

    // Safety checks -- Wristband backend should never send bad query params
    const {
      code,
      state: paramState,
      error,
      error_description: errorDescription,
      tenant_custom_domain: tenantCustomDomainParam,
    } = req.query;
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
    if (!!tenantCustomDomainParam && typeof tenantCustomDomainParam !== 'string') {
      throw new TypeError('Invalid query parameter [tenant_custom_domain] passed from Wristband during callback');
    }

    // Resolve and validate the tenant domain name
    const resolvedTenantDomainName: string = resolveTenantDomainName(req, this.parseTenantFromRootDomain);
    if (!resolvedTenantDomainName) {
      throw new WristbandError(
        this.parseTenantFromRootDomain ? 'missing_tenant_subdomain' : 'missing_tenant_domain',
        this.parseTenantFromRootDomain
          ? 'Callback request URL is missing a tenant subdomain'
          : 'Callback request is missing the [tenant_domain] query parameter from Wristband'
      );
    }

    // Construct the tenant login URL in the event we have to redirect to the login endpoint
    let tenantLoginUrl: string = this.parseTenantFromRootDomain
      ? this.loginUrl.replace(TENANT_DOMAIN_TOKEN, resolvedTenantDomainName)
      : `${this.loginUrl}?tenant_domain=${resolvedTenantDomainName}`;
    if (tenantCustomDomainParam) {
      tenantLoginUrl = `${tenantLoginUrl}${this.parseTenantFromRootDomain ? '?' : '&'}tenant_custom_domain=${tenantCustomDomainParam}`;
    }

    // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
    const loginStateCookie: string = getAndClearLoginStateCookie(req, res, this.dangerouslyDisableSecureCookies);
    if (!loginStateCookie) {
      return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
    }
    const loginState: LoginState = await decryptLoginState(loginStateCookie, this.loginStateSecret);
    const { codeVerifier, customState, redirectUri, returnUrl, state: cookieState } = loginState;

    // Check for any potential error conditions
    if (paramState !== cookieState) {
      return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
    }
    if (error) {
      if (error.toLowerCase() === LOGIN_REQUIRED_ERROR) {
        return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
      }
      throw new WristbandError(error, errorDescription);
    }

    // Exchange the authorization code for tokens
    if (!code) {
      throw new TypeError('Invalid query parameter [code] passed from Wristband during callback');
    }
    try {
      const tokenResponse: TokenResponse = await this.wristbandService.getTokens(code, redirectUri, codeVerifier);
      const {
        access_token: accessToken,
        id_token: idToken,
        refresh_token: refreshToken,
        expires_in: expiresIn,
      } = tokenResponse;

      // Fetch the userinfo for the user logging in.
      const userinfo: Userinfo = await this.wristbandService.getUserinfo(accessToken);

      const callbackData: CallbackData = {
        accessToken,
        ...(!!customState && { customState }),
        idToken,
        expiresIn,
        ...(!!refreshToken && { refreshToken }),
        ...(!!returnUrl && { returnUrl }),
        ...(!!tenantCustomDomainParam && { tenantCustomDomain: tenantCustomDomainParam }),
        tenantDomainName: resolvedTenantDomainName,
        userinfo,
      };
      return { type: CallbackResultType.COMPLETED, callbackData };
    } catch (ex) {
      if (ex instanceof InvalidGrantError) {
        return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
      }
      throw ex;
    }
  }

  async logout(req: Request, res: Response, config: LogoutConfig = { tenantCustomDomain: '' }): Promise<string> {
    res.header('Cache-Control', 'no-store');
    res.header('Pragma', 'no-cache');

    const { host } = req.headers;
    const { tenant_custom_domain: tenantCustomDomainParam, tenant_domain: tenantDomainParam } = req.query;

    if (!!tenantCustomDomainParam && typeof tenantCustomDomainParam !== 'string') {
      throw new TypeError('More than one [tenant_custom_domain] query parameter was encountered during logout');
    }
    if (!!tenantDomainParam && typeof tenantDomainParam !== 'string') {
      throw new TypeError('More than one [tenant_domain] query parameter was encountered during logout');
    }

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
    const separator = this.isApplicationCustomDomainActive ? '.' : '-';

    // Domain priority order resolution:
    // 1) If the LogoutConfig has a tenant custom domain explicitly defined, use that.
    // 2) If the LogoutConfig has a tenant domain defined, then use that.
    // 3) If the tenant_custom_domain query param exists, then use that.
    // 4a) If tenant subdomains are enabled, get the tenant domain from the host.
    // 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_domain query param.
    let tenantDomainToUse = '';
    if (config.tenantCustomDomain) {
      tenantDomainToUse = config.tenantCustomDomain;
    } else if (config.tenantDomainName) {
      tenantDomainToUse = `${config.tenantDomainName}${separator}${this.wristbandApplicationVanityDomain}`;
    } else if (tenantCustomDomainParam) {
      tenantDomainToUse = tenantCustomDomainParam;
    } else if (
      this.parseTenantFromRootDomain &&
      host &&
      host!.substring(host!.indexOf('.') + 1) === this.parseTenantFromRootDomain
    ) {
      const tenantDomainNameFromHost = host!.substring(0, host!.indexOf('.'));
      tenantDomainToUse = `${tenantDomainNameFromHost}${separator}${this.wristbandApplicationVanityDomain}`;
    } else if (tenantDomainParam) {
      tenantDomainToUse = `${tenantDomainParam}${separator}${this.wristbandApplicationVanityDomain}`;
    } else {
      // Construct the appropriate fallback URL that the user will get redirected to.
      const appLoginUrl: string =
        this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationVanityDomain}/login`;
      return config.redirectUrl || `${appLoginUrl}?client_id=${this.clientId}`;
    }

    return `https://${tenantDomainToUse}/api/v1/logout?${query}`;
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
      async (bail) => {
        try {
          tokenResponse = await this.wristbandService.refreshToken(refreshToken);
        } catch (error: unknown) {
          if (error instanceof InvalidGrantError) {
            // Specifically handle invalid_grant errors
            bail(error);
            return;
          }
          if (
            error instanceof AxiosError &&
            error.response &&
            error.response.status >= 400 &&
            error.response.status < 500
          ) {
            const errorDescription =
              error.response.data && error.response.data.error_description
                ? error.response.data.error_description
                : 'Invalid Refresh Token';
            // Only 4xx errors should short-circuit the retry loop early.
            bail(new WristbandError('invalid_refresh_token', errorDescription));
            return;
          }

          // Retry any 5xx errors.
          throw new WristbandError('unexpected_error', 'Unexpected Error');
        }
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

    // This is merely a safety check, but this should never happen.
    throw new WristbandError('unexpected_error', 'Unexpected Error');
  }
}
