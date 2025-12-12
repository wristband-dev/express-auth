import { AxiosError, AxiosRequestConfig } from 'axios';
import { WristbandApiClient } from './wristband-api-client';
import { JSON_MEDIA_TYPE } from './utils/constants';
import { SdkConfiguration, UserInfo, WristbandTokenResponse, WristbandUserinfoResponse } from './types';
import { InvalidGrantError } from './error';

const SDK_CONFIGS_AXIOS_REQUEST_CONFIG: AxiosRequestConfig = {
  auth: undefined,
  headers: { 'Content-Type': JSON_MEDIA_TYPE, Accept: JSON_MEDIA_TYPE },
};

/**
 * Service class for making REST API calls to the Wristband platform.
 *
 * Handles OAuth token exchange, user information retrieval, token refresh,
 * and token revocation. Most methods use HTTP Basic Authentication with
 * the configured client credentials.
 *
 * @internal
 */
export class WristbandService {
  private wristbandApiClient: WristbandApiClient;
  private clientId: string;
  private clientSecret: string;
  private basicAuthConfig: AxiosRequestConfig;

  constructor(wristbandApplicationVanityDomain: string, clientId: string, clientSecret: string) {
    if (!wristbandApplicationVanityDomain || !wristbandApplicationVanityDomain.trim()) {
      throw new Error('Wristband application domain is required');
    }

    if (!clientId || !clientId.trim()) {
      throw new Error('Client ID is required');
    }

    if (!clientSecret || !clientSecret.trim()) {
      throw new Error('Client secret is required');
    }

    this.wristbandApiClient = new WristbandApiClient(wristbandApplicationVanityDomain);
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.basicAuthConfig = {
      auth: { username: this.clientId, password: this.clientSecret },
    };
  }

  /**
   * Fetches SDK configuration from Wristband's auto-configuration endpoint.
   *
   * Retrieves application-specific configuration values including login URLs,
   * redirect URIs, and custom domain settings.
   *
   * @returns Promise resolving to the SDK configuration object
   * @throws {Error} When the API request fails
   */
  async getSdkConfiguration(): Promise<SdkConfiguration> {
    const response = await this.wristbandApiClient.axiosInstance.get(
      `/clients/${this.clientId}/sdk-configuration`,
      SDK_CONFIGS_AXIOS_REQUEST_CONFIG
    );
    return response.data;
  }

  /**
   * Exchanges an authorization code for OAuth tokens.
   *
   * Makes a request to Wristband's token endpoint using the authorization code
   * received from the callback. Uses PKCE (code verifier) for enhanced security.
   *
   * @param code - The authorization code from the OAuth callback
   * @param redirectUri - The redirect URI used in the authorization request
   * @param codeVerifier - The PKCE code verifier for this authorization request
   * @returns Promise resolving to token response with access_token, id_token, and optional refresh_token
   * @throws {Error} When any parameter is missing or empty
   * @throws {InvalidGrantError} When the authorization code is invalid or expired
   */
  async getTokens(code: string, redirectUri: string, codeVerifier: string): Promise<WristbandTokenResponse> {
    if (!code || !code.trim()) {
      throw new Error('Authorization code is required');
    }

    if (!redirectUri || !redirectUri.trim()) {
      throw new Error('Redirect URI is required');
    }

    if (!codeVerifier || !codeVerifier.trim()) {
      throw new Error('Code verifier is required');
    }

    try {
      const formParams: string = `grant_type=authorization_code&code=${code}&redirect_uri=${redirectUri}&code_verifier=${codeVerifier}`;
      const tokenResponse = await this.wristbandApiClient.axiosInstance.post(
        '/oauth2/token',
        formParams,
        this.basicAuthConfig
      );

      // Validate response data is a valid WristbandTokenResponse
      WristbandService.validateTokenResponse(tokenResponse.data);

      return tokenResponse.data;
    } catch (error: unknown) {
      if (WristbandService.isAxiosError(error) && WristbandService.hasInvalidGrantError(error)) {
        throw new InvalidGrantError(WristbandService.getErrorDescription(error) || 'Invalid grant');
      }
      throw error;
    }
  }

  /**
   * Retrieves user information from Wristband's userinfo endpoint.
   *
   * Fetches OIDC-compliant user claims including profile, email, phone, and role data
   * based on the scopes associated with the access token. Transforms snake_case OIDC
   * claims to camelCase field names.
   *
   * @param accessToken - The OAuth access token
   * @returns Promise resolving to structured UserInfo object with user claims
   * @throws {Error} When access token is missing or empty
   * @throws {TypeError} When response is invalid or missing required claims
   */
  async getUserInfo(accessToken: string): Promise<UserInfo> {
    if (!accessToken || !accessToken.trim()) {
      throw new Error('Access token is required');
    }

    const bearerTokenConfig = {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': JSON_MEDIA_TYPE,
        Accept: JSON_MEDIA_TYPE,
      },
    };

    const response = await this.wristbandApiClient.axiosInstance.get('/oauth2/userinfo', bearerTokenConfig);

    // Validate response data is a valid UserInfo object
    WristbandService.validateUserinfoResponse(response.data);

    return WristbandService.mapUserinfoClaims(response.data);
  }

  /**
   * Refreshes an expired access token using a refresh token.
   *
   * Exchanges a valid refresh token for a new set of tokens. The refresh token
   * must have been obtained with the 'offline_access' scope.
   *
   * @param refreshToken - The refresh token
   * @returns Promise resolving to new token response with fresh access_token and id_token
   * @throws {Error} When refresh token is missing or empty
   * @throws {InvalidGrantError} When the refresh token is invalid or expired
   */
  async refreshToken(refreshToken: string): Promise<WristbandTokenResponse> {
    if (!refreshToken || !refreshToken.trim()) {
      throw new Error('Refresh token is required');
    }

    try {
      const formParams: string = `grant_type=refresh_token&refresh_token=${refreshToken}`;
      const tokenResponse = await this.wristbandApiClient.axiosInstance.post(
        '/oauth2/token',
        formParams,
        this.basicAuthConfig
      );

      // Validate response data is a valid WristbandTokenResponse
      WristbandService.validateTokenResponse(tokenResponse.data);

      return tokenResponse.data;
    } catch (error: unknown) {
      if (WristbandService.isAxiosError(error) && WristbandService.hasInvalidGrantError(error)) {
        throw new InvalidGrantError(WristbandService.getErrorDescription(error) || 'Invalid refresh token');
      }
      throw error;
    }
  }

  /**
   * Revokes a refresh token to invalidate it.
   *
   * Makes a request to Wristband's revocation endpoint to permanently invalidate
   * the refresh token. After revocation, the token can no longer be used to obtain
   * new access tokens. This is typically called during logout.
   *
   * @param refreshToken - The refresh token to revoke
   * @returns Promise that resolves when revocation is complete
   * @throws {Error} When refresh token is missing or empty
   */
  async revokeRefreshToken(refreshToken: string): Promise<void> {
    if (!refreshToken || !refreshToken.trim()) {
      throw new Error('Refresh token is required');
    }

    await this.wristbandApiClient.axiosInstance.post('/oauth2/revoke', `token=${refreshToken}`, this.basicAuthConfig);
  }

  /// /////////////////////////////////
  //  PRIVATE METHODS
  /// /////////////////////////////////

  /**
   * Type guard to check if an error is an Axios error.
   *
   * @param error - The error to check
   * @returns True if the error is an AxiosError
   *
   * @internal
   */
  private static isAxiosError(error: unknown): error is AxiosError {
    return !!error && typeof error === 'object' && 'isAxiosError' in error;
  }

  /**
   * Checks if an Axios error response contains an invalid_grant error.
   *
   * @param error - The Axios error to check
   * @returns True if the error response has error code 'invalid_grant'
   *
   * @internal
   */
  private static hasInvalidGrantError(error: AxiosError): boolean {
    return (
      !!error.response?.data &&
      typeof error.response.data === 'object' &&
      'error' in error.response.data &&
      error.response.data.error === 'invalid_grant'
    );
  }

  /**
   * Extracts the error_description field from an Axios error response.
   *
   * @param error - The Axios error
   * @returns The error description string, or undefined if not present
   *
   * @internal
   */
  private static getErrorDescription(error: AxiosError): string | undefined {
    if (error.response?.data && typeof error.response.data === 'object' && 'error_description' in error.response.data) {
      return error.response.data.error_description as string;
    }
    return undefined;
  }

  /**
   * Validates that a token response contains required fields.
   *
   * Ensures the response has access_token and expires_in fields with correct types.
   *
   * @param data - The response data to validate
   * @throws {Error} When response is invalid or missing required fields
   *
   * @internal
   */
  private static validateTokenResponse(data: any): asserts data is WristbandTokenResponse {
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid token response');
    }

    if (!('access_token' in data) || typeof data.access_token !== 'string') {
      throw new Error('Invalid token response: missing access_token');
    }

    if (!('expires_in' in data) || typeof data.expires_in !== 'number') {
      throw new Error('Invalid token response: missing expires_in');
    }
  }

  /**
   * Validates that the userinfo response from Wristband contains all required OIDC claims.
   *
   * Checks for the presence and correct types of mandatory claims that Wristband
   * always returns regardless of scopes: sub (userId), tnt_id (tenantId),
   * app_id (applicationId), and idp_name (identityProviderName).
   *
   * @param data - The raw response data from the userinfo endpoint
   * @throws {Error} When response is not an object or missing required claims
   *
   * @internal
   */
  private static validateUserinfoResponse(data: any): asserts data is WristbandUserinfoResponse {
    if (!data || typeof data !== 'object') {
      throw new TypeError('Invalid userinfo response: expected object');
    }

    // Validate required fields that are always present
    if (!data.sub || typeof data.sub !== 'string') {
      throw new TypeError('Invalid userinfo response: missing sub claim');
    }
    if (!data.tnt_id || typeof data.tnt_id !== 'string') {
      throw new TypeError('Invalid userinfo response: missing tnt_id claim');
    }
    if (!data.app_id || typeof data.app_id !== 'string') {
      throw new TypeError('Invalid userinfo response: missing app_id claim');
    }
    if (!data.idp_name || typeof data.idp_name !== 'string') {
      throw new TypeError('Invalid userinfo response: missing idp_name claim');
    }
  }

  /**
   * Transforms the raw OIDC claims from Wristband's userinfo endpoint
   * to the structured UserInfo type with camelCase field names.
   *
   * @param userinfo - Raw userinfo claims from Wristband auth SDK
   * @returns Structured UserInfo object from Wristband session SDK
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private static mapUserinfoClaims(userinfo: WristbandUserinfoResponse): UserInfo {
    return {
      // Always present
      userId: userinfo.sub,
      tenantId: userinfo.tnt_id,
      applicationId: userinfo.app_id,
      identityProviderName: userinfo.idp_name,

      // Profile scope
      fullName: userinfo.name ?? undefined,
      givenName: userinfo.given_name ?? undefined,
      familyName: userinfo.family_name ?? undefined,
      middleName: userinfo.middle_name ?? undefined,
      nickname: userinfo.nickname ?? undefined,
      displayName: userinfo.preferred_username ?? undefined,
      pictureUrl: userinfo.picture ?? undefined,
      gender: userinfo.gender ?? undefined,
      birthdate: userinfo.birthdate ?? undefined,
      timeZone: userinfo.zoneinfo ?? undefined,
      locale: userinfo.locale ?? undefined,
      updatedAt: userinfo.updated_at ?? undefined,

      // Email scope
      email: userinfo.email ?? undefined,
      emailVerified: userinfo.email_verified ?? undefined,

      // Phone scope
      phoneNumber: userinfo.phone_number ?? undefined,
      phoneNumberVerified: userinfo.phone_number_verified ?? undefined,

      // Roles scope
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      roles: userinfo.roles?.map((role: any) => {
        return {
          id: role.id,
          name: role.name,
          displayName: role.display_name || role.displayName,
        };
      }),

      // Custom claims
      customClaims: userinfo.custom_claims,
    };
  }
}
