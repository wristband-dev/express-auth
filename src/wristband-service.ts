// The Wristband Service contains all code for REST API calls to the Wristband platform.
import { AxiosError } from 'axios';
import { WristbandApiClient } from './wristband-api-client';
import { JSON_MEDIA_TYPE } from './utils/constants';
import { TokenResponse, Userinfo } from './types';
import { InvalidGrantError } from './error';

export class WristbandService {
  private wristbandApiClient: WristbandApiClient;
  private clientId: string;
  private clientSecret: string;
  private basicAuthConfig: object;

  constructor(wristbandApplicationDomain: string, clientId: string, clientSecret: string) {
    if (!wristbandApplicationDomain || !wristbandApplicationDomain.trim()) {
      throw new Error('Wristband application domain is required');
    }

    if (!clientId || !clientId.trim()) {
      throw new Error('Client ID is required');
    }

    if (!clientSecret || !clientSecret.trim()) {
      throw new Error('Client secret is required');
    }

    this.wristbandApiClient = new WristbandApiClient(wristbandApplicationDomain);
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.basicAuthConfig = {
      auth: {
        username: this.clientId,
        password: this.clientSecret,
      },
    };
  }

  async getTokens(code: string, redirectUri: string, codeVerifier: string): Promise<TokenResponse> {
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

      // Validate response data is a valid TokenResponse
      WristbandService.validateTokenResponse(tokenResponse.data);

      return tokenResponse.data;
    } catch (error: unknown) {
      if (WristbandService.isAxiosError(error) && WristbandService.hasInvalidGrantError(error)) {
        throw new InvalidGrantError(WristbandService.getErrorDescription(error) || 'Invalid grant');
      }
      throw error;
    }
  }

  async getUserinfo(accessToken: string): Promise<Userinfo> {
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

    // Validate response data is a valid Userinfo object
    if (typeof response.data !== 'object' || response.data === null) {
      throw new Error('Invalid userinfo response');
    }

    return response.data;
  }

  async refreshToken(refreshToken: string): Promise<TokenResponse> {
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

      // Validate response data is a valid TokenResponse
      WristbandService.validateTokenResponse(tokenResponse.data);

      return tokenResponse.data;
    } catch (error: unknown) {
      if (WristbandService.isAxiosError(error) && WristbandService.hasInvalidGrantError(error)) {
        throw new InvalidGrantError(WristbandService.getErrorDescription(error) || 'Invalid refresh token');
      }
      throw error;
    }
  }

  async revokeRefreshToken(refreshToken: string): Promise<void> {
    if (!refreshToken || !refreshToken.trim()) {
      throw new Error('Refresh token is required');
    }

    await this.wristbandApiClient.axiosInstance.post('/oauth2/revoke', `token=${refreshToken}`, this.basicAuthConfig);
  }

  // Helper method to check if an error is an Axios error
  private static isAxiosError(error: unknown): error is AxiosError {
    return !!error && typeof error === 'object' && 'isAxiosError' in error;
  }

  // Helper method to check if an error has an invalid_grant error
  private static hasInvalidGrantError(error: AxiosError): boolean {
    return (
      !!error.response?.data &&
      typeof error.response.data === 'object' &&
      'error' in error.response.data &&
      error.response.data.error === 'invalid_grant'
    );
  }

  // Helper method to get error description from an axios error
  private static getErrorDescription(error: AxiosError): string | undefined {
    if (error.response?.data && typeof error.response.data === 'object' && 'error_description' in error.response.data) {
      return error.response.data.error_description as string;
    }
    return undefined;
  }

  // Helper method to validate token response
  private static validateTokenResponse(data: any): asserts data is TokenResponse {
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
}
