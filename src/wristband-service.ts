// The Wristband Service contains all code for REST API calls to the Wristband platform.
import { WristbandApiClient } from './wristband-api-client';
import { JSON_MEDIA_TYPE } from './utils/constants';
import { TokenResponse, Userinfo } from './types';

export class WristbandService {
  private wristbandApiClient: WristbandApiClient;
  private clientId: string;
  private clientSecret: string;
  private basicAuthConfig: object;

  constructor(wristbandApplicationDomain: string, clientId: string, clientSecret: string) {
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
    const formParams: string = `grant_type=authorization_code&code=${code}&redirect_uri=${redirectUri}&code_verifier=${codeVerifier}`;
    const tokenResponse = await this.wristbandApiClient.axiosInstance.post(
      '/oauth2/token',
      formParams,
      this.basicAuthConfig
    );
    return tokenResponse.data;
  }

  async getUserinfo(accessToken: string): Promise<Userinfo> {
    const bearerTokenConfig = {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': JSON_MEDIA_TYPE,
        Accept: JSON_MEDIA_TYPE,
      },
    };
    const response = await this.wristbandApiClient.axiosInstance.get('/oauth2/userinfo', bearerTokenConfig);
    return response.data;
  }

  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const formParams: string = `grant_type=refresh_token&refresh_token=${refreshToken}`;
    const tokenResponse = await this.wristbandApiClient.axiosInstance.post(
      '/oauth2/token',
      formParams,
      this.basicAuthConfig
    );
    return tokenResponse.data;
  }

  async revokeRefreshToken(refreshToken: string): Promise<void> {
    await this.wristbandApiClient.axiosInstance.post('/oauth2/revoke', `token=${refreshToken}`, this.basicAuthConfig);
  }
}
