import axios, { AxiosInstance } from 'axios';

export class WristbandApiClient {
  readonly axiosInstance: AxiosInstance;

  constructor(wristbandApplicationDomain: string) {
    this.axiosInstance = axios.create({
      baseURL: `https://${wristbandApplicationDomain}/api/v1`,
    });
  }
}
