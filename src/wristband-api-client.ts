import axios, { AxiosInstance } from 'axios';
import http from 'http';
import https from 'https';

import { FORM_URLENCODED_MEDIA_TYPE, JSON_MEDIA_TYPE } from './utils/constants';

export class WristbandApiClient {
  public axiosInstance: AxiosInstance;

  constructor(wristbandApplicationVanityDomain: string) {
    this.axiosInstance = axios.create({
      baseURL: `https://${wristbandApplicationVanityDomain}/api/v1`,
      httpAgent: new http.Agent({
        keepAlive: true,
        maxSockets: 100,
        maxFreeSockets: 10,
        timeout: 60000,
        keepAliveMsecs: 1000,
        scheduling: 'lifo',
      }),
      httpsAgent: new https.Agent({
        keepAlive: true,
        maxSockets: 100,
        maxFreeSockets: 10,
        timeout: 60000,
        keepAliveMsecs: 1000,
        scheduling: 'lifo',
      }),
      headers: { 'Content-Type': FORM_URLENCODED_MEDIA_TYPE, Accept: JSON_MEDIA_TYPE },
      maxRedirects: 0,
    });
  }
}
