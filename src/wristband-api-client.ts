import { FetchError } from './error/fetch-error';
import { FORM_URLENCODED_MEDIA_TYPE, JSON_MEDIA_TYPE } from './utils/constants';

interface RequestOptions extends RequestInit {
  headers?: HeadersInit;
  body?: any;
}

/**
 * Thin fetch-based HTTP client for the Wristband API.
 *
 * Wraps native `fetch` (Node 20+) with a base URL, default headers, and
 * structured error handling. Non-2xx responses are thrown as {@link FetchError}
 * instances carrying both the raw `Response` and the parsed body.
 */
export class WristbandApiClient {
  private readonly baseURL: string;
  private readonly defaultHeaders: HeadersInit;

  constructor(wristbandApplicationVanityDomain: string) {
    this.baseURL = `https://${wristbandApplicationVanityDomain}/api/v1`;
    this.defaultHeaders = {
      'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
      Accept: JSON_MEDIA_TYPE,
    };
  }

  private async request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    const headers = { ...this.defaultHeaders, ...options.headers };
    const config: RequestInit = { ...options, headers };
    const response = await fetch(url, config);

    if (response.status === 204) {
      return undefined as T;
    }

    const responseBodyText = await response.text();
    const responseBody = responseBodyText ? (JSON.parse(responseBodyText) as T) : (undefined as T);

    if (response.status >= 400) {
      throw new FetchError(response, responseBody);
    }

    return responseBody;
  }

  /**
   * Performs a GET request to the given API endpoint.
   *
   * @param endpoint - Path relative to the base URL.
   * @param headers - Optional additional or override headers.
   * @returns The parsed JSON response body.
   * @throws {FetchError} On non-2xx responses.
   */
  public async get<T>(endpoint: string, headers: HeadersInit = {}): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET', headers, keepalive: true });
  }

  /**
   * Performs a POST request to the given API endpoint.
   *
   * @param endpoint - Path relative to the base URL.
   * @param body - Request body (typically a form-encoded string).
   * @param headers - Optional additional or override headers.
   * @returns The parsed JSON response body.
   * @throws {FetchError} On non-2xx responses.
   */
  public async post<T>(endpoint: string, body: any, headers: HeadersInit = {}): Promise<T> {
    return this.request<T>(endpoint, { method: 'POST', headers, body, keepalive: true });
  }
}
