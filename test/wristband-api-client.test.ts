import { WristbandApiClient } from '../src/wristband-api-client';
import { FetchError } from '../src/error/fetch-error';
import { FORM_URLENCODED_MEDIA_TYPE, JSON_MEDIA_TYPE } from '../src/utils/constants';

const WRISTBAND_DOMAIN = 'test.wristband.dev';
const BASE_URL = `https://${WRISTBAND_DOMAIN}/api/v1`;

function mockFetch(status: number, body: unknown, contentType = 'application/json') {
  const bodyText = typeof body === 'string' ? body : JSON.stringify(body);
  global.fetch = jest.fn().mockResolvedValue({
    status,
    ok: status >= 200 && status < 300,
    headers: {
      get: () => {
        return contentType;
      },
    },
    text: jest.fn().mockResolvedValue(bodyText),
    json: jest.fn().mockResolvedValue(body),
  });
}

describe('WristbandApiClient', () => {
  let client: WristbandApiClient;

  beforeEach(() => {
    client = new WristbandApiClient(WRISTBAND_DOMAIN);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Constructor', () => {
    test('Sets correct base URL from domain', () => {
      mockFetch(200, {});
      client.get('/test');
      expect(global.fetch).toHaveBeenCalledWith(`${BASE_URL}/test`, expect.any(Object));
    });

    test('Sets default Content-Type and Accept headers', () => {
      mockFetch(200, {});
      client.get('/test');
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
            Accept: JSON_MEDIA_TYPE,
          }),
        })
      );
    });

    test('Handles different domains correctly', () => {
      const otherClient = new WristbandApiClient('other.wristband.dev');
      mockFetch(200, {});
      otherClient.get('/test');
      expect(global.fetch).toHaveBeenCalledWith('https://other.wristband.dev/api/v1/test', expect.any(Object));
    });
  });

  describe('get()', () => {
    test('Makes GET request to correct URL', async () => {
      mockFetch(200, { result: 'ok' });
      await client.get('/oauth2/userinfo');
      expect(global.fetch).toHaveBeenCalledWith(
        `${BASE_URL}/oauth2/userinfo`,
        expect.objectContaining({ method: 'GET' })
      );
    });

    test('Returns parsed JSON body on success', async () => {
      const responseBody = { sub: 'user-123', tnt_id: 'tenant-abc' };
      mockFetch(200, responseBody);
      const result = await client.get('/oauth2/userinfo');
      expect(result).toEqual(responseBody);
    });

    test('Merges per-request headers with defaults', async () => {
      mockFetch(200, {});
      await client.get('/test', { Authorization: 'Bearer token123' });
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
            Accept: JSON_MEDIA_TYPE,
            Authorization: 'Bearer token123',
          }),
        })
      );
    });

    test('Per-request headers override defaults', async () => {
      mockFetch(200, {});
      await client.get('/test', { 'Content-Type': JSON_MEDIA_TYPE });
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({ 'Content-Type': JSON_MEDIA_TYPE }),
        })
      );
    });

    test('Sets keepalive to true', async () => {
      mockFetch(200, {});
      await client.get('/test');
      expect(global.fetch).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ keepalive: true }));
    });

    test('Throws FetchError on 400 response', async () => {
      const errorBody = { error: 'bad_request', error_description: 'Invalid request' };
      mockFetch(400, errorBody);
      await expect(client.get('/test')).rejects.toThrow(FetchError);
    });

    test('Throws FetchError on 401 response', async () => {
      mockFetch(401, { error: 'unauthorized' });
      await expect(client.get('/test')).rejects.toThrow(FetchError);
    });

    test('Throws FetchError on 500 response', async () => {
      mockFetch(500, { error: 'server_error' });
      await expect(client.get('/test')).rejects.toThrow(FetchError);
    });

    test('FetchError carries correct status and body', async () => {
      const errorBody = { error: 'invalid_grant', error_description: 'Code expired' };
      mockFetch(400, errorBody);
      try {
        await client.get('/test');
        throw new Error('Expected FetchError to be thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(FetchError);
        const fetchError = err as FetchError<Response>;
        expect(fetchError.response?.status).toBe(400);
        expect(fetchError.body).toEqual(errorBody);
      }
    });

    test('Returns undefined on 204 No Content', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        status: 204,
        ok: true,
        headers: {
          get: () => {
            return null;
          },
        },
        text: jest.fn().mockResolvedValue(''),
      });
      const result = await client.get('/test');
      expect(result).toBeUndefined();
    });
  });

  describe('post()', () => {
    test('Makes POST request to correct URL', async () => {
      mockFetch(200, { access_token: 'token', expires_in: 3600 });
      await client.post('/oauth2/token', 'grant_type=authorization_code&code=abc');
      expect(global.fetch).toHaveBeenCalledWith(
        `${BASE_URL}/oauth2/token`,
        expect.objectContaining({ method: 'POST' })
      );
    });

    test('Sends body in request', async () => {
      mockFetch(200, {});
      const body = 'grant_type=refresh_token&refresh_token=abc123';
      await client.post('/oauth2/token', body);
      expect(global.fetch).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ body }));
    });

    test('Returns parsed JSON body on success', async () => {
      const responseBody = { access_token: 'token123', expires_in: 3600 };
      mockFetch(200, responseBody);
      const result = await client.post('/oauth2/token', 'grant_type=refresh_token&refresh_token=abc');
      expect(result).toEqual(responseBody);
    });

    test('Merges per-request headers with defaults', async () => {
      mockFetch(200, {});
      await client.post('/oauth2/token', 'body', { Authorization: 'Basic dXNlcjpwYXNz' });
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
            Accept: JSON_MEDIA_TYPE,
            Authorization: 'Basic dXNlcjpwYXNz',
          }),
        })
      );
    });

    test('Sets keepalive to true', async () => {
      mockFetch(200, {});
      await client.post('/test', 'body');
      expect(global.fetch).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ keepalive: true }));
    });

    test('Throws FetchError on 400 response', async () => {
      const errorBody = { error: 'invalid_grant', error_description: 'Invalid code' };
      mockFetch(400, errorBody);
      await expect(client.post('/oauth2/token', 'grant_type=authorization_code&code=bad')).rejects.toThrow(FetchError);
    });

    test('FetchError carries correct status and body', async () => {
      const errorBody = { error: 'invalid_grant', error_description: 'Refresh token expired' };
      mockFetch(400, errorBody);
      try {
        await client.post('/oauth2/token', 'grant_type=refresh_token&refresh_token=expired');
        throw new Error('Expected FetchError to be thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(FetchError);
        const fetchError = err as FetchError<Response>;
        expect(fetchError.response?.status).toBe(400);
        expect(fetchError.body).toEqual(errorBody);
      }
    });

    test('Returns undefined on 204 No Content', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        status: 204,
        ok: true,
        headers: {
          get: () => {
            return null;
          },
        },
        text: jest.fn().mockResolvedValue(''),
      });
      const result = await client.post('/oauth2/revoke', 'token=abc');
      expect(result).toBeUndefined();
    });

    test('Throws FetchError on 500 response', async () => {
      mockFetch(500, { error: 'server_error' });
      await expect(client.post('/oauth2/token', 'body')).rejects.toThrow(FetchError);
    });
  });

  describe('Configuration constants', () => {
    test('Uses correct media type constants', () => {
      expect(FORM_URLENCODED_MEDIA_TYPE).toBe('application/x-www-form-urlencoded');
      expect(JSON_MEDIA_TYPE).toBe('application/json;charset=UTF-8');
    });
  });
});
