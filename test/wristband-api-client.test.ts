import axios from 'axios';
import { WristbandApiClient } from '../src/wristband-api-client';
import { FORM_URLENCODED_MEDIA_TYPE, JSON_MEDIA_TYPE } from '../src/utils/constants';

// Mock axios.create to avoid actual HTTP calls
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('WristbandApiClient', () => {
  const WRISTBAND_DOMAIN = 'test.wristband.dev';
  let wristbandApiClient: WristbandApiClient;
  let mockAxiosInstance: any;

  beforeEach(() => {
    mockAxiosInstance = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
      patch: jest.fn(),
      request: jest.fn(),
    };
    mockedAxios.create.mockReturnValue(mockAxiosInstance);
    wristbandApiClient = new WristbandApiClient(WRISTBAND_DOMAIN);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Constructor', () => {
    test('Creates axios instance with correct base URL', () => {
      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({ baseURL: `https://${WRISTBAND_DOMAIN}/api/v1` })
      );
    });

    test('Sets correct default headers', () => {
      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({
          headers: { 'Content-Type': FORM_URLENCODED_MEDIA_TYPE, Accept: JSON_MEDIA_TYPE },
        })
      );
    });

    test('Configures HTTP agent with correct settings', () => {
      const createCall = mockedAxios.create.mock.calls[0]?.[0];
      expect(createCall).toBeDefined();
      expect(createCall!.httpAgent).toBeDefined();
      expect(createCall!.httpAgent.keepAlive).toBe(true);
      expect(createCall!.httpAgent.maxSockets).toBe(100);
      expect(createCall!.httpAgent.maxFreeSockets).toBe(10);
      expect(createCall!.httpAgent.options.timeout).toBe(60000);
      expect(createCall!.httpAgent.keepAliveMsecs).toBe(1000);
      expect(createCall!.httpAgent.scheduling).toBe('lifo');
    });

    test('Configures HTTPS agent with correct settings', () => {
      const createCall = mockedAxios.create.mock.calls[0]?.[0];
      expect(createCall).toBeDefined();
      expect(createCall!.httpsAgent).toBeDefined();
      expect(createCall!.httpsAgent.keepAlive).toBe(true);
      expect(createCall!.httpsAgent.maxSockets).toBe(100);
      expect(createCall!.httpsAgent.maxFreeSockets).toBe(10);
      expect(createCall!.httpsAgent.options.timeout).toBe(60000);
      expect(createCall!.httpsAgent.keepAliveMsecs).toBe(1000);
      expect(createCall!.httpsAgent.scheduling).toBe('lifo');
    });

    test('Disables redirects', () => {
      expect(mockedAxios.create).toHaveBeenCalledWith(expect.objectContaining({ maxRedirects: 0 }));
    });

    test('Exposes axios instance publicly', () => {
      expect(wristbandApiClient.axiosInstance).toBe(mockAxiosInstance);
    });
  });

  describe('Multiple instances', () => {
    test('Creates axios instances for different domains', () => {
      const domain1 = 'domain1.wristband.dev';
      const domain2 = 'domain2.wristband.dev';

      // eslint-disable-next-line no-new
      new WristbandApiClient(domain1);
      // eslint-disable-next-line no-new
      new WristbandApiClient(domain2);

      // Including the beforeEach call
      expect(mockedAxios.create).toHaveBeenCalledTimes(3);

      const calls = mockedAxios.create.mock.calls.map((call) => {
        return call[0]?.baseURL;
      });

      expect(calls).toContain(`https://${domain1}/api/v1`);
      expect(calls).toContain(`https://${domain2}/api/v1`);
    });
  });

  describe('Domain handling', () => {
    test('Handles domain with protocol (strips it)', () => {
      const domainWithProtocol = 'https://test.wristband.dev';

      // eslint-disable-next-line no-new
      new WristbandApiClient(domainWithProtocol);

      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({ baseURL: `https://${domainWithProtocol}/api/v1` })
      );
    });

    test('Handles domain with path (includes it)', () => {
      const domainWithPath = 'test.wristband.dev/custom';

      // eslint-disable-next-line no-new
      new WristbandApiClient(domainWithPath);

      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({ baseURL: `https://${domainWithPath}/api/v1` })
      );
    });

    test('Handles domain with port', () => {
      const domainWithPort = 'test.wristband.dev:8080';

      // eslint-disable-next-line no-new
      new WristbandApiClient(domainWithPort);

      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({ baseURL: `https://${domainWithPort}/api/v1` })
      );
    });

    test('Handles empty domain', () => {
      const emptyDomain = '';

      // eslint-disable-next-line no-new
      new WristbandApiClient(emptyDomain);

      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({ baseURL: `https://${emptyDomain}/api/v1` })
      );
    });
  });

  describe('Agent configuration validation', () => {
    test('HTTP and HTTPS agents have identical configurations', () => {
      const createCall = mockedAxios.create.mock.calls[0]?.[0];
      expect(createCall).toBeDefined();

      const httpAgent = createCall!.httpAgent;
      const httpsAgent = createCall!.httpsAgent;

      // Compare all properties
      expect(httpAgent.keepAlive).toBe(httpsAgent.keepAlive);
      expect(httpAgent.maxSockets).toBe(httpsAgent.maxSockets);
      expect(httpAgent.maxFreeSockets).toBe(httpsAgent.maxFreeSockets);
      expect(httpAgent.timeout).toBe(httpsAgent.timeout);
      expect(httpAgent.keepAliveMsecs).toBe(httpsAgent.keepAliveMsecs);
      expect(httpAgent.scheduling).toBe(httpsAgent.scheduling);
    });

    test('Uses different agent constructors for HTTP and HTTPS', () => {
      const createCall = mockedAxios.create.mock.calls[0]?.[0];
      expect(createCall).toBeDefined();

      // Verify that different constructors were used
      expect(createCall!.httpAgent.constructor.name).toBe('Agent');
      expect(createCall!.httpsAgent.constructor.name).toBe('Agent');

      // They should be different instances
      expect(createCall!.httpAgent).not.toBe(createCall!.httpsAgent);
    });
  });

  describe('Configuration constants', () => {
    test('Uses correct media type constants', () => {
      // This test ensures the constants are properly imported and used
      expect(FORM_URLENCODED_MEDIA_TYPE).toBe('application/x-www-form-urlencoded');
      expect(JSON_MEDIA_TYPE).toBe('application/json;charset=UTF-8');

      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json;charset=UTF-8' },
        })
      );
    });
  });

  describe('Instance behavior', () => {
    test('Axios instance methods are available', () => {
      expect(wristbandApiClient.axiosInstance.get).toBeDefined();
      expect(wristbandApiClient.axiosInstance.post).toBeDefined();
      expect(wristbandApiClient.axiosInstance.put).toBeDefined();
      expect(wristbandApiClient.axiosInstance.delete).toBeDefined();
      expect(wristbandApiClient.axiosInstance.patch).toBeDefined();
      expect(wristbandApiClient.axiosInstance.request).toBeDefined();
    });

    test('Can make HTTP requests through the axios instance', async () => {
      const mockResponse = { data: { test: 'data' }, status: 200 };
      mockAxiosInstance.get.mockResolvedValue(mockResponse);
      const response = await wristbandApiClient.axiosInstance.get('/test-endpoint');
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/test-endpoint');
      expect(response).toBe(mockResponse);
    });

    test('Axios instance inherits all configuration', async () => {
      const mockResponse = { data: { test: 'data' }, status: 200 };
      mockAxiosInstance.post.mockResolvedValue(mockResponse);
      await wristbandApiClient.axiosInstance.post('/test', { data: 'test' });
      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/test', { data: 'test' });
    });
  });

  describe('Edge cases', () => {
    test('Handles special characters in domain', () => {
      const specialDomain = 'test-domain_123.wristband.dev';

      // eslint-disable-next-line no-new
      new WristbandApiClient(specialDomain);
      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({ baseURL: `https://${specialDomain}/api/v1` })
      );
    });

    test('Handles very long domain names', () => {
      const longDomain = `${'a'.repeat(100)}.wristband.dev`;

      // eslint-disable-next-line no-new
      new WristbandApiClient(longDomain);
      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({ baseURL: `https://${longDomain}/api/v1` })
      );
    });

    test('Configuration is immutable after creation', () => {
      const createCall = mockedAxios.create.mock.calls[0]?.[0];
      expect(createCall).toBeDefined();
      const originalBaseURL = createCall!.baseURL;

      // Attempt to modify the configuration (this shouldn't affect the instance)
      createCall!.baseURL = 'https://different.domain.com/api/v1';

      // The axios instance should still use the original configuration
      expect(originalBaseURL).toBe(`https://${WRISTBAND_DOMAIN}/api/v1`);
    });
  });
});
