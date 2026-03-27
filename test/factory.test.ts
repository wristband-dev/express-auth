import { createWristbandAuth, discoverWristbandAuth } from '../src/factory';
import { WristbandError } from '../src/error';
import { TENANT_DOMAIN_PLACEHOLDER, TENANT_NAME_PLACEHOLDER } from '../src/utils/constants';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const LOGIN_URL = 'http://localhost:6001/api/auth/login';
const REDIRECT_URI = 'http://localhost:6001/api/auth/callback';
const ROOT_DOMAIN = 'business.invotastic.com';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2b-invotastic.dev.wristband.dev';
const SDK_CONFIG_ENDPOINT = `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/clients/${CLIENT_ID}/sdk-configuration`;

const getLoginUrlWithPlaceholder = (placeholder: string) => {
  return `http://${placeholder}.business.invotastic.com/api/auth/login`;
};
const getRedirectUriWithPlaceholder = (placeholder: string) => {
  return `http://${placeholder}.business.invotastic.com/api/auth/callback`;
};

function mockFetchSdkConfig(responses: { status: number; body: unknown }[]) {
  let callCount = 0;
  global.fetch = jest.fn().mockImplementation(() => {
    const response = responses[Math.min(callCount, responses.length - 1)];
    callCount += 1;
    return Promise.resolve({
      status: response.status,
      ok: response.status >= 200 && response.status < 300,
      headers: {
        get: () => {
          return 'application/json';
        },
      },
      text: jest.fn().mockResolvedValue(JSON.stringify(response.body)),
    });
  });
}

describe('createWristbandAuth Instantiation Errors', () => {
  test('Empty clientId', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: '',
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        autoConfigureEnabled: false,
      });
    }).toThrow(TypeError);
  });

  test('Empty clientSecret', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: '',
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        autoConfigureEnabled: false,
      });
    }).toThrow(TypeError);
  });

  test('Empty loginUrl', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: '',
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        autoConfigureEnabled: false,
      });
    }).toThrow(TypeError);
  });

  test('Empty redirectUri', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: '',
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        autoConfigureEnabled: false,
      });
    }).toThrow(TypeError);
  });

  test('Empty wristbandApplicationVanityDomain', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: '',
        autoConfigureEnabled: false,
      });
    }).toThrow(TypeError);
  });

  describe.each([
    ['tenant_domain', TENANT_DOMAIN_PLACEHOLDER],
    ['tenant_name', TENANT_NAME_PLACEHOLDER],
  ])('Tenant placeholder validation with %s', (placeholderName, placeholder) => {
    test(`Missing ${placeholderName} placeholder in loginUrl with tenant subdomains`, async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: getRedirectUriWithPlaceholder(placeholder),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow(TypeError);
    });

    test(`Missing ${placeholderName} placeholder in redirectUri with tenant subdomains`, async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(placeholder),
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow(TypeError);
    });

    test(`Invalid ${placeholderName} placeholder in loginUrl with no tenant subdomains`, async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(placeholder),
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow(TypeError);
    });

    test(`Invalid ${placeholderName} placeholder in redirectUri with no tenant subdomains`, async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: getRedirectUriWithPlaceholder(placeholder),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow(TypeError);
    });
  });

  describe('Mixed placeholder support', () => {
    test('tenant_domain in loginUrl and tenant_name in redirectUri', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(TENANT_DOMAIN_PLACEHOLDER),
          redirectUri: getRedirectUriWithPlaceholder(TENANT_NAME_PLACEHOLDER),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });

    test('tenant_name in loginUrl and tenant_domain in redirectUri', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(TENANT_NAME_PLACEHOLDER),
          redirectUri: getRedirectUriWithPlaceholder(TENANT_DOMAIN_PLACEHOLDER),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });
  });
});

describe('discoverWristbandAuth', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('error when autoConfigureEnabled set to false', async () => {
    await expect(
      discoverWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        autoConfigureEnabled: false,
      })
    ).rejects.toThrow(WristbandError);
  });

  test('Successfully creates WristbandAuth with SDK discovery', async () => {
    const mockSdkConfig = {
      customApplicationLoginPageUrl: null,
      isApplicationCustomDomainActive: false,
      loginUrl: LOGIN_URL,
      loginUrlTenantDomainSuffix: null,
      redirectUri: REDIRECT_URI,
    };
    mockFetchSdkConfig([{ status: 200, body: mockSdkConfig }]);

    const wristbandAuth = await discoverWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
    });

    expect(wristbandAuth).toBeDefined();
    expect(wristbandAuth.login).toBeDefined();
    expect(wristbandAuth.callback).toBeDefined();
    expect(wristbandAuth.logout).toBeDefined();
    expect(wristbandAuth.refreshTokenIfExpired).toBeDefined();
    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(global.fetch).toHaveBeenCalledWith(SDK_CONFIG_ENDPOINT, expect.any(Object));
  });

  test('Handles SDK configuration fetch failure', async () => {
    // 3 attempts all fail — exhausts MAX_FETCH_ATTEMPTS
    mockFetchSdkConfig([
      { status: 500, body: { error: 'Internal Server Error' } },
      { status: 500, body: { error: 'Internal Server Error' } },
      { status: 500, body: { error: 'Internal Server Error' } },
    ]);

    await expect(
      discoverWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      })
    ).rejects.toThrow();

    expect(global.fetch).toHaveBeenCalledTimes(3);
  });

  test('Discovery fails with partial manual config override', async () => {
    const mockSdkConfig = {
      customApplicationLoginPageUrl: 'https://sdk-login.example.com',
      isApplicationCustomDomainActive: true,
      loginUrl: 'https://sdk-login-url.com',
      loginUrlTenantDomainSuffix: 'sdk.domain.com',
      redirectUri: 'https://sdk-redirect.com',
    };
    mockFetchSdkConfig([{ status: 200, body: mockSdkConfig }]);

    await expect(
      discoverWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL, // Manual override
        redirectUri: REDIRECT_URI, // Manual override
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      })
    ).rejects.toThrow();

    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('Discovery with invalid SDK configuration response', async () => {
    mockFetchSdkConfig([{ status: 200, body: { invalid: 'response' } }]);

    await expect(
      discoverWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      })
    ).rejects.toThrow();

    expect(global.fetch).toHaveBeenCalledTimes(1);
  });
});
