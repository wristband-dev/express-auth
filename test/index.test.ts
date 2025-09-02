import nock from 'nock';
import { createWristbandAuth, discoverWristbandAuth, WristbandError } from '../src/index';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const LOGIN_URL = 'http://localhost:6001/api/auth/login';
const LOGIN_URL_WITH_SUBDOMAIN = 'http://{tenant_domain}.business.invotastic.com/api/auth/login';
const REDIRECT_URI = 'http://localhost:6001/api/auth/callback';
const REDIRECT_URI_WITH_SUBDOMAIN = 'http://{tenant_domain}.business.invotastic.com/api/auth/callback';
const ROOT_DOMAIN = 'business.invotastic.com';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2b-invotastic.dev.wristband.dev';

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
      });
    }).toThrow(TypeError);
  });

  test('Missing tenant domain token in loginUrl with tenant subdomains', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI_WITH_SUBDOMAIN,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        parseTenantFromRootDomain: ROOT_DOMAIN,
      });
    }).toThrow(TypeError);
  });

  test('Missing tenant domain token in redirectUri with tenant subdomains', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL_WITH_SUBDOMAIN,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        parseTenantFromRootDomain: ROOT_DOMAIN,
      });
    }).toThrow(TypeError);
  });

  test('Invalid tenant domain token in loginUrl with no tenant subdomains', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL_WITH_SUBDOMAIN,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      });
    }).toThrow(TypeError);
  });

  test('Invalid tenant domain token in redirectUri with no tenant subdomains', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI_WITH_SUBDOMAIN,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      });
    }).toThrow(TypeError);
  });
});

describe('discoverWristbandAuth', () => {
  beforeEach(() => {
    nock.cleanAll();
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

    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .get(`/api/v1/clients/${CLIENT_ID}/sdk-configuration`)
      .reply(200, mockSdkConfig);

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

    scope.done();
  });

  test('Handles SDK configuration fetch failure', async () => {
    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .get(`/api/v1/clients/${CLIENT_ID}/sdk-configuration`)
      .reply(500, { error: 'Internal Server Error' });

    await expect(
      discoverWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      })
    ).rejects.toThrow();

    scope.done();
  });

  test('Discovery fails with partial manual config override', async () => {
    const mockSdkConfig = {
      customApplicationLoginPageUrl: 'https://sdk-login.example.com',
      isApplicationCustomDomainActive: true,
      loginUrl: 'https://sdk-login-url.com',
      loginUrlTenantDomainSuffix: 'sdk.domain.com',
      redirectUri: 'https://sdk-redirect.com',
    };

    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .get(`/api/v1/clients/${CLIENT_ID}/sdk-configuration`)
      .reply(200, mockSdkConfig);

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

    scope.done();
  });

  test('Discovery with invalid SDK configuration response', async () => {
    const scope = nock(`https://${WRISTBAND_APPLICATION_DOMAIN}`)
      .get(`/api/v1/clients/${CLIENT_ID}/sdk-configuration`)
      .reply(200, { invalid: 'response' }); // Missing required fields

    await expect(
      discoverWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      })
    ).rejects.toThrow();

    scope.done();
  });
});
