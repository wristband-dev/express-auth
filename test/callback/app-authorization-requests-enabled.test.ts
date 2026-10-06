/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-underscore-dangle */

import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { mockWristbandFetch } from '../helpers/mock-fetch';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

describe('Callback - App-Level Authorization Requests', () => {
  let wristbandAuth: WristbandAuth;

  beforeEach(() => {
    mockWristbandFetch();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('Clears the app-level login state cookie with a Domain attribute matching parseTenantFromRootDomain', async () => {
    const parseTenantFromRootDomain = 'business.invotastic.com';
    const wristbandApplicationVanityDomain = 'auth.invotastic.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      parseTenantFromRootDomain,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: true,
      fallbackLoginUrl: `https://${wristbandApplicationVanityDomain}/login`,
      autoConfigureEnabled: false,
    });

    // Step 1: login() with an unresolved tenant sets the app-level login state cookie
    const loginReq = httpMocks.createRequest({ headers: { host: parseTenantFromRootDomain } }) as any;
    const loginRes = httpMocks.createResponse() as any;
    const authorizeUrl = await wristbandAuth.login(loginReq, loginRes);
    const state = new URL(authorizeUrl).searchParams.get('state');
    const loginSetCookieHeader = loginRes._getHeaders()['set-cookie'] as string;
    const [cookieNameValue] = loginSetCookieHeader.split('; ');

    // Step 2: simulate the callback landing on a resolved tenant subdomain, carrying that same cookie
    const callbackReq = httpMocks.createRequest({
      headers: {
        host: `devs4you.${parseTenantFromRootDomain}`,
        cookie: cookieNameValue,
      },
      query: { state },
    }) as any;
    const callbackRes = httpMocks.createResponse() as any;

    // Deliberately omit [code] so we stop right after the cookie is cleared, before any token exchange
    await expect(wristbandAuth.callback(callbackReq, callbackRes)).rejects.toThrow(
      'Invalid query parameter [code] passed from Wristband during callback'
    );

    const clearedCookieHeader = callbackRes._getHeaders()['set-cookie'] as string;
    expect(clearedCookieHeader).toContain('Max-Age=0');
    expect(clearedCookieHeader).toContain(`Domain=.${parseTenantFromRootDomain}`);
  });

  test('Clears the tenant-level login state cookie with a Domain attribute matching parseTenantFromRootDomain', async () => {
    const parseTenantFromRootDomain = 'business.invotastic.com';
    const wristbandApplicationVanityDomain = 'auth.invotastic.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      parseTenantFromRootDomain,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: true,
      fallbackLoginUrl: `https://${wristbandApplicationVanityDomain}/login`,
      autoConfigureEnabled: false,
    });

    // Step 1: login() on a resolved tenant subdomain (tenant-level flow) with the flag enabled still
    // sets the login state cookie on the root domain
    const loginReq = httpMocks.createRequest({
      headers: { host: `devs4you.${parseTenantFromRootDomain}` },
    }) as any;
    const loginRes = httpMocks.createResponse() as any;
    const authorizeUrl = await wristbandAuth.login(loginReq, loginRes);
    const state = new URL(authorizeUrl).searchParams.get('state');
    const loginSetCookieHeader = loginRes._getHeaders()['set-cookie'] as string;
    expect(loginSetCookieHeader).toContain(`Domain=.${parseTenantFromRootDomain}`);
    const [cookieNameValue] = loginSetCookieHeader.split('; ');

    // Step 2: the callback clears that cookie with the matching root Domain
    const callbackReq = httpMocks.createRequest({
      headers: {
        host: `devs4you.${parseTenantFromRootDomain}`,
        cookie: cookieNameValue,
      },
      query: { state },
    }) as any;
    const callbackRes = httpMocks.createResponse() as any;

    await expect(wristbandAuth.callback(callbackReq, callbackRes)).rejects.toThrow(
      'Invalid query parameter [code] passed from Wristband during callback'
    );

    const clearedCookieHeader = callbackRes._getHeaders()['set-cookie'] as string;
    expect(clearedCookieHeader).toContain('Max-Age=0');
    expect(clearedCookieHeader).toContain(`Domain=.${parseTenantFromRootDomain}`);
  });

  test('Clears the login state cookie without a Domain attribute when parseTenantFromRootDomain is not set', async () => {
    const wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
    const loginUrl = 'https://localhost:6001/api/auth/login';
    const redirectUri = 'https://localhost:6001/api/auth/callback';

    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: true,
      autoConfigureEnabled: false,
    });

    const loginReq = httpMocks.createRequest({ headers: { host: 'localhost:6001' } }) as any;
    const loginRes = httpMocks.createResponse() as any;
    const authorizeUrl = await wristbandAuth.login(loginReq, loginRes);
    const state = new URL(authorizeUrl).searchParams.get('state');
    const loginSetCookieHeader = loginRes._getHeaders()['set-cookie'] as string;
    const [cookieNameValue] = loginSetCookieHeader.split('; ');

    const callbackReq = httpMocks.createRequest({
      headers: { host: 'localhost:6001', cookie: cookieNameValue },
      query: { state, tenant_name: 'devs4you' },
    }) as any;
    const callbackRes = httpMocks.createResponse() as any;

    await expect(wristbandAuth.callback(callbackReq, callbackRes)).rejects.toThrow(
      'Invalid query parameter [code] passed from Wristband during callback'
    );

    const clearedCookieHeader = callbackRes._getHeaders()['set-cookie'] as string;
    expect(clearedCookieHeader).toContain('Max-Age=0');
    expect(clearedCookieHeader).not.toContain('Domain=');
  });

  test('Clears the tenant-level login state cookie without a Domain attribute when parseTenantFromRootDomain is not set', async () => {
    const wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
    const loginUrl = 'https://localhost:6001/api/auth/login';
    const redirectUri = 'https://localhost:6001/api/auth/callback';

    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: true,
      autoConfigureEnabled: false,
    });

    // Login resolves the tenant via the tenant_name query param (tenant-level flow, not app-level)
    const loginReq = httpMocks.createRequest({
      headers: { host: 'localhost:6001' },
      query: { tenant_name: 'devs4you' },
    }) as any;
    const loginRes = httpMocks.createResponse() as any;
    const authorizeUrl = await wristbandAuth.login(loginReq, loginRes);
    const state = new URL(authorizeUrl).searchParams.get('state');
    const loginSetCookieHeader = loginRes._getHeaders()['set-cookie'] as string;
    expect(loginSetCookieHeader).not.toContain('Domain=');
    const [cookieNameValue] = loginSetCookieHeader.split('; ');

    const callbackReq = httpMocks.createRequest({
      headers: { host: 'localhost:6001', cookie: cookieNameValue },
      query: { state, tenant_name: 'devs4you' },
    }) as any;
    const callbackRes = httpMocks.createResponse() as any;

    await expect(wristbandAuth.callback(callbackReq, callbackRes)).rejects.toThrow(
      'Invalid query parameter [code] passed from Wristband during callback'
    );

    const clearedCookieHeader = callbackRes._getHeaders()['set-cookie'] as string;
    expect(clearedCookieHeader).toContain('Max-Age=0');
    expect(clearedCookieHeader).not.toContain('Domain=');
  });

  test('Clears the login state cookie without a Domain attribute when applicationAuthorizationRequestsEnabled is false', async () => {
    const parseTenantFromRootDomain = 'business.invotastic.com';
    const wristbandApplicationVanityDomain = 'auth.invotastic.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

    // applicationAuthorizationRequestsEnabled intentionally omitted (defaults to false)
    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      parseTenantFromRootDomain,
      isApplicationCustomDomainActive: true,
      wristbandApplicationVanityDomain,
      autoConfigureEnabled: false,
    });

    // Login resolves the tenant subdomain normally here (tenant-level flow, not app-level)
    const loginReq = httpMocks.createRequest({
      headers: { host: `devs4you.${parseTenantFromRootDomain}` },
    }) as any;
    const loginRes = httpMocks.createResponse() as any;
    const authorizeUrl = await wristbandAuth.login(loginReq, loginRes);
    const state = new URL(authorizeUrl).searchParams.get('state');
    const loginSetCookieHeader = loginRes._getHeaders()['set-cookie'] as string;
    expect(loginSetCookieHeader).not.toContain('Domain=');
    const [cookieNameValue] = loginSetCookieHeader.split('; ');

    const callbackReq = httpMocks.createRequest({
      headers: { host: `devs4you.${parseTenantFromRootDomain}`, cookie: cookieNameValue },
      query: { state },
    }) as any;
    const callbackRes = httpMocks.createResponse() as any;

    await expect(wristbandAuth.callback(callbackReq, callbackRes)).rejects.toThrow(
      'Invalid query parameter [code] passed from Wristband during callback'
    );

    const clearedCookieHeader = callbackRes._getHeaders()['set-cookie'] as string;
    expect(clearedCookieHeader).toContain('Max-Age=0');
    expect(clearedCookieHeader).not.toContain('Domain=');
  });

  test('No login state cookie present - nothing to clear regardless of the domain logic', async () => {
    const parseTenantFromRootDomain = 'business.invotastic.com';
    const wristbandApplicationVanityDomain = 'auth.invotastic.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      parseTenantFromRootDomain,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: true,
      fallbackLoginUrl: `https://${wristbandApplicationVanityDomain}/login`,
      autoConfigureEnabled: false,
    });

    const callbackReq = httpMocks.createRequest({
      headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      query: { state: 'some-state' },
    }) as any;
    const callbackRes = httpMocks.createResponse() as any;

    const result = await wristbandAuth.callback(callbackReq, callbackRes);

    expect(result.type).toBe('redirect_required');
    expect((result as any).reason).toBe('missing_login_state');
    expect(callbackRes._getHeaders()['set-cookie']).toBeUndefined();
  });
});
