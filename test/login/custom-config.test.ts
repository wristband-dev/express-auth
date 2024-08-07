/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-underscore-dangle */

import httpMocks from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { decryptLoginState } from '../../src/utils';
import { LoginState } from '../../src/types';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const CUSTOM_SCOPES = ['openid', 'roles'];
const CUSTOM_STATE = { test: 'abc' };
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

describe('Custom Login Configurations', () => {
  let wristbandAuth: WristbandAuth;
  let rootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationDomain: string;

  beforeEach(() => {
    rootDomain = 'business.invotastic.com';
    wristbandApplicationDomain = 'auth.invotastic.com';
    loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
    redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
  });

  describe('Successful Redirect to Authorize Endpoint', () => {
    test('Custom Scopes Configuration at the Class Level', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
        scopes: CUSTOM_SCOPES,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes);

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate query params of Authorize URL
      expect(searchParams.get('scope')).toEqual(CUSTOM_SCOPES.join(' '));

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeFalsy();
    });

    test('Custom State at the Function Level', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, { customState: CUSTOM_STATE });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toEqual(CUSTOM_STATE);
    });

    test('Default tenant domain at the Function Level, using subdomains, missing subdomain', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, {
        defaultTenantDomainName: 'global',
      });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://global.${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    test('Default tenant domain at the Function Level, using subdomains, with subdomain present', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, {
        defaultTenantDomainName: 'global',
      });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    test('Default tenant domain at the Function Level, not using subdomains, missing query param', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://${rootDomain}/api/auth/login`,
        redirectUri: `https://${rootDomain}/api/auth/callback`,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, {
        defaultTenantDomainName: 'global',
      });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://global.${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    test('Default tenant domain at the Function Level, not using subdomains, with query param present', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://${rootDomain}/api/auth/login`,
        redirectUri: `https://${rootDomain}/api/auth/callback`,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_domain: 'devs4you' },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, {
        defaultTenantDomainName: 'global',
      });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    //
    //
    //
    // ///////////////////////////////////
    //
    //
    //
    //
    //

    test('Default tenant custom domain at the Function Level, without subdomains, without query param', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, { defaultTenantCustomDomain: 'tenant.custom.com' });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    test('Default tenant custom domain at the Function Level, without subdomains, with query param', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com' },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, {
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://query.tenant.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    test('Default tenant custom domain at the Function Level, with subdomains config, without query param', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, { defaultTenantCustomDomain: 'tenant.custom.com' });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    test('Default tenant custom domain at the Function Level, with subdomains config, with query param', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com' },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, {
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://query.tenant.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    test('Default tenant domain AND tenant custom domain at the Function Level, not using subdomains, missing query params', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://{tenant_domain}.${rootDomain}/api/auth/login`,
        redirectUri: `https://{tenant_domain}.${rootDomain}/api/auth/callback`,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, {
        defaultTenantDomainName: 'global',
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    test('Default tenant domain AND tenant custom domain at the Function Level, without subdomains, tenant domain query param', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://${rootDomain}/api/auth/login`,
        redirectUri: `https://${rootDomain}/api/auth/callback`,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_domain: 'global' },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, {
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    test('Default tenant domain AND tenant custom domain at the Function Level, without subdomains, tenant custom domain query param', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://${rootDomain}/api/auth/login`,
        redirectUri: `https://${rootDomain}/api/auth/callback`,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com' },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, {
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://query.tenant.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    test('Default tenant domain AND tenant custom domain at the Function Level, with subdomains, tenant domain query param', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://{tenant_domain}.${rootDomain}/api/auth/login`,
        redirectUri: `https://{tenant_domain}.${rootDomain}/api/auth/callback`,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `devs4you.${rootDomain}` },
        query: { tenant_domain: 'global' },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, {
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://tenant.custom.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    test('Default tenant domain AND tenant custom domain at the Function Level, with subdomains, tenant custom domain query param', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://{tenant_domain}.${rootDomain}/api/auth/login`,
        redirectUri: `https://{tenant_domain}.${rootDomain}/api/auth/callback`,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com' },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, {
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://query.tenant.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });

    test('Default tenant domain AND tenant custom domain at the Function Level, without subdomains, all query params', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://${rootDomain}/api/auth/login`,
        redirectUri: `https://${rootDomain}/api/auth/callback`,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      const mockExpressReq = httpMocks.createRequest({
        headers: { host: `${rootDomain}` },
        query: { tenant_domain: 'global', tenant_custom_domain: 'query.tenant.com' },
      });
      const mockExpressRes = httpMocks.createResponse();

      await wristbandAuth.login(mockExpressReq, mockExpressRes, {
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      const { cookies, statusCode } = mockExpressRes;
      expect(statusCode).toEqual(302);
      const location: string = mockExpressRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://query.tenant.com`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate login state cookie
      expect(Object.keys(cookies)).toHaveLength(1);
      const loginStateCookie = Object.entries(cookies)[0];
      const keyParts: string[] = loginStateCookie[0].split(':');
      const cookieValue = loginStateCookie[1];
      expect(Object.keys(cookieValue)).toHaveLength(2);
      const loginState: LoginState = await decryptLoginState(cookieValue.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toBeUndefined();
    });
  });
});
