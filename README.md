<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Enterprise-ready auth that is secure by default, truly multi-tenant, and ungated for small businesses.
  </p>
  <p align="center">
    <b>
      <a href="https://wristband.dev">Website</a> • 
      <a href="https://docs.wristband.dev/">Documentation</a>
    </b>
  </p>
</div>

<br/>

---

<br/>

# Wristband Multi-Tenant Authentication SDK for Express

[![npm package](https://img.shields.io/badge/npm%20i-express--auth-brightgreen)](https://www.npmjs.com/package/@wristband/express-auth)
[![version number](https://img.shields.io/github/v/release/wristband-dev/express-auth?color=green&label=version)](https://github.com/wristband-dev/express-auth/releases)
[![Actions Status](https://github.com/wristband-dev/express-auth/workflows/Test/badge.svg)](https://github.com/wristband-dev/express-auth/actions)
[![License](https://img.shields.io/github/license/wristband-dev/express-auth)](https://github.com/wristband-dev/express-auth/blob/main/LICENSE.md)

Enterprise-ready authentication for multi-tenant [Express applications](https://expressjs.com) using OAuth 2.1 and OpenID Connect standards. It supports both CommonJS and ES Modules and includes TypeScript declaration files.

<br>

## Overview

This SDK provides complete authentication integration with Wristband, including:

- **Login flow** - Redirect to Wristband and handle OAuth callbacks
- **Session management** - Encrypted cookie-based sessions with optional CSRF token protection
- **Token handling** - Automatic access token refresh and validation
- **Logout flow** - Token revocation and session cleanup
- **Multi-tenancy** - Support for tenant subdomains and custom domains

Learn more about Wristband's authentication patterns:

- [Backend Server Integration Pattern](https://docs.wristband.dev/docs/backend-server-integration)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

<br>

---

<br>

## Table of Contents

- [Migrating From Older SDK Versions](#migrating-from-older-sdk-versions)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [1) Initialize the Auth SDK](#1-initialize-the-auth-sdk)
  - [2) Set Up Session Management](#2-set-up-session-management)
  - [3) Add Auth Endpoints](#3-add-auth-endpoints)
    - [Login Endpoint](#login-endpoint)
    - [Callback Endpoint](#callback-endpoint)
    - [Logout Endpoint](#logout-endpoint)
    - [Session Endpoint](#session-endpoint)
    - [Token Endpoint (Optional)](#token-endpoint-optional)
  - [4) Protect Your API Routes](#4-protect-your-api-routes)
  - [5) Use Your Access Token with APIs](#5-use-your-access-token-with-apis)
- [Auth Configuration Options](#auth-configuration-options)
  - [createWristbandAuth()](#createwristbandauth)
  - [discoverWristbandAuth()](#discoverwristbandauth)
- [Auth API](#auth-api)
  - [Login](#loginreq-request-res-response-config-loginconfig-promisestring)
  - [Callback](#callbackreq-request-res-response-promisecallbackresult)
  - [Logout](#logoutreq-request-res-response-config-logoutconfig-promisestring)
  - [RefreshTokenIfExpired](#refreshtokenifexpiredrefreshtoken-string-expiresat-number-promisetokendata--null)
- [Session Management](#session-management)
  - [Session Configuration](#session-configuration)
  - [The Session Object](#the-session-object)
  - [Authentication Middleware](#authentication-middleware)
  - [Session Access Patterns](#session-access-patterns)
  - [Session API](#session-api)
    - [session.fromCallback()](#sessionfromcallbackcallbackdata-customfields)
    - [session.save()](#sessionsave)
    - [session.destroy()](#sessiondestroy)
    - [session.getSessionResponse()](#sessiongetsessionresponsemetadata)
    - [session.getTokenResponse()](#sessiongettokenresponse)
  - [CSRF Protection](#csrf-protection)
- [Questions](#questions)

<br/>

## Migrating From Older SDK Versions

On an older version of our SDK? Check out our migration guide:

- [Instructions for migrating to Version 5.x](migration/v5/README.md)
- [Instructions for migrating to Version 4.x](migration/v4/README.md)
- [Instructions for migrating to Version 3.x](migration/v3/README.md)

<br>

## Prerequisites

Before installing, ensure you have:

- [Node.js](https://nodejs.org/en) >= 20.0.0
- [Express](https://expressjs.com/) >= 4.0.0
- Your preferred package manager (npm >= 9.6.0, yarn, pnpm, etc.)

<br>

## Installation

```bash
# With npm
npm install @wristband/express-auth

# Or with yarn
yarn add @wristband/express-auth

# Or with pnpm
pnpm add @wristband/express-auth
```

<br>

## Usage

### 1) Initialize the Auth SDK

First, create an instance of `WristbandAuth` in your Express directory structure in any location of your choice (i.e. `src/wristband.ts`). Then, you can export this instance and use it across your project.

```typescript
// src/wristband.ts
import { createWristbandAuth } from '@wristband/express-auth';

// Wristband authentication instance for handling login, callback, and logout flows.
export const wristbandAuth = createWristbandAuth({
  clientId: "replace-me-with-your-client-id",
  clientSecret: "replace-me-with-your-client-secret",
  wristbandApplicationVanityDomain: "auth.yourapp.io",
});
```

<br>

### 2) Set Up Session Management

Wristband provides encrypted cookie-based session management built directly into this SDK, powered by [@wristband/typescript-session](https://github.com/wristband-dev/typescript-session). Add the session middleware and authentication middleware to your Express app:

```typescript
// src/wristband.ts (continued)
import { createWristbandAuth } from '@wristband/express-auth';
import { createWristbandSession } from '@wristband/express-auth/session';

export const wristbandAuth = createWristbandAuth({
  clientId: "replace-me-with-your-client-id",
  clientSecret: "replace-me-with-your-client-secret",
  wristbandApplicationVanityDomain: "auth.yourapp.io",
});

// Session middleware for encrypted cookie-based session management.
// Wrapped in a factory function to ensure fresh middleware instance per app.use() call.
// See Session Configuration section for additional details.
export function wristbandSession() {
  return createWristbandSession({
    secrets: 'dummyval-b5c1-463a-812c-0d8db87c0ec5', // 32+ character secret
    maxAge: 3600, // 1 hour in seconds
    secure: process.env.NODE_ENV === 'production',
  });
};

// Middleware that ensures the user has an authenticated session and refreshes tokens if needed.
export const requireWristbandAuth = wristbandAuth.createRequireSessionAuth();
```

Then apply the session middleware to your Express app:

```typescript
// src/app.ts
import express from 'express';
import { wristbandSession } from './wristband';

const app = express();

// Add Wristband session middleware.
app.use(wristbandSession());

...
```

This approach requires no additional dependencies and works seamlessly with Wristband auth callbacks.

> [!NOTE]
> If you prefer server-side sessions (Redis, databases, etc.) or want to use a different session library like [express-session](https://github.com/expressjs/session), you can skip importing `/session` and manage sessions however you'd like. Just make sure to store the Wristband tokens in your session after authentication.

<br>

### 3) Add Auth Endpoints

There are <ins>four core API endpoints</ins> your FastAPI server should expose to facilitate both the Login and Logout workflows in Wristband. You'll need to add them to wherever your Express routes/controllers are.

<br>

#### [Login Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#login-endpoint)

The goal of the Login Endpoint is to initiate an auth request by redirecting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. The frontend of your application should redirect to this endpoint when users need to log in to your application.

```typescript
// src/routes/auth-routes.ts
import { requireWristbandAuth, wristbandAuth } from '../wristband';

// Login Endpoint - Route path can be whatever you prefer
app.get('/auth/login', async (req, res) => {
  try {
    const loginUrl = await wristbandAuth.login(req, res, { /* Optional login configs */ });
    res.redirect(loginUrl);
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});
```

#### [Callback Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#callback-endpoint)

The goal of the Callback Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

```typescript
// src/routes/auth-routes.ts (continued)

...

// Callback Endpoint - Route path can be whatever you prefer
app.get('/auth/callback', async (req, res) => {
  try {
    const callbackResult = await wristbandAuth.callback(req, res);
    const { callbackData, redirectUrl, type } = callbackResult;
    
    // For certain edge cases, the SDK will require you to redirect back to login.
    if (type === CallbackResultType.REDIRECT_REQUIRED) {
      return res.redirect(redirectUrl!);
    }

    // Save necessary fields in the user's session.
    req.session.fromCallback(callbackData!);
    await req.session.save();

    // Send the user back to your application.
    return res.redirect(callbackData!.returnUrl || `https://${callbackData!.tenantName}.yourapp.io/`);
  } catch (error) {
    return res.status(500).send('Internal Server Error');
  }
});
```

#### [Logout Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#logout-endpoint-1)

The goal of the Logout Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).


```typescript
// src/routes/auth-routes.ts (continued)

...

// Logout Endpoint - Route path can be whatever you prefer
app.get('/auth/logout', async (req, res) => {
  const { refreshToken, tenantName } = req.session;

  // Always destroy your application's session.
  req.session.destroy();

  try {
    const logoutUrl = await wristbandAuth.logout(req, res, { tenantName, refreshToken });
    res.redirect(logoutUrl);
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});
```

<br>

#### Session Endpoint

> [!NOTE]
> This endpoint is required for Wristband frontend SDKs to function. For more details, see the [Wristband Session Management documentation](https://docs.wristband.dev/docs/session-management-backend-server).

Wristband frontend SDKs require a Session Endpoint in your backend to verify authentication status and retrieve session metadata. Create a protected session endpoint that uses `session.getSessionResponse()` to return the session response format expected by Wristband's frontend SDKs. The response type will always have a `userId` and a `tenantId` in it. You can include any additional data for your frontend by customizing the `metadata` parameter (optional), which requires JSON-serializable values.

**Make sure to protect this endpoint using the `requireWristbandAuth` middleware you created!**

```typescript
// src/routes/auth-routes.ts (continued)

...

// Session Endpoint - Route path can be whatever you prefer
// Use the "requireWristbandAuth" middleware to protect this endpoint.
app.get('/auth/session', requireWristbandAuth, (req, res) => {
  res.header('Cache-Control', 'no-store');
  res.header('Pragma', 'no-cache');

  const sessionResponse = req.session.getSessionResponse({ foo: 'bar' });
  return res.status(200).json(sessionResponse);
});
```

The Session Endpoint returns the `SessionResponse` type to your frontend:

```json
{
  "tenantId": "tenant_abc123",
  "userId": "user_xyz789",
  "metadata": {
    "foo": "bar",
    // Any other optional data you provide...
  }
}
```

<br>

#### Token Endpoint (Optional)

> [!NOTE]
> This endpoint is required when your frontend needs to make authenticated API requests directly to Wristband or other protected services. For more details, see the [Wristband documentation on using access tokens from the frontend](https://docs.wristband.dev/docs/authenticating-api-requests-with-bearer-tokens#using-access-tokens-from-the-frontend).
>
> If your application doesn't need frontend access to tokens (e.g., all API calls go through your backend), you can skip this endpoint.

Some applications require the frontend to make direct API calls to Wristband or other protected services using the user's access token. The Token Endpoint provides a secure way for your frontend to retrieve the current access token and its expiration time without exposing it in the session cookie or in browser storage.

Create a protected token endpoint that uses `session.getTokenResponse()` to return the token data expected by Wristband's frontend SDKs.

**Make sure to protect this endpoint using the `requireWristbandAuth` middleware you created!**

```typescript
// src/routes/auth-routes.ts (continued)

...

// Token Endpoint - Route path can be whatever you prefer
// Use the "requireWristbandAuth" middleware to protect this endpoint.
app.get('/auth/session', requireWristbandAuth, (req, res) => {
  res.header('Cache-Control', 'no-store');
  res.header('Pragma', 'no-cache');

  const tokenResponse = req.session.getTokenResponse();
  return res.status(200).json(tokenResponse);
});
```

The Token Endpoint returns the `TokenResponse` type to your frontend:

```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresAt": 1735689600000
}
```

Your frontend can then use the `accessToken` in the Authorization header when making API requests:

```typescript
const tokenResponse = await fetch('/auth/token');
const { accessToken } = await tokenResponse.json();

// Use token to call Wristband API
const userResponse = await fetch('https://<your-wristband-app-vanity_domain>/api/v1/users/123', {
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});
```

<br>

### 4) Protect Your API Routes

Use the `requireWristbandAuth` middleware to protect routes that require authentication. This middleware automatically checks if the access token is expired and refreshes it if necessary (with up to 3 retry attempts).

> [!NOTE]
> Token refresh only occurs when both `refreshToken` and `expiresAt` are present in the session.

```typescript
// src/routes/protected-routes.ts
import express from 'express';
import { requireWristbandAuth } from '../wristband';

const router = express.Router();

// Protect any routes that require an authenticated session.
router.get('api/hello-world', requireWristbandAuth, (req, res) => {
  res.status(200).json({ message: 'Hello World!' })
});

export default router;
```

<br>

### 5) Use Your Access Token with APIs

> [!NOTE]
> This section is only applicable if you need to call Wristband APIs or protect your own backend services with Wristband tokens.

To call Wristband APIs or authenticate requests to your backend services, include the access token in the `Authorization` request header:

```
Authorization: Bearer <your_access_token>
```

**Example:** Using the access token with Axios to call a downstream API:

```typescript
// Helper function to add bearer token to requests
const withBearerToken = function(req: Request) {
  return { headers: { Authorization: `Bearer ${req.session.accessToken}` } };
};

// Pass your access token to downstream API
app.post('/api/orders', requireWristbandAuth, async (req, res) => {
  try {
    const newOrder = { ...req.body };
    db.save(newOrder)
    await axios.post(
      'https://api.example.com/email-receipt',
      newOrder,
      withBearerToken(req),
    );
    res.status(201).send();
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});
```

<br>

## Auth Configuration Options

There are two functions you can use for initializing the SDK in your application: `createWristbandAuth()` and `discoverWristbandAuth()`.

| Method | When Config is Fetched | Use When |
| ------ | ---------------------- | -------- |
| `createWristbandAuth()` (default) | Lazily, on first auth method call (login, callback, etc.) | Standard usage - allows your app to start without waiting for config |
| `discoverWristbandAuth()` | Eagerly, immediately when called | You want to fail fast at startup if auto-config is unavailable |

Both functions accept an `AuthConfig` object containing the settings required to integrate Wristband authentication.

| AuthConfig Field | Type | Required | Auto-Configurable | Description |
| ---------------- | ---- | -------- | ----------------- | ----------- |
| autoConfigureEnabled | boolean | No | _N/A_ | Flag that tells the SDK to automatically set some of the SDK configuration values by calling to Wristband's SDK Auto-Configuration Endpoint. Any manually provided configurations will take precedence over the configs returned from the endpoint. Auto-configure is enabled by default. When disabled, if manual configurations are not provided, then an error will be thrown. |
| clientId | string | Yes | No | The ID of the Wristband client. |
| clientSecret | string | Yes | No | The client's secret. |
| customApplicationLoginPageUrl | string | No | Yes | Custom Application-Level Login Page URL (i.e. Tenant Discovery Page URL). This value only needs to be provided if you are self-hosting the application login page. By default, the SDK will use your Wristband-hosted Application-Level Login page URL. If this value is provided, the SDK will redirect to this URL in certain cases where it cannot resolve a proper Tenant-Level Login URL. |
| dangerouslyDisableSecureCookies | boolean | No | No | USE WITH CAUTION: If set to `true`, the "Secure" attribute will not be included in any cookie settings. This should only be done when testing in local development environments that don't have HTTPS enabed.  If not provided, this value defaults to `false`. |
| isApplicationCustomDomainActive | boolean | No | Yes | Indicates whether your Wristband application is configured with an application-level custom domain that is active. This tells the SDK which URL format to use when constructing the Wristband Authorize Endpoint URL. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `defaultTenantCustomDomain` config.  Defaults to `false`. |
| loginStateSecret | string | No | No | A 32 character (or longer) secret used for encryption and decryption of login state cookies. If not provided, it will default to using the client secret. For enhanced security, it is recommended to provide a value that is unique from the client secret. You can run `openssl rand -base64 32` to create a secret from your CLI. |
| loginUrl | string | Yes | Yes | The URL of your application's login endpoint.  This is the endpoint within your application that redirects to Wristband to initialize the login flow. If you intend to use tenant subdomains in your Login Endpoint URL, then this value must contain the `{tenant_domain}` token. For example: `https://{tenant_domain}.yourapp.com/auth/login`. |
| parseTenantFromRootDomain | string | Only if using tenant subdomains in your application | Yes | The root domain for your application. This value only needs to be specified if you intend to use tenant subdomains in your Login and Callback Endpoint URLs.  The root domain should be set to the portion of the domain that comes after the tenant subdomain.  For example, if your application uses tenant subdomains such as `tenantA.yourapp.com` and `tenantB.yourapp.com`, then the root domain should be set to `yourapp.com`. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `defaultTenantCustomDomain` config. When this configuration is enabled, the SDK extracts the tenant subdomain from the host and uses it to construct the Wristband Authorize URL. |
| redirectUri | string | Yes | Yes | The URI that Wristband will redirect to after authenticating a user.  This should point to your application's callback endpoint. If you intend to use tenant subdomains in your Callback Endpoint URL, then this value must contain the `{tenant_domain}` token. For example: `https://{tenant_domain}.yourapp.com/auth/callback`. |
| scopes | string[] | No | No | The scopes required for authentication. Refer to the docs for [currently supported scopes](https://docs.wristband.dev/docs/oauth2-and-openid-connect-oidc#supported-openid-scopes). The default value is `[openid, offline_access, email]`. |
| tokenExpirationBuffer | number | No | No | Buffer time (in seconds) to subtract from the access token’s expiration time. This causes the token to be treated as expired before its actual expiration, helping to avoid token expiration during API calls. Defaults to 60 seconds. |
| wristbandApplicationVanityDomain | string | Yes | No | The vanity domain of the Wristband application. |

<br>

### `createWristbandAuth()`

```ts
function createWristbandAuth(authConfig: AuthConfig): WristbandAuth {}
```

This function creates an instance of `WristbandAuth` using lazy auto-configuration. Auto-configuration is enabled by default and will fetch any missing configuration values from the Wristband SDK Configuration Endpoint when any auth function is first called (i.e. `login`, `callback`, etc.). Set `autoConfigureEnabled` to `false` to prevent the SDK from making an API request to the Wristband SDK Configuration Endpoint. In the event auto-configuration is disabled, you must manually configure all required values. Manual configuration values take precedence over auto-configured values.

**Minimal config with auto-configure (default behavior)**
```ts
const auth = createWristbandAuth({
  clientId: "your-client-id",
  clientSecret: "your-secret",
  wristbandApplicationVanityDomain: "auth.yourapp.io"
});
```

**Manual override with partial auto-configure for some fields**
```ts
const auth = createWristbandAuth({
  clientId: "your-client-id",
  clientSecret: "your-secret",
  wristbandApplicationVanityDomain: "auth.yourapp.io",
  loginUrl: "https://yourapp.io/auth/login", // Manually override "loginUrl"
  // "redirectUri" will be auto-configured
});
```

**Auto-configure disabled**
```ts
const auth = createWristbandAuth({
  autoConfigureEnabled: false,
  clientId: "your-client-id",
  clientSecret: "your-secret",
  wristbandApplicationVanityDomain: "auth.custom.com",
  // Must manually configure non-auto-configurable fields
  isApplicationCustomDomainActive: true,
  loginUrl: "https://{tenant_domain}.custom.com/auth/login",
  redirectUri: "https://{tenant_domain}.custom.com/auth/callback",
  parseTenantFromRootDomain: "custom.com",
});
```

<br>

### `discoverWristbandAuth()`

This function creates an instance of `WristbandAuth` with eager auto-configuration. Unlike `createWristbandAuth()`, this function immediately fetches and resolves all auto-configuration values from the Wristband SDK Configuration Endpoint during initialization. This is useful when you want to fail fast when auto-configuration is unavailable, or when you need configuration values resolved before making any auth function calls. Manual configuration values take precedence over auto-configured values.

> [!WARNING]
> NOTE: For CommonJS environments, createWristbandAuth() provides simpler integration since it doesn't require async module initialization patterns.

**Eager auto-configure with error handling**
```ts
try {
  const wristbandAuth = await discoverWristbandAuth({
    clientId: "your-client-id",
    clientSecret: "your-secret",
    wristbandApplicationVanityDomain: "auth.yourapp.io"
  });

  //
  // ...Configuration is now resolved and validated...
  //
} catch (error) {
  console.error('Auto-configuration failed:', error.message);
}
```

<br>

## Auth API

### `login(req: Request, res: Response, config?: LoginConfig): Promise<string>`

```ts
await login(req, res);
```

Wristband requires that your application specify a Tenant-Level domain when redirecting to the Wristband Authorize Endpoint when initiating an auth request. When the frontend of your application redirects the user to your Express Login Endpoint, there are two ways to accomplish getting the `tenantName` information: passing a query parameter or using tenant subdomains.

The `login()` function can also take optional configuration if your application needs custom behavior:

| LoginConfig Field | Type | Required | Description |
| ----------------- | ---- | -------- | ----------- |
| customState | JSON | No | Additional state to be saved in the Login State Cookie. Upon successful completion of an auth request/login attempt, your Callback Endpoint will return this custom state (unmodified) as part of the return type. |
| defaultTenantName | string | No | An optional default tenant name to use for the login request in the event the tenant name cannot be found in either the subdomain or query parameters (depending on your subdomain configuration). |
| defaultTenantCustomDomain | string | No | An optional default tenant custom domain to use for the login request in the event the tenant custom domain cannot be found in the query parameters. |
| returnUrl | string | No | The URL to return to after authentication is completed. If a value is provided, then it takes precedence over the `return_url` request query parameter. |

#### Which Domains Are Used in the Authorize URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Authorize URL, which your login endpoint will redirect users to during the login flow. The selection follows this precedence order:

1. `tenant_custom_domain` query parameter: If provided, this takes top priority.
2. Tenant subdomain in the URL: Used if `parseTenantFromRootDomain` is specified and there is a subdomain present in the host.
3. `tenant_domain` query parameter: Evaluated if no tenant subdomain is found in the host.
4. `defaultTenantCustomDomain` in LoginConfig: Used if none of the above are present.
5. `defaultTenantName` in LoginConfig: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Tenant Domain Query Param

If your application does not wish to utilize subdomains for each tenant, you can pass the `tenant_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.io/auth/login?tenant_domain=customer01
```

Your AuthConfig would look like the following when creating an SDK instance without any subdomains:

```ts
const wristbandAuth = createWristbandAuth({
  clientId: "ic6saso5hzdvbnof3bwgccejxy",
  clientSecret: "30e9977124b13037d035be10d727806f",
  loginStateSecret: '7ffdbecc-ab7d-4134-9307-2dfcc52f7475',
  loginUrl: "https://yourapp.io/auth/login",
  redirectUri: "https://yourapp.io/auth/callback",
  wristbandApplicationVanityDomain: "yourapp-yourcompany.us.wristband.dev",
});
```

#### Tenant Subdomains

If your application wishes to utilize tenant subdomains, then you do not need to pass a query param when redirecting to your Express Login Endpoint. The SDK will parse the tenant subdomain from the host in order to make the redirection to the Wristband Authorize Endpoint. You will also need to tell the SDK what your application's root domain is in order for it to correctly parse the subdomain.

```sh
GET https://customer01.yourapp.io/auth/login
```

Your AuthConfig would look like the following when creating an SDK instance when using subdomains:

```ts
const wristbandAuth = createWristbandAuth({
  clientId: "ic6saso5hzdvbnof3bwgccejxy",
  clientSecret: "30e9977124b13037d035be10d727806f",
  loginStateSecret: '7ffdbecc-ab7d-4134-9307-2dfcc52f7475',
  loginUrl: "https://{tenant_domain}.yourapp.io/auth/login",
  redirectUri: "https://{tenant_domain}.yourapp.io/auth/callback",
  parseTenantFromRootDomain: "yourapp.io",
  wristbandApplicationVanityDomain: "yourapp-yourcompany.us.wristband.dev",
});
```

#### Default Tenant Name

For certain use cases, it may be useful to specify a default tenant name in the event that the `login()` function cannot find a tenant name in either the query parameters or in the URL subdomain. You can specify a fallback default tenant name via a `LoginConfig` object:

```ts
const loginUrl = await wristbandAuth.login(req, res, { defaultTenantName: 'default' });
res.redirect(loginUrl);
```

#### Tenant Custom Domain Query Param

If your application wishes to utilize tenant custom domains, you can pass the `tenant_custom_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.io/auth/login?tenant_custom_domain=mytenant.com
```

The tenant custom domain takes precedence over all other possible domains else when present.

#### Default Tenant Custom Domain

For certain use cases, it may be useful to specify a default tenant custom domain in the event that the `login()` function cannot find a tenant custom domain in the query parameters. You can specify a fallback default tenant custom domain via a `LoginConfig` object:

```ts
const loginUrl = await wristbandAuth.login(req, res, { defaultTenantCustomDomain: 'mytenant.com' });
res.redirect(loginUrl);
```

The default tenant custom domain takes precedence over all other possible domain configurations when present except for the case where the `tenant_custom_domain` query parameter exists in the request.

#### Custom State

Before your Login Endpoint redirects to Wristband, it will create a Login State Cookie to cache all necessary data required in the Callback Endpoint to complete any auth requests. You can inject additional state into that cookie via a `LoginConfig` object:

```ts
const loginUrl = await wristbandAuth.login(req, res, { customState: { test: 'abc' } });
res.redirect(loginUrl);
```

> [!WARNING]
> Injecting custom state is an advanced feature, and it is recommended to use `customState` sparingly. Most applications may not need it at all. The max cookie size is 4kB. From our own tests, passing a `customState` JSON of at most 1kB should be a safe ceiling.

#### Login Hints

Wristband will redirect to your Express Login Endpoint for workflows like Application-Level Login (Tenant Discovery) and can pass the `login_hint` query parameter as part of the redirect request:

```sh
GET https://customer01.yourapp.io/auth/login?login_hint=user@wristband.dev
```

If Wristband passes this parameter, it will be appended as part of the redirect request to the Wristband Authorize Endpoint. Typically, the email form field on the Tenant-Level Login page is pre-filled when a user has previously entered their email on the Application-Level Login Page.

#### Return URLs

It is possible that users will try to access a location within your application that is not some default landing page. In those cases, they would expect to immediately land back at that desired location after logging in.  This is a better experience for the user, especially in cases where they have application URLs bookmarked for convenience.

Given that your frontend will redirect users to your Express Login Endpoint, you can either include it in your Login Config:

```ts
const loginUrl = await wristbandAuth.login(req, res, {
  returnUrl: 'https://customer01.yourapp.io/settings/profile',
});
res.redirect(loginUrl);
```

...or you can pass a `return_url` query parameter when redirecting to your Login Endpoint:

```sh
GET https://customer01.yourapp.io/auth/login?return_url=https://customer01.yourapp.io/settings/profile
```

The return URL is stored in the Login State Cookie, and it is available to you in your Callback Endpoint after the SDK's `callback()` method is done executing. You can choose to send users to that return URL (if necessary). The Login Config takes precedence over the query parameter in the event a value is provided for both.

##### Return URL Preservation During Tenant Discovery

When the `login()` method cannot resolve a tenant domain from the request (subdomain, query parameters, or defaults), the SDK redirects users to the Application-Level Login (Tenant Discovery) Page. To ensure a seamless user experience, any provided return URL values are automatically preserved by appending them to the `state` query parameter. This allows the return URL to be propagated back to the Login Endpoint once tenant discovery is complete, ensuring users land at their originally intended destination after authentication.

<br>

### `callback(req: Request, res: Response): Promise<CallbackResult>`

```ts
const callbackResult = await callback(req, res);
```

After a user authenticates on the Tenant-Level Login Page, Wristband will redirect to your Express Callback Endpoint with an authorization code which can be used to exchange for an access token. It will also pass the state parameter that was generated during the Login Endpoint.

```sh
GET https://customer01.yourapp.io/auth/callback?state=f983yr893hf89ewn0idjw8e9f&code=shcsh90jf9wc09j9w0jewc
```

The SDK will validate that the incoming state matches the Login State Cookie, and then it will call the Wristband Token Endpoint to exchange the authorizaiton code for JWTs. Lastly, it will call the Wristband Userinfo Endpoint to get any user data as specified by the `scopes` in your SDK configuration. The return type of the callback function is a CallbackResult object containing the result of what happened during callback execution as well as any accompanying data:

| CallbackResult Field | Type | Description |
| -------------------- | ---- | ----------- |
| callbackData | `CallbackData` | The callback data received after authentication (`COMPLETED` result only). |
| redirectUrl | string | A URL that you need to redirect to (`REDIRECT_REQUIRED` result only). For some edge cases, the SDK will require a redirect to restart the login flow. |
| type | `CallbackResultType`  | Enum representing the type of the callback result. |

The following are the possible `CallbackResultType` enum values that can be returned from the callback execution:

| CallbackResultType  | Description |
| ------------------- | ----------- |
| `COMPLETED`  | Indicates that the callback is successfully completed and data is available for creating a session. |
| `REDIRECT_REQUIRED`  | Indicates that a redirect to the login endpoint is required. |

When the callback returns a `COMPLETED` result, all of the token and userinfo data also gets returned. This enables your application to create an application session for the user and then redirect them back into your application. The `CallbackData` is defined as follows:

| CallbackData Field | Type | Description |
| ------------------ | ---- | ----------- |
| accessToken | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| customState | JSON or `undefined` | If you injected custom state into the Login State Cookie during the Login Endpoint for the current auth request, then that same custom state will be returned in this field. |
| expiresAt | number | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `tokenExpirationBuffer` SDK configuration is accounted for in this value. |
| expiresIn | number | The durtaion from the current time until the access token is expired (in seconds). The `tokenExpirationBuffer` SDK configuration is accounted for in this value. |
| idToken | string | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refreshToken | string or `undefined` | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |
| returnUrl | string or `undefined` | The URL to return to after authentication is completed. |
| tenantCustomDomain | string | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenantName | string | The name of the tenant the user belongs to. |
| userinfo | `UserInfo` | Data for the current user retrieved from the Wristband Userinfo Endpoint. The data returned in this object follows the format laid out in the [Wristband Userinfo Endpoint documentation](https://docs.wristband.dev/reference/userinfov1). The exact fields that get returned are based on the scopes you configured in the SDK. |

The `UserInfo` type is defined as follows:

| UserInfo Field | Type | Always Returned | Description |
| -------------- | ---- | --------------- | ----------- |
| userId | string | Yes | ID of the user (mapped from "sub" claim). |
| tenantId | string | Yes | ID of the tenant that the user belongs to (mapped from "tnt_id" claim). |
| applicationId | string | Yes | ID of the application that the user belongs to (mapped from "app_id" claim). |
| identityProviderName | string | Yes | Name of the identity provider (mapped from "idp_name" claim). |
| fullName | string or `undefined` | No | End-User's full name in displayable form (mapped from "name" claim; requires `profile` scope). |
| givenName | string or `undefined` | No | Given name(s) or first name(s) of the End-User (requires `profile` scope). |
| familyName | string or `undefined` | No | Surname(s) or last name(s) of the End-User (requires `profile` scope). |
| middleName | string or `undefined` | No | Middle name(s) of the End-User (requires `profile` scope). |
| nickname | string or `undefined` | No | Casual name of the End-User (requires `profile` scope). |
| displayName | string or `undefined` | No | Shorthand name by which the End-User wishes to be referred (requires `profile` scope). |
| pictureUrl | string or `undefined` | No | URL of the End-User's profile picture (requires `profile` scope). |
| email | string or `undefined` | No | End-User's preferred email address (requires `email` scope). |
| emailVerified | boolean or `undefined` | No | True if the End-User's email address has been verified (requires `email` scope). |
| gender | string or `undefined` | No | End-User's gender (requires `profile` scope). |
| birthdate | string or `undefined` | No | End-User's birthday in YYYY-MM-DD format (requires `profile` scope). |
| timeZone | string or `undefined` | No | End-User's time zone (requires `profile` scope). |
| locale | string or `undefined` | No | End-User's locale as BCP47 language tag, e.g., "en-US" (requires `profile` scope). |
| phoneNumber | string or `undefined` | No | End-User's telephone number in E.164 format (requires `phone` scope). |
| phoneNumberVerified | boolean or `undefined` | No | True if the End-User's phone number has been verified (requires `phone` scope). |
| updatedAt | number or `undefined` | No | Time the End-User's information was last updated as Unix timestamp (requires `profile` scope). |
| roles | `UserInfoRole[]` or `undefined` | No | The roles assigned to the user (requires `roles` scope). |
| customClaims | `Record<string, any>` or `undefined` | No | Object containing any configured custom claims. |

The `UserInfoRole` type is defined as follows:

| UserInfoRole Field | Type | Description |
| ------------------ | ---- | ----------- |
| id | string | Globally unique ID of the role. |
| name | string | The role name (e.g., "app:app-name:admin"). |
| displayName | string | The human-readable display name for the role. |

#### Redirect Responses

There are certain scenarios where a redirect URL is returned by the SDK. The following are edge cases where this occurs:

- The Login State Cookie is missing by the time Wristband redirects back to the Callback Endpoint.
- The `state` query parameter sent from Wristband to your Callback Endpoint does not match the Login State Cookie.
- Wristband sends an `error` query parameter to your Callback Endpoint, and it is an expected error type that the SDK knows how to resolve.

The location of where the user gets redirected to in these scenarios depends on if the application is using tenant subdomains and if the SDK is able to determine which tenant the user is currently attempting to log in to. The resolution happens in the following order:

1. If the tenant domain can be determined, then the user will get redirected back to your Express Login Endpoint.
2. Otherwise, the user will be sent to the Wristband-hosted Tenant-Level Login Page URL.

#### Error Parameters

Certain edge cases are possible where Wristband encounters an error during the processing of an auth request. These are the following query parameters that are sent for those cases to your Callback Endpoint:

| Query Parameter | Description |
| --------------- | ----------- |
| error | Indicates an error that occurred during the Login Workflow. |
| error_description | A human-readable description or explanation of the error to help diagnose and resolve issues more effectively. |

```sh
GET https://customer01.yourapp.io/auth/callback?state=f983yr893hf89ewn0idjw8e9f&error=login_required&error_description=User%20must%20re-authenticate%20because%20the%20specified%20max_age%20value%20has%20elapsed
```

The error types that get automatically resolved in the SDK are:

| Error | Description |
| ----- | ----------- |
| login_required | Indicates that the user needs to log in to continue. This error can occur in scenarios where the user's session has expired, the user is not currently authenticated, or Wristband requires the user to explicitly log in again for security reasons. |

For all other error types, the SDK will throw a `WristbandError` object (containing the error and description) that your application can catch and handle. Most errors come from SDK configuration issues during development that should be addressed before release to production.

<br>

### `logout(req: Request, res: Response, config?: LogoutConfig): Promise<string>`

```ts
const logoutUrl = await logout(req, res, { refreshToken: '98yht308hf902hc90wh09' });
res.redirect(logoutUrl);
```

When users of your application are ready to log out or their application session expires, your frontend should redirect the user to your Express Logout Endpoint.

```sh
GET https://customer01.yourapp.io/auth/logout
```

If your application created a session, it should destroy it before invoking the `logout()` function.  This function can also take an optional `LogoutConfig` argument:

| LogoutConfig Field | Type | Required | Description |
| ------------------ | ---- | -------- | ----------- |
| redirectUrl | string | No | Optional URL that Wristband will redirect to after the logout operation has completed. This will also take precedence over the `customApplicationLoginPageUrl` (if specified) in the SDK AuthConfig if the tenant domain cannot be determined when attempting to redirect to the Wristband Logout Endpoint. |
| refreshToken | string | No | The refresh token to revoke. |
| state | string | No | Optional value that will be appended as a query parameter to the resolved logout URL, if provided. Maximum length of 512 characters. |
| tenantCustomDomain | string | No | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenantName | string | No | The name of the tenant the user belongs to. |

#### Which Domains Are Used in the Logout URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Logout URL, which your login endpoint will redirect users to during the logout flow. The selection follows this precedence order:

1. `tenantCustomDomain` in LogoutConfig: If provided, this takes top priority.
2. `tenantName` in LogoutConfig: This takes the next priority if `tenantCustomDomain` is not present.
3. `tenant_custom_domain` query parameter: Evaluated if present and there is also no LogoutConfig provided for either `tenantCustomDomain` or `tenantName`.
4. Tenant subdomain in the URL: Used if none of the above are present, and `parseTenantFromRootDomain` is specified, and the subdomain is present in the host.
5. `tenant_domain` query parameter: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Revoking Refresh Tokens

If your application requested refresh tokens during the Login Workflow (via the `offline_access` scope), it is crucial to revoke the user's access to that refresh token when logging out. Otherwise, the refresh token would still be valid and able to refresh new access tokens.  You should pass the refresh token into the LogoutConfig when invoking the `logout()` function, and the SDK will call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) automatically.

#### Resolving Tenant Domains

Much like the Login Endpoint, Wristband requires your application specify a Tenant-Level domain when redirecting to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1). If your application does not utilize tenant subdomains, then you can either explicitly pass it into the LogoutConfig:

```ts
const logoutUrl = await logout(req, res, config: {
  refreshToken: '98yht308hf902hc90wh09',
  tenantName: 'customer01'
});
res.redirect(logoutUrl);
```

...or you can alternatively pass the `tenant_domain` query parameter in your redirect request to Logout Endpoint:

```ts
//
// Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_domain=customer01"
//
const logoutUrl = await logout(req, res, config: { refreshToken: '98yht308hf902hc90wh09' });
res.redirect(logoutUrl);
```

If your application uses tenant subdomains, then passing the `tenantName` field to the LogoutConfig is not required since the SDK will automatically parse the subdomain from the URL as long as the `parseTenantFromRootDomain` SDK config is set.

#### Tenant Custom Domains

If you have a tenant that relies on a tenant custom domain, then you can either explicitly pass it into the LogoutConfig:

```ts
const logoutUrl = await logout(req, res, { refreshToken: '98yht308hf902hc90wh09', tenantCustomDomain: 'mytenant.com' });
res.redirect(logoutUrl);
```

...or you can alternatively pass the `tenant_custom_domain` query parameter in your redirect request to Logout Endpoint:

```ts
//
// Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_custom_domain=customer01.com"
//
const logoutUrl = await logout(req, res, config: { refreshToken: '98yht308hf902hc90wh09' });
res.redirect(logoutUrl);
```

If your application supports a mixture of tenants that use tenant subdomains and tenant custom domains, then you should consider passing both the tenant names and tenant custom domains (either via LogoutConfig or by query parameters) to ensure all use cases are handled by the SDK.

**Pass tenant names and custom domains in LogoutConfig**
```ts
const { refreshToken, tenantCustomDomain, tenantName } = session;

const logoutUrl = await logout(req, res, { refreshToken, tenantCustomDomain, tenantName });
res.redirect(logoutUrl);
```

**Pass tenant names and custom domains in query params**
```ts
//
// Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_custom_domain=customer01.com&tenant_domain=customer01"
//
const { refreshToken } = session;

const logoutUrl = await logout(req, res, { refreshToken });
res.redirect(logoutUrl);
```

#### Preserving State After Logout

The `state` field in the `LogoutConfig` allows you to preserve application state through the logout flow.

```ts
const logoutConfig = {
  refreshToken: '98yht308hf902hc90wh09',
  state: 'user_initiated_logout',
  tenantName: 'customer01'
};
const logoutUrl = await logout(req, res, logoutConfig);
```

The state value gets appended as a query parameter to the Wristband Logout Endpoint URL:

```sh
https://customer01.auth.yourapp.io/api/v1/logout?client_id=123&state=user_initiated_logout
```

After logout completes, Wristband will redirect to your configured redirect URL (either your Login Endpoint by default, or a custom logout redirect URL if configured) with the `state` parameter included:

```sh
https://yourapp.io/auth/login?tenant_domain=customer01&state=user_initiated_logout
```

This is useful for tracking logout context, displaying post-logout messages, or handling different logout scenarios. The state value is limited to 512 characters and will be URL-encoded automatically.

#### Custom Logout Redirect URL

Some applications might require the ability to land on a different page besides the Login Page after logging a user out. You can add the `redirectUrl` field to the LogoutConfig, and doing so will tell Wristband to redirect to that location after it finishes processing the logout request.

```ts
const logoutConfig = {
  redirectUrl: 'https://custom-logout.com',
  refreshToken: '98yht308hf902hc90wh09',
  tenantName: 'customer01'
};
const logoutUrl = await logout(req, res, logoutConfig);
res.redirect(logoutUrl);
```

<br>

### `refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null>`

```ts
const tokenData = await refreshTokenIfExpired('98yht308hf902hc90wh09', 1710707503788);
```

If your application is using access tokens generated by Wristband either to make API calls to Wristband or to protect other backend APIs, then your applicaiton needs to ensure that access tokens don't expire until the user's session ends.  You can use the refresh token to generate new access tokens.

| Argument | Type | Required | Description |
| -------- | ---- | -------- | ----------- |
| expiresAt | number | Yes | Unix timestamp in milliseconds at which the token expires. |
| refreshToken | string | Yes | The refresh token used to send to Wristband when access tokens expire in order to receive new tokens. |

If the `refreshTokenIfExpired()` functions finds that your token has not expired yet, it will return `null` as the value, which means your app can simply continue forward as usual.

The `TokenData` is defined as follows:

| TokenData Field | Type | Description |
| --------------- | ---- | ----------- |
| accessToken | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| expiresAt | number | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `tokenExpirationBuffer` SDK configuration is accounted for in this value. |
| expiresIn | number | The durtaion from the current time until the access token is expired (in seconds). The `tokenExpirationBuffer` SDK configuration is accounted for in this value. |
| idToken | string | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refreshToken | string or `undefined` | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |

<br>

## Session Management

The SDK provides encrypted cookie-based session management via `createWristbandSession()`, powered by [@wristband/typescript-session](https://github.com/wristband-dev/typescript-session). Sessions are automatically attached to `req.session` on every request and provide both dictionary-style and attribute-style access for storing user data. All session data is encrypted using AES-256-GCM before being stored in a session cookie.

<br>

### Session Configuration

Configure session behavior when creating the middleware:

```typescript
import express from 'express';
import { createWristbandSession } from '@wristband/express-auth/session';

const app = express();

app.use(createWristbandSession({
  // Session cookie configs
  cookieName: 'session',
  secrets: 'your-secret-key-min-32-chars',
  domain: 'app.example.com',
  maxAge: 3600,
  path: '/',
  sameSite: 'Lax',
  secure: true,
  // Optional CSRF token protection configs
  enableCsrfProtection: true,
  csrfCookieName: 'CSRF-TOKEN',
  csrfCookieDomain: '.example.com',
}));
```

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| secrets | string or string[] | Yes | N/A | Secret key(s) for session encryption (minimum 32 characters). Can be a single string or array of strings for key rotation. You can run `openssl rand -base64 32` on your CLI to generate a secret. |
| cookieName | string | No | `session` | Name of the session cookie. |
| domain | string | No | `undefined` (cookie only sent to current domain) | Domain for the session cookie. |
| maxAge | number | No | 3600 (1 hour) | Cookie expiration time in seconds. |
| path | string | No | "/" | Cookie path. |
| sameSite | `Lax` or `Strict` or `None` | No | `Lax` | Cookie SameSite attribute. |
| secure | boolean | No | true | Require HTTPS for cookies. **Set `secure: true` in production to ensure cookies are only sent over HTTPS.** |
| enableCsrfProtection | boolean | No | false | When enabled, a CSRF token is automatically generated after authentication (via  `session.save()`) and is stored in the session. A separate CSRF cookie is also set in addition to the session cookie. |
| csrfCookieName | string | No | `CSRF-TOKEN` | Name of the CSRF cookie. |
| csrfCookieDomain | string | No | `undefined` (defaults to `domain` value) | Domain for CSRF cookie. |

For full details on session configuration options, see the [@wristband/typescript-session](https://github.com/wristband-dev/typescript-session?tab=readme-ov-file#sessionoptions) documentation.

> [!NOTE]
> When using CommonJS, you can either call `createWristbandSession()` inline in `app.use()`, or wrap it in a factory function if exporting from a separate module (see [Set Up Session Management](#2-set-up-session-management) for an example). Do not export the middleware directly as a singleton (e.g., `const wristbandSession = createWristbandSession(...); module.exports = { wristbandSession }`) with CommonJS as this causes session decryption failures due to how the `onHeaders` hook interacts with module caching. This issue does not affect ES modules.

<br>

### The Session Object

Once `wristbandSession` middleware is configured and added to your Express app, every request automatically has a session object attached at `req.session`. The session data is typed using the `SessionData` interface from [@wristband/typescript-session](https://github.com/wristband-dev/typescript-session?tab=readme-ov-file#typescript-support). You can access session data using both dictionary-style access (`req.session['key']`) and attribute-style access (`req.session.key`).

#### Understanding Session State

Sessions start empty. All base session fields are initially `undefined` because the session begins with no data. Session fields are only populated when you either:

- Call `req.session.fromCallback(callbackData)` after successful authentication (automatically sets all auth-related fields)
- Manually set fields and call `req.session.save()` to persist them

This means before authentication, fields like `userId`, `accessToken`, etc. will be `undefined`.

#### Base Session Fields

These `SessionData` fields are automatically populated when you call `req.session.fromCallback()` after successful Wristband authentication:

| SessionData Field | Type | Description |
| ----------------- | ---- | ----------- |
| isAuthenticated | boolean or `undefined` | Whether the user is authenticated (set to `true` by `fromCallback()`). |
| accessToken | string or `undefined` | JWT access token for making authenticated API calls to Wristband and other services. |
| expiresAt | number or `undefined` | Token expiration timestamp (milliseconds since Unix epoch). Accounts for `tokenExpirationBuffer` from SDK config. |
| userId | string or `undefined` | Unique identifier for the authenticated user. |
| tenantId | string or `undefined` | Unique identifier for the tenant that the user belongs to. |
| tenantName | string or `undefined` | Name of the tenant that the user belongs to. |
| identityProviderName | string or `undefined` | Name of the identity provider that the user belongs to. |
| csrfToken | string or `undefined` | CSRF token for request validation. Token value is automatically generated by `fromCallback()`. |
| refreshToken | string or `undefined` | Refresh token for obtaining new access tokens when they expire. Only present if `offline_access` scope was requested during authentication. |
| tenantCustomDomain | string or `undefined` | Custom domain for the tenant, if configured. Only present if a tenant custom domain was used during authentication. |

#### Extending SessionData with Custom Fields

You can extend the `SessionData` interface to add type-safe custom fields to your session using TypeScript declaration merging:

```typescript
// src/types/session-data.ts
import '@wristband/typescript-session';

/**
 * Augment SessionData with optional, app-specific fields so custom
 * properties are type-checked across your application.
 */
declare module '@wristband/typescript-session' {
  interface SessionData {
    theme?: string;
    lastLogin?: number;
  }
}
```

Then use your custom fields with full type safety:

```typescript
// src/routes/settings-routes.ts
app.post('/api/settings', requireWristbandAuth, async (req, res) => {
  req.session.theme = 'dark';          // ✅ Type-safe
  req.session.lastLogin = Date.now();  // ✅ Type-safe
  req.session.foo = 'bar';             // ❌ Not type-safe
  
  await req.session.save();
  
  res.json({ 
    userId: req.session.userId,
    theme: req.session.theme
  });
});
```

<br>

### Authentication Middleware

The SDK provides a factory function for creating the `requireWristbandAuth` middleware (via `wristbandAuth.createRequireSessionAuth()`) for protecting routes with session-based authentication. When a request hits a route protected by `requireWristbandAuth`, the middleware:

1. Checks if the session exists and the user is authenticated
2. Validates the CSRF token (if `enableCsrfProtection` is enabled)
3. Checks if the access token has expired (if both `refreshToken` and `expiresAt` are present in the session)
4. If expired and a refresh token exists, automatically refreshes the token (with up to 3 retry attempts)
5. Updates the session with new token data when refresh occurs
6. Saves the session to persist changes and extend expiration (rolling sessions)

#### Configuration Options

You create this middleware in your Wristband configuration file:

```typescript
// src/wristband.ts
import { createWristbandAuth } from '@wristband/express-auth';

export const wristbandAuth = createWristbandAuth({
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  wristbandApplicationVanityDomain: "auth.yourapp.io",
});

// Create the auth middleware
export const requireWristbandAuth = wristbandAuth.createRequireSessionAuth();
```

The `createRequireSessionAuth()` function accepts an optional configuration object:

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| enableCsrfProtection | boolean | No | false | Enable CSRF token validation. When enabled, the middleware will validate that the CSRF token from the request header matches the token in the session. See [CSRF Protection](#csrf-protection) for more details. |
| csrfTokenHeaderName | string | No | `x-csrf-token` | The HTTP request header name to read the CSRF token from. Must match the header name your frontend uses when sending CSRF tokens. |

**Example with CSRF protection:**
```typescript
// Frontend will send CSRF token in X-CUSTOM-XSRF-TOKEN header
export const requireWristbandAuth = wristbandAuth.createRequireSessionAuth({
  enableCsrfProtection: true,
  csrfTokenHeaderName: 'X-CUSTOM-XSRF-TOKEN'
});
```

#### Using the Session Auth Middleware

You can apply the session auth middleware in two ways:

- At the router level to protect all routes within a router
- At the individual route level for more granular control

**Router-Level Protection**
```typescript
// src/routes/protected-routes.ts
import express from 'express';
import { requireWristbandAuth } from '../wristband';

const router = express.Router();

// All routes in this router require authentication
router.use(requireWristbandAuth);

router.get('/api/orders', (req, res) => {
  res.json({ orders: [] });
});

router.get('/api/settings', (req, res) => {
  res.json({ settings: req.session.preferences });
});

export default router;
```

**Route-Level Protection**
```typescript
// src/routes/mixed-routes.ts
import express from 'express';
import { requireWristbandAuth } from '../wristband';

const router = express.Router();

// No authentication required on this route
router.get('/api/public', (req, res) => {
  res.json({ message: 'Public data' });
});

// Authentication is required on this route
router.get('/api/protected', requireWristbandAuth, (req, res) => {
  res.json({ message: 'Protected data' });
});

export default router;
```

#### Middleware Error Handling

Depending on the outcome, any of the following error scenarios could occur:

- If the `wristbandSession` middleware is not configured on the Express app (i.e. no `req.session` object), then the middleware will throw an error.
- If the user is not authenticated or token refresh fails, then an HTTP 401 response is returned.
- If CSRF token validation fails, then an HTTP 403 response is returned.

Your frontend should treat 401 and 403 responses as signals that the user must re-authenticate before continuing.

**Handling Auth Errors in Your Frontend:**
```typescript
async function makeAuthenticatedRequest(url: string, options: RequestInit = {}) {
  try {
    const response = await fetch(url, {
      ...options,
      credentials: 'include', // Include cookies
      headers: {
        'X-CSRF-TOKEN': getCsrfToken(), // Your function to read CSRF cookie
        ...options.headers,
      },
    });

    // Handle authentication errors
    if (response.status === 401 || response.status === 403) {
      // Redirect to login - user needs to re-authenticate
      window.location.href = '/api/auth/login';
      return;
    }

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Request failed:', error);
    throw error;
  }
}
```

<br>

### Session Access Patterns

Sessions behave like plain JavaScript objects, supporting both dot (`session.userId`) and bracket (`session['userId']`) notation for getting, setting, checking, and deleting values. You can access session data via `req.session` in any route handler.

```typescript
// Setting values
req.session['userId'] = '123';
req.session.cart = { items: [], total: 0 };

// Getting values
const userId = req.session['userId'];
const cart = req.session.cart;

// Check existence
if ('cart' in req.session) {
  const cart = req.session.cart;
}

// Deleting values
delete req.session['userId'];
delete req.session.cart;

// Save changes
await req.session.save();
```

For additional session access methods, see the [@wristband/typescript-session](https://github.com/wristband-dev/typescript-session?tab=readme-ov-file#core-methods-all-runtimes) methods documentation.

<br>

#### Limitations

**JSON Serialization:** All values stored in the session must be JSON-serializable. Attempting to store non-serializable values (like functions, class instances, or objects with circular references) will result in errors when the session is encrypted and saved.

**Size Limit:** Sessions are limited to 4KB total, including encryption overhead and cookie attributes. This limit is enforced by the browser per [RFC 6265](https://datatracker.ietf.org/doc/html/rfc6265). If your session data exceeds this limit, an error will be thrown when attempting to save. If you need to store larger amounts of data, consider:

- Storing only essential data in the session (IDs, tokens, minimal user info)
- Using a server-side session store like Redis with express-session
- Storing large data in a database and keeping only a reference ID in the session

<br>

### Session API

The session object provides several methods for managing sessions and authentication data. These include lifecycle methods for persisting and destroying sessions, as well as Wristband-specific methods for creating sessions from callback data and generating responses for frontend SDKs.

#### `session.fromCallback(callbackData, customFields?)`

Create a session from Wristband callback data after successful authentication. This is a convenience method that automatically:

- Extracts a core subset of user and tenant info from callback data
- Optionally generates a CSRF token (if `enableCsrfProtection` is enabled)
- Marks the session for persistence in an encrypted session cookie

| Parameters | Type | Required | Default | Description |
| ---------- | ---- | -------- | ------- | ----------- |
| callbackData | `CallbackData` | Yes | N/A | The callback data from `wristbandAuth.callback()`. An error is thrown if `callbackData` is null or `callbackData.userinfo` is missing. |
| customFields | `Record<string, any>` | No | `undefined` | Additional fields to store. An error is thrown if `customFields` aren't JSON-serializable. |

```typescript
const callbackResult = await wristbandAuth.callback(req, res);

// Example: basic usage
req.session.fromCallback(callbackResult.callbackData!);

// Example: with custom fields
req.session.fromCallback(callbackResult.callbackData!, {
  preferences: { theme: 'dark' },
  lastLogin: Date.now()
});
```

The following fields from the callback data are automatically stored in the session:

- `isAuthenticated` (always set to `true`)
- `accessToken`
- `expiresAt`
- `userId` (from `callbackData.userinfo.userId`)
- `tenantId` (from `callbackData.userinfo.tenantId`)
- `tenantName`
- `identityProviderName` (from `callbackData.userinfo.identityProviderName`)
- `csrfToken` (auto-generated only if `enableCsrfProtection` is enabled)
- `refreshToken` (only if `offline_access` scope was requested)
- `tenantCustomDomain` (only if a tenant custom domain was used during authentication)

<br>

#### `session.save()`

Mark the session for persistence. This refreshes the cookie expiration time (implementing rolling sessions - extending session expiration on each request) and saves any modifications made to session data. If CSRF protection is enabled, this also generates and stores a CSRF token in both the session (in the `csrfToken` field, assuming a value is not already defined) and CSRF cookies. Use `save()` when manually modifying session data or when you want to keep sessions alive based on user activity.

```typescript
// Extend session without modification (rolling sessions)
if (req.session.isAuthenticated) {
  await req.session.save();
}

// After modifying session
req.session.lastActivity = Date.now();
await req.session.save();
```

<br>

#### `session.destroy()`

Delete the session and clear all cookies (both session and CSRF). Use this when logging users out.

```typescript
app.get('/auth/logout', async (req, res) => {
  const { refreshToken, tenantName } = req.session;
  
  // Destroy session
  req.session.destroy();

  const logoutUrl = await wristbandAuth.logout(req, res, { tenantName, refreshToken });
  res.redirect(logoutUrl);
});
```

<br>

#### `session.getSessionResponse(metadata?)`

Create a `SessionResponse` for Wristband frontend SDKs. This method is typically used in your Session Endpoint. An error is thrown if `tenantId` or `userId` are missing from the session.

| Parameters | Type | Required | Default | Description |
| ---------- | ---- | -------- | ------- | ----------- |
| metadata | `Record<string, any>` | No | `undefined` | Custom metadata to include (must be JSON-serializable). |

```typescript
app.get('/auth/session', requireWristbandAuth, async (req, res) => {
  const sessionResponse = req.session.getSessionResponse({
    name: req.session.fullName,
    preferences: req.session.preferences
  });
  return res.status(200).json(sessionResponse);
});
```

##### `SessionResponse`

Returned by `getSessionResponse()`. The response format matches what Wristband frontend SDKs expect from Session Endpoints.

| SessionResponse Field | Type | Description |
| --------------------- | ---- | ----------- |
| userId | string | The ID of the user who authenticated. |
| tenantId | string | The ID of the tenant that the authenticated user belongs to. |
| metadata | `Record<string, any>` | Any included custom session metadata. Defaults to an empty object if none was provided. |

<br>

#### `session.getTokenResponse()`

Create a TokenResponse for Wristband frontend SDKs. This method is typically used in your Token Endpoint. An error is thrown if `accessToken` or `expiresAt` are missing from the session.

```typescript
app.get('/auth/token', requireWristbandAuth, async (req, res) => {
  const tokenResponse = req.session.getTokenResponse();
  return res.status(200).json(tokenResponse);
});
```

##### TokenResponse

Returned by `getTokenResponse()`. The response format matches what Wristband frontend SDKs expect from Token Endpoints.

| TokenResponse Field | Type | Description |
| --------------------- | ---- | ----------- |
| accessToken | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| expiresAt | number | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `tokenExpirationBuffer` SDK configuration is accounted for in this value. |

<br>

### CSRF Protection

When you enable CSRF protection in your session configuration and save a session using `save()`, the SDK automatically generates a CSRF token and stores it in two locations:

- Session cookie (encrypted, HttpOnly): Contains the CSRF token as part of the encrypted session data
- CSRF cookie (unencrypted, readable by JavaScript): Contains the same CSRF token in plaintext

This dual-cookie approach follows the [Synchronizer Token Pattern](https://docs.wristband.dev/docs/csrf-protection-for-backend-servers):

- The session cookie proves the user is authenticated (server-side validation)
- The CSRF cookie must be read by your frontend and sent in request headers (client-side participation)

#### Enabling CSRF Protection

To enable CSRF protection, you must configure it in both the session middleware and the authentication middleware:

```typescript
// src/wristband.ts
export const wristbandSession = createWristbandSession({
  secrets: 'your-secret-key-min-32-chars',
  maxAge: 3600,
  enableCsrfProtection: true,  // <-- Enable CSRF protection
});

export const requireWristbandAuth = wristbandAuth.createRequireSessionAuth({
  enableCsrfProtection: true,  // <-- Validate CSRF tokens on protected routes
  csrfTokenHeaderName: 'x-csrf-token'
});
```

#### Frontend Implementation

Your frontend must read the CSRF token from the CSRF cookie and include it in a CSRF header for all state-changing requests:

```typescript
// Read CSRF token from cookie
const csrfToken = document.cookie
  .split('; ')
  .find(row => row.startsWith('CSRF-TOKEN='))
  ?.split('=')[1];

// Include in requests
fetch('/api/protected-endpoint', {
  method: 'POST',
  headers: {
    'X-CSRF-TOKEN': csrfToken,
    'Content-Type': 'application/json'
  },
  credentials: 'include',
  body: JSON.stringify({ data: 'example' })
});
```

When you use the `requireWristbandAuth` middleware with `enableCsrfProtection: true`, CSRF validation happens automatically on every request. If CSRF validation fails, an HTTP 403 Forbidden response is returned.

> [!NOTE]
> CSRF validation is primarily for state-changing operations (POST, PUT, DELETE). GET requests can use `requireWristbandAuth` for authentication without concern, though the CSRF token will still be validated.

```typescript
// CSRF is validated automatically when using requireWristbandAuth
app.post('/api/data', requireWristbandAuth, async (req, res) => {
  // By the time your route handler runs, CSRF has been validated
  req.session.data = 'new_data';
  await req.session.save();
  return res.json({ status: 'success' });
});
```

<br>

## Wristband Multi-Tenant Express Demo App

You can check out the [Wristband Express demo app](https://github.com/wristband-dev/expressjs-demo-app) to see this SDK in action. Refer to that GitHub repository for more information.

<br/>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.

<br/>
