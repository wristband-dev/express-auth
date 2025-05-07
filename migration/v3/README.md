<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instruction from version v2.0.0 to version v3.0.0
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

# Migration instruction from version v2.0.0 to version v3.0.0

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 3.x

<br>

## Table of Contents

- [SDK Configuration Property Name Change](#sdk-configuration-property-name-change)
- [Redirect Logic Moved Upstream in Auth Flows](#redirect-logic-moved-upstream-in-auth-flows)
  - [Login](#login)
  - [Logout](#logout)
- [Callback Result Field Renamed](#callback-result-field-renamed)

<br>

## SDK Configuration Property Name Change

When calling `createWristbandAuth` to initialize the SDK, the `wristbandApplicationDomain` property has been renamed to `wristbandApplicationVanityDomain` in order to be more explicit:

```typescript
import { createWristbandAuth } from '@wristband/express-auth';

const wristbandAuth = createWristbandAuth({
  clientId: "ic6saso5hzdvbnof3bwgccejxy",
  clientSecret: "30e9977124b13037d035be10d727806f",
  loginStateSecret: '7ffdbecc-ab7d-4134-9307-2dfcc52f7475',
  loginUrl: "https://{tenant_domain}.yourapp.io/auth/login",
  redirectUri: "https://{tenant_domain}.yourapp.io/auth/callback",
  rootDomain: "yourapp.io",
  useCustomDomains: true,
  useTenantSubdomains: true,
  // New name for app vanity domain
  - wristbandApplicationDomain: "auth.yourapp.io",  
  + wristbandApplicationVanityDomain: "auth.yourapp.io",   
});

export default wristbandAuth;
```

<br>

## Redirect Logic Moved Upstream in Auth Flows

Both the `login` and `logout` functions now return a redirect URL value instead of automatically invoking the redirect. The server code which calls `login` and `logout` is now responsible for calling `res.redirect()` with the value of the returned url. This change allows your code to customize redirect behavior, making auth flows more adaptable to different environments and use cases.

**Login**
```typescript
import { wristbandAuth } from './wristband-auth.js';

app.get('/auth/login', async (req, res) => {
  try {
    // caller now does the redirect with the returned URL
    - await wristbandAuth.login(req, res);
    + const loginUrl = await wristbandAuth.login(req, res);
    + res.redirect(loginUrl);
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});
```

<br>

**Logout**
```typescript
import { wristbandAuth } from './wristband-auth.js';

app.get('/auth/logout', async (req, res) => {
  const { refreshToken, tenantDomainName } = req.session;

  res.clearCookie('my-session-cookie-name');
  req.session.destroy();

  try {
    // caller now does the redirect with the returned url
    - await wristbandAuth.logout(req, res, { tenantDomainName, refreshToken });
    + const logoutUrl = await wristbandAuth.logout(req, res, { tenantDomainName, refreshToken });
    + res.redirect(logoutUrl);
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});
```

<br>

## Callback Result Refactoring

The `CallbackResult` that is returned from calling `callback` has two changes:
1. The `result` property has been renamed to `type` (Typescript type is still `CallbackResultType`) in order to reduce confusion.
2. When the `type` has a value of `REDIRECT_REQUIRED`, a `redirectUrl` value is returned in the `CallbackResult` instead of automatically invoking the redirect. The server code which calls `callback` is now responsible for calling `res.redirect()` with the value of the returned url. This change allows your code to customize redirect behavior, making auth flows more adaptable to different environments and use cases.

```typescript
...
- const { callbackData, result } = await wristbandAuth.callback(req, res);
+ const { callbackData, redirectUrl, type } = await wristbandAuth.callback(req, res);
    
- if (result === CallbackResultType.REDIRECT_REQUIRED) {
+ if (type === CallbackResultType.REDIRECT_REQUIRED) {
  // caller now does the redirect with the returned URL
  - return;
  + return res.redirect(redirectUrl);
}
...
```

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
