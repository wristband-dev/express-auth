<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instruction from version v6.x to version v7.x
  </p>
  <p align="center">
    <b>
      <a href="https://wristband.dev">Website</a> • 
      <a href="https://docs.wristband.dev/">Documentation</a> • 
      <a href="https://docs.wristband.dev/llms.txt">LLMs.txt</a>
    </b>
  </p>
</div>

<br/>

---

<br/>

# Migration instruction from version v6.x to version v7.x

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 7.x

<br>

## Table of Contents

- [Minimum Node.js and npm Versions](#minimum-nodejs-and-npm-versions)
- [Tenant Domain URL Placeholder Removed](#tenant-domain-url-placeholder-removed)
- [parseTenantFromRootDomain Config Removed](#parsetenantfromrootdomain-config-removed)
- [customState and customClaims Type Changes](#customstate-and-customclaims-type-changes)
- [Return URL Validation in callback()](#return-url-validation-in-callback)
- [Login State Cookie Encryption Changes](#login-state-cookie-encryption-changes)
- [Automatic No-Cache Headers](#automatic-no-cache-headers)
- [Session Cookie Encoding Changes](#session-cookie-encoding-changes)

<br>

## Minimum Node.js and npm Versions

The minimum supported Node.js version is now 22.0.0, and the minimum npm version is now 10.5.1. Node.js 20 reached end of life on April 30, 2026.

The SDK's `package.json` now declares:

**Before (v6.x):**
```json
"engines": {
- "node": ">=20.0.0",
- "npm": ">=9.6.0"
}
```

**After (v7.x):**
```json
"engines": {
+ "node": ">=22.0.0",
+ "npm": ">=10.5.1"
}
```

**Key Changes:**
1. Upgrade your app's runtime to Node.js 22 or later (Node.js 22.0.0 ships with npm 10.5.1, so upgrading Node covers npm too)
2. Update anything still pinned to Node.js 20, such as CI workflows, Dockerfiles, `.nvmrc` files, or hosting platform settings

<br>

## Tenant Domain URL Placeholder Removed

The `{tenant_domain}` placeholder, deprecated in v6.x, has been removed. `{tenant_name}` is now the only supported tenant placeholder in `loginUrl` and `redirectUri`.

**Before (v6.x):**
```typescript
const wristbandAuth = createWristbandAuth({
  // ... other config
- loginUrl: "https://{tenant_domain}.yourapp.com/auth/login",
- redirectUri: "https://{tenant_domain}.yourapp.com/auth/callback",
});
```

**After (v7.x):**
```typescript
const wristbandAuth = createWristbandAuth({
  // ... other config
+ loginUrl: "https://{tenant_name}.yourapp.com/auth/login",
+ redirectUri: "https://{tenant_name}.yourapp.com/auth/callback",
});
```

<br>

## parseTenantFromRootDomain Config Removed

The `parseTenantFromRootDomain` config has been removed from `AuthConfig`. Tenant subdomain parsing is now enabled whenever `loginUrl` contains the `{tenant_name}` placeholder, and the SDK determines the root domain from `loginUrl` by removing the `{tenant_name}` subdomain.

**Before (v6.x):**
```typescript
const wristbandAuth = createWristbandAuth({
  // ... other config
  loginUrl: "https://{tenant_name}.yourapp.com/auth/login",
  redirectUri: "https://{tenant_name}.yourapp.com/auth/callback",
- parseTenantFromRootDomain: "yourapp.com",
});
```

**After (v7.x):**
```typescript
const wristbandAuth = createWristbandAuth({
  // ... other config
  loginUrl: "https://{tenant_name}.yourapp.com/auth/login",
  redirectUri: "https://{tenant_name}.yourapp.com/auth/callback",
});
```

**Key Changes:**
1. Remove `parseTenantFromRootDomain` from your SDK config
2. The root domain is derived from `loginUrl` (e.g. `https://{tenant_name}.yourapp.com/auth/login` gives a root domain of `yourapp.com`)
3. If your app relies on auto-configuration and never set `parseTenantFromRootDomain`, no change is needed

> **⚠️ Important:**
>
> The `{tenant_name}` placeholder must appear exactly once in `loginUrl` and `redirectUri`, as the leftmost part of the hostname. Either both URLs contain the placeholder or neither does.

<br>

## customState and customClaims Type Changes

`customState` (in `LoginConfig` and `CallbackData`) and `customClaims` (in `UserInfo`) are now typed as `Record<string, unknown>` instead of allowing `any` values. Runtime behavior is unchanged, and JavaScript apps are not affected.

**Reading Values:**

**Before (v6.x):**
```typescript
const callbackResult = await wristbandAuth.callback(req, res);

if (callbackResult.type === 'completed') {
  const { customState, userinfo } = callbackResult.callbackData;
- const userId: string = customState?.userId;
- const plan: string = userinfo.customClaims?.plan;
}
```

**After (v7.x):**
```typescript
const callbackResult = await wristbandAuth.callback(req, res);

if (callbackResult.type === 'completed') {
  const { customState, userinfo } = callbackResult.callbackData;
+ const userId = customState?.userId as string;
+ const plan = userinfo.customClaims?.plan as string;
}
```

**Passing customState to login():**

**Before (v6.x):**
```typescript
- interface MyCustomState {
-   userId: string;
- }

const customState: MyCustomState = { userId: '123' };
const loginUrl = await wristbandAuth.login(req, res, { customState });
```

**After (v7.x):**
```typescript
+ type MyCustomState = {
+   userId: string;
+ };

const customState: MyCustomState = { userId: '123' };
const loginUrl = await wristbandAuth.login(req, res, { customState });
```

**Key Changes:**
1. Values read from `customState` or `customClaims` must be narrowed or cast before use
2. A `customState` value declared with an `interface` is no longer assignable and causes a type error. Declare it with a `type` alias instead, or pass a spread copy (e.g. `customState: { ...myState }`).

<br>

## Return URL Validation in callback()

`callback()` now validates the return URL before including it in the returned callback data. In v6.x, the return URL was passed through unchanged. A return URL that fails validation is now left out of the callback data, and the flow continues without it.

**Before (v6.x):**
```typescript
// Login request: /auth/login?return_url=https://otherapp.com/dashboard
const callbackResult = await wristbandAuth.callback(req, res);

if (callbackResult.type === 'completed') {
  const { returnUrl } = callbackResult.callbackData;
- // returnUrl === 'https://otherapp.com/dashboard'
- return res.redirect(returnUrl);
}
```

**After (v7.x):**
```typescript
// Login request: /auth/login?return_url=https://otherapp.com/dashboard
const callbackResult = await wristbandAuth.callback(req, res);

if (callbackResult.type === 'completed') {
  const { returnUrl } = callbackResult.callbackData;
+ // returnUrl === undefined (the host does not match the request's host or the root domain)
+ return res.redirect(returnUrl || '/home');
}
```

**Key Changes:**
1. Relative paths (e.g. `/settings`) resolve against the current request's host
2. The protocol must match the request's protocol, which blocks downgrades like `https` to `http`
3. The hostname must be either the root domain (when `loginUrl` contains the `{tenant_name}` placeholder) or the request's host
4. When application-level authorization requests are enabled and `loginUrl` contains the `{tenant_name}` placeholder, a return URL on the bare root domain is rewritten to the tenant's subdomain (e.g. `yourapp.com` to `acme.yourapp.com`)

> **⚠️ Important:**
>
> Make sure your Callback Endpoint has a default redirect location for when `returnUrl` is not present, since a return URL that worked in v6.x may now be left out.

<br>

## Login State Cookie Encryption Changes

The Login State Cookie is now encrypted with Wristband's own in-house crypto implementation, replacing the `iron-webcrypto` and `uncrypto` dependencies. No code or config changes are needed: the cookie is still encrypted with `loginStateSecret`, or with `clientSecret` when `loginStateSecret` is not set.

**Key Changes:**
1. Login State Cookies created by v6.x cannot be decrypted by v7.x. A user who is mid-login during the upgrade is redirected to the Login Endpoint once, and because Wristband already has an authenticated session for that user, the new login flow completes without asking them to sign in again.
2. When the Login State Cookie cannot be decrypted (tampered, expired, encrypted with a different secret, or created by v6.x), `callback()` no longer throws. The cookie is cleared, and `callback()` returns `redirect_required` with the `invalid_login_state` reason.

> **⚠️ Important:**
>
> If your Callback Endpoint already handles the `redirect_required` result type, no change is needed. Otherwise, make sure it redirects to `callbackResult.redirectUrl` when `type` is `'redirect_required'`.

<br>

## Automatic No-Cache Headers

Any response that writes or deletes a session cookie now automatically includes `Cache-Control: no-store` and `Pragma: no-cache`. This prevents browsers and shared caches (such as CDNs and proxies) from storing a response that carries a user's session cookie and serving it to someone else. In v6.x, apps were solely responsible for setting these headers. For security, the SDK now sets them itself, so a forgotten header can no longer leave a session cookie cacheable.

**Before (v6.x):**
```typescript
// Session Endpoint (protected by the Wristband auth middleware)
app.get('/auth/session', (req, res) => {
- res.header('Cache-Control', 'no-store');
- res.header('Pragma', 'no-cache');
  res.json(req.session.getSessionResponse());
});
```

**After (v7.x):**
```typescript
// Session Endpoint (protected by the Wristband auth middleware)
app.get('/auth/session', (req, res) => {
+ // Cache-Control and Pragma are set automatically when the middleware saves the session
  res.json(req.session.getSessionResponse());
});
```

**Key Changes:**
1. The auth middleware saves the session on every request it authenticates with the `SESSION` strategy (rolling sessions), so those responses always include the headers
2. `session.save()` and `session.destroy()` set the headers on any route that calls them
3. Requests authenticated with the `JWT` strategy do not write cookies, so those responses do not get the headers automatically
4. Manually set `Cache-Control` and `Pragma` headers can be removed only from routes that save or destroy the session on every request, such as routes protected by the `SESSION` strategy. Keep them on any route that only sometimes saves or destroys the session, or that never does, since those responses do not get the headers automatically.

> **⚠️ Important:**
>
> Existing `Cache-Control` and `Pragma` values on the response are replaced, not merged. If your app sets a custom `Cache-Control` value on a response that also saves or destroys the session, that value is now replaced with `no-store`.

<br>

## Session Cookie Encoding Changes

Encrypted session cookie values are now base64url-encoded, matching the Login State Cookie. No code or config changes are needed.

**Key Changes:**
1. Session cookies created by v6.x are still decrypted by v7.x, so existing users stay logged in after the upgrade

> **⚠️ Important:**
>
> v6.x cannot read session cookies created by v7.x. Rolling back to v6.x after the upgrade logs out users with a new cookie once.

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
