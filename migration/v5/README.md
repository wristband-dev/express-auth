<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instruction from version v4.0.0 to version v5.0.0
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

# Migration instruction from version v4.0.0 to version v5.0.0

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 5.x

<br>

## Table of Contents

- [UserInfo Type Changes](#userinfo-type-changes)
- [LoginConfig Property Rename](#loginconfig-property-rename)
- [CallbackData Property Changes](#callbackdata-property-changes)
- [LogoutConfig Property Rename](#logoutconfig-property-rename)
- [Optional: Built-in Session Management](#optional-built-in-session-management)

<br>

## UserInfo Type Changes

The SDK now provides a new `UserInfo` type that transforms raw OIDC claims from Wristband's Userinfo Endpoint into a structured format that provides better type safety and aligns with JavaScript/TypeScript naming conventions. The `CallbackData.userinfo` field now uses this new `UserInfo` type.

Key changes include:

- Standard OIDC claims are now mapped to camelCase properties (e.g., `sub` → `userId`, `tnt_id` → `tenantId`, `idp_name` → `identityProviderName`)
- All other user profile fields follow camelCase naming (e.g., `given_name` → `givenName`, `picture` → `pictureUrl`)
- The `roles` field now uses the new `UserInfoRole` type with properly typed properties

**Before (v4.x):**
```typescript
const callbackResult = await wristbandAuth.callback(req, res);
const { userinfo } = callbackResult.callbackData;

// Access raw OIDC claims
const userId = userinfo.sub;
const tenantId = userinfo.tnt_id;
const identityProvider = userinfo.idp_name;
const givenName = userinfo.given_name;
...
```

**After (v5.x):**
```typescript
const callbackResult = await wristbandAuth.callback(req, res);
const { userinfo } = callbackResult.callbackData;

// Access structured, camelCase properties
const userId = userinfo.userId;        // Previously: userinfo.sub
const tenantId = userinfo.tenantId;    // Previously: userinfo.tnt_id
const identityProvider = userinfo.identityProviderName;  // Previously: userinfo.idp_name
const givenName = userinfo.givenName;  // Previously: userinfo.given_name
...
```

For a complete mapping of all field names and types, refer to the `UserInfo` type documentation in the main [README](../../README.md#callbackreq-request-res-response-promisecallbackresult).

<br>

## LoginConfig Property Rename

The `LoginConfig` property `defaultTenantDomainName` has been renamed to `defaultTenantName` for better clarity.

```typescript
const loginUrl = await wristbandAuth.login(req, res, {
  - defaultTenantDomainName: 'default',
  + defaultTenantName: 'default',
});
res.redirect(loginUrl);
```

<br>

## CallbackData Property Changes

The `CallbackData` type has two property changes for better consistency and clarity:

- `tenantDomainName` has been renamed to `tenantName`
- `userinfo` now uses the new `UserInfo` type (see [UserInfo Type Changes](#userinfo-type-changes))

```typescript
const callbackResult = await wristbandAuth.callback(req, res);
const { callbackData } = callbackResult;

// Access tenant name
- const tenantName = callbackData.tenantDomainName;
+ const tenantName = callbackData.tenantName;

// Access userinfo with new camelCase properties
- const userId = callbackData.userinfo.sub;
+ const userId = callbackData.userinfo.userId;
```

<br>

## LogoutConfig Property Rename

The `LogoutConfig` property `tenantDomainName` has been renamed to `tenantName` for clarity.

```typescript
const logoutUrl = await wristbandAuth.logout(req, res, {
  refreshToken: '98yht308hf902hc90wh09',
  - tenantDomainName: 'customer01',
  + tenantName: 'customer01',
});
res.redirect(logoutUrl);
```

<br>

## Optional: Built-in Session Management

Version 5.x introduces optional built-in session management powered by [@wristband/typescript-session](https://github.com/wristband-dev/typescript-session). This is entirely optional and does not affect existing applications using other session libraries.

If you want to reduce dependencies on third-party session libraries, you can now use Wristband's built-in session management:

```typescript
// src/wristband.ts
import { createWristbandAuth } from '@wristband/express-auth';
import { createWristbandSession } from '@wristband/express-auth/session'; // Optional

export const wristbandAuth = createWristbandAuth({
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  wristbandApplicationVanityDomain: "auth.yourapp.io",
});

// Optional: Use built-in session management
export const wristbandSession = createWristbandSession({
  secrets: 'your-secret-key-min-32-chars',
  maxAge: 3600,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'Lax'
});

export const requireWristbandAuth = wristbandAuth.createRequireSessionAuth();
```

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
