<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instruction from version v5.x to version v6.x
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

# Migration instruction from version v5.x to version v6.x

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 6.x

<br>

## Table of Contents

- [Authentication Middleware API Changes](#authentication-middleware-api-changes)
- [Tenant Domain Query Parameter Rename](#tenant-domain-query-parameter-rename)
- [AuthMiddlewareConfig Type Changes](#authmiddlewareconfig-type-changes)
- [CallbackResultType Changes](#callbackresulttype-changes)

<br>

## Authentication Middleware API Changes

The `createRequireSessionAuth()` method has been replaced with `createAuthMiddleware()`, which now requires explicit configuration of authentication strategies.

**Before (v5.x):**
```typescript
// src/wristband.ts
import { createWristbandAuth } from '@wristband/express-auth';
import { createWristbandSession } from '@wristband/express-auth/session';

export const wristbandAuth = createWristbandAuth({
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  wristbandApplicationVanityDomain: "auth.yourapp.io",
});

export function wristbandSession() {
  return createWristbandSession({
    secrets: 'your-secret-key-min-32-chars',
    maxAge: 3600,
    secure: process.env.NODE_ENV === 'production',
  });
}

// Old method name
- export const requireWristbandAuth = wristbandAuth.createRequireSessionAuth({
-   enableCsrfProtection: true,
-   csrfTokenHeaderName: 'x-csrf-token'
- });
```

**After (v6.x):**
```typescript
// src/wristband.ts
import { createWristbandAuth, SessionOptions } from '@wristband/express-auth';
import { createWristbandSession } from '@wristband/express-auth/session';

export const wristbandAuth = createWristbandAuth({
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  wristbandApplicationVanityDomain: "auth.yourapp.io",
});

+ const sessionOptions: SessionOptions = {
+   secrets: 'dummyval-b5c1-463a-812c-0d8db87c0ec5',
+   enableCsrfProtection: true,
+ };

+ export function wristbandSession() {
+   return createWristbandSession(sessionOptions);
+ }

// New method name with explicit strategy configuration
+ export const requireWristbandAuth = wristbandAuth.createAuthMiddleware({
+   authStrategies: ['SESSION'],
+   sessionConfig: {
+     sessionOptions,
+     csrfTokenHeaderName: 'x-csrf-token'
+   }
+ });
```

**Key Changes:**
1. Method renamed: `createRequireSessionAuth()` → `createAuthMiddleware()`
2. Must explicitly specify `authStrategies: ['SESSION']`
3. `sessionOptions` must now be provided in `sessionConfig`
4. CSRF configuration read from `sessionConfig.sessionOptions`

<br>

## Tenant Domain Query Parameter Rename

The `tenant_domain` query parameter has been renamed to `tenant_name` as part of a broader standardization across the Wristband platform.

**Query Parameter Changes:**

**Before (v5.x):**
```typescript
// Frontend redirect to login
- window.location.href = '/api/auth/login?tenant_domain=customer01';

// Logout with tenant domain
- window.location.href = '/api/auth/logout?tenant_domain=customer01';
```

**After (v6.x):**
```typescript
// Frontend redirect to login
+ window.location.href = '/api/auth/login?tenant_name=customer01';

// Logout with tenant name
+ window.location.href = '/api/auth/logout?tenant_name=customer01';
```

> **⚠️ Important:**
>
> The old `tenant_domain` query parameter will continue to work for backward compatibility, but it is now deprecated and will be removed in a future major version. All new code should use `tenant_name`.

<br>

## AuthMiddlewareConfig Type Changes

The configuration structure for authentication middleware has changed significantly to support multiple authentication strategies.

**Before (v5.x):**
```typescript
// Direct configuration at the root level
- type SessionAuthConfig = {
-   enableCsrfProtection?: boolean;
-   csrfTokenHeaderName?: string;
- };
```

**After (v6.x):**
```typescript
// Nested configuration with explicit strategies
+ interface AuthMiddlewareConfig {
+   // Required array of strategies to try in order
+   authStrategies: AuthStrategy[];
+   
+   // Nested session configuration
+   sessionConfig?: {
+     sessionOptions: SessionOptions;
+     enableCsrfProtection?: boolean;
+     csrfTokenHeaderName?: string;
+   };
+   
+   // JWT configuration (optional, new in v6)
+   jwtConfig?: {
+     jwksCacheMaxSize?: number;
+     jwksCacheTtl?: number;
+   };
+ }
```

**Migration Example:**

**Before (v5.x):**
```typescript
- const requireAuth = wristbandAuth.createRequireSessionAuth({
-   enableCsrfProtection: true,
-   csrfTokenHeaderName: 'x-csrf-token'
- });
```

**After (v6.x):**
```typescript
+ const requireAuth = wristbandAuth.createAuthMiddleware({
+   authStrategies: ['SESSION'],
+   sessionConfig: {
+     sessionOptions: {
+       secrets: process.env.SESSION_SECRET!,
+       maxAge: 3600,
+       secure: true
+     },
+     enableCsrfProtection: true,
+     csrfTokenHeaderName: 'x-csrf-token'
+   }
+ });
```

<br>

## CallbackResultType Changes

The `CallbackResultType` enum values have changed to use snake_case string literals instead of SCREAMING_SNAKE_CASE.

**Before (v5.x):**
```typescript
- import { CallbackResultType } from '@wristband/express-auth';

const callbackResult = await wristbandAuth.callback(req, res);
- const { type } = callbackResult;

- if (type === CallbackResultType.REDIRECT_REQUIRED) {
-   return res.redirect(callbackResult.redirectUrl);
- }

- if (type === CallbackResultType.COMPLETED) {
-   // Handle successful authentication
- }
```

**After (v6.x):**
```typescript
+ // No need to import CallbackResultType anymore

const callbackResult = await wristbandAuth.callback(req, res);
+ const { type } = callbackResult;

+ if (type === 'redirect_required') {
+   return res.redirect(callbackResult.redirectUrl);
+ }

+ if (type === 'completed') {
+   // Handle successful authentication
+ }
```

The type is now a string literal union:

```typescript
type CallbackResultType = 'completed' | 'redirect_required';
```

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
