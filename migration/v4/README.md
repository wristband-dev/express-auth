<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instruction from version v3.0.0 to version v4.0.0
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

# Migration instruction from version v3.0.0 to version v4.0.0

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 4.x

<br>

## Table of Contents

- [SDK Configuration Property Name Change](#sdk-configuration-property-name-changes)
  - [Configuring Usage of Custom Domains](#configuring-usage-of-custom-domains)
  - [Configuring Usage of Tenant Subdomains](#configuring-usage-of-tenant-subdomains)

<br>

## SDK Configuration Property Name Changes

When calling `createWristbandAuth` to initialize the SDK, there are a few properties that have been altered. Your application will need to ensure that these changes are reflected when using version 4.x of this SDK.

<br>

### Configuring Usage of Custom Domains

The configuration field `useCustomDomains` has been renamed to `isApplicationCustomDomainActive` to make it more explicit as to which custom domains are being utilized and what the impact is. The config description has been updated to the following:

> Indicates whether your Wristband application is configured with an application-level custom domain that is active. This tells the SDK which URL format to use when constructing the Wristband Authorize Endpoint URL. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `defaultTenantCustomDomain` config.  Defaults to `false`.

```typescript
import { createWristbandAuth } from '@wristband/express-auth';

const wristbandAuth = createWristbandAuth({
  //
  // ...your other configs...
  //
  - useCustomDomains: true,
  + isApplicationCustomDomainActive: true,
});

export default wristbandAuth;
```

<br>

### Configuring Usage of Tenant Subdomains

In previous versions, if your application was relying on tenant subdomains, you had to configure two separate properties of the SDK: `useTenantSubdomains` and `rootDomain`. To reduce confusion and simplify configuration, the following changes have been made:

- `rootDomain` has been renamed to `parseTenantFromRootDomain`
- `useTenantSubdomains` has been removed as an SDK configuration option

The config description for `parseTenantFromRootDomain` has been updated to the following:

> The root domain for your application. This value only needs to be specified if you intend to use tenant subdomains in your Login and Callback Endpoint URLs.  The root domain should be set to the portion of the domain that comes after the tenant subdomain.  For example, if your application uses tenant subdomains such as `tenantA.yourapp.com` and `tenantB.yourapp.com`, then the root domain should be set to `yourapp.com`. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `defaultTenantCustomDomain` config. When this configuration is enabled, the SDK extracts the tenant subdomain from the host and uses it to construct the Wristband Authorize URL.

It is also expected that if a value is provided for `parseTenantFromRootDomain`, then both the `loginUrl` and `redirectUri` configs must contain the `{tenant_domain}` token in the URL.

```typescript
import { createWristbandAuth } from '@wristband/express-auth';

const wristbandAuth = createWristbandAuth({
  //
  // ...your other configs...
  //
  // Only specify the {tenant_domain} token if your app uses tenant subdomains in the URLs.
  loginUrl: 'https://{tenant_domain}.yourapp.io/auth/login',
  redirectUri: 'https://{tenant_domain}.yourapp.io/auth/callback',
  - useTenantSubdomains: true,
  - rootDomain: 'yourapp.io',
  // Only specify this config if your app uses tenant subdomains in the URLs.
  + parseTenantFromRootDomain: 'yourapp.io',
});

export default wristbandAuth;
```

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
