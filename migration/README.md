<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instruction for version below v3.0.0
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

# Migration instruction for version v3.0.0 comparing to older versions: 
(-) indiate the older version need to be changed to the (+) new changes

### During the initialization of the SDK, wristbandApplicationDomain param got renamed to wristbandApplicationVanityDomain 

```typescript
// ESModules
import { createWristbandAuth } from '@wristband/express-auth';
// CommonJS
// const { createWristbandAuth } = require('@wristband/express-auth');

const wristbandAuth = createWristbandAuth({
  clientId: "ic6saso5hzdvbnof3bwgccejxy",
  clientSecret: "30e9977124b13037d035be10d727806f",
  loginStateSecret: '7ffdbecc-ab7d-4134-9307-2dfcc52f7475',
  loginUrl: "https://{tenant_domain}.yourapp.io/auth/login",
  redirectUri: "https://{tenant_domain}.yourapp.io/auth/callback",
  rootDomain: "yourapp.io",
  useCustomDomains: true,
  useTenantSubdomains: true,
  - wristbandApplicationDomain: "auth.yourapp.io",  
  + wristbandApplicationVanityDomain: "auth.yourapp.io",   
});

// ESModules
export default wristbandAuth;
// CommonJS
// module.exports = wristbandAuth; 
```


#### Login and Logout now returns a URL instead redirecting to that url directly. The client code calling login & logout will be responsible to redirect with the returned url.

```typescript
import { wristbandAuth } from './wristband-auth.js';

// Login Endpoint - Route path can be whatever you prefer
app.get('/auth/login', async (req, res) => {
  try {
    - await wristbandAuth.login(req, res, { /* Optional login configs */ });      // used to redirect inside login
    + res.redirect(await wristbandAuth.login(req, res, { /* Optional login configs */ }));  // caller now does the redirect with the returned url
  } catch (error) {
    // Handle error
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});


```

```typescript
import { wristbandAuth } from './wristband-auth.js';

// Logout Endpoint - Route path can be whatever you prefer
app.get('/auth/logout', async (req, res) => {
  const { refreshToken, tenantDomainName } = session;

  // Always destroy your application's session.
  res.clearCookie('my-session-cookie-name');
  req.session.destroy();

  try {
    - await wristbandAuth.logout(req, res, { tenantDomainName, refreshToken });      // used to redirect inside logout
    + res.redirect(await wristbandAuth.logout(req, res, { tenantDomainName, refreshToken })); // caller now does the redirect with the returned url
  } catch (error) {
    // Handle error
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});
```

#### [Callback Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#callback-endpoint) : CallbackResult.result got renamed to CallbackResult.type (Enum: CallbackResultType)

```typescript

const callbackResult = await wristbandAuth.callback(req, res);
    - const { callbackData, result } = callbackResult;
    + const { callbackData, type } = callbackResult;
    
    // The SDK will have already invoked the redirect() function, so we just stop execution here.
    - if (result === CallbackResultType.REDIRECT_REQUIRED) {
    + if (type === CallbackResultType.REDIRECT_REQUIRED) {
      return;
    }
```

---