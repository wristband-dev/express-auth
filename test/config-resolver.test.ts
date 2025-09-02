import { ConfigResolver } from '../src/config-resolver';
import { WristbandService } from '../src/wristband-service';
import { AuthConfig, SdkConfiguration } from '../src/types';
import { WristbandError } from '../src/error';

// Mock WristbandService
jest.mock('../src/wristband-service');
const MockWristbandService = WristbandService as jest.MockedClass<typeof WristbandService>;

const validAuthConfig: AuthConfig = {
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  loginStateSecret: 'this-is-a-very-long-login-state-secret-that-meets-requirements',
  wristbandApplicationVanityDomain: 'test.wristband.dev',
};

const validSdkConfig: SdkConfiguration = {
  loginUrl: 'https://test.example.com/auth/login',
  redirectUri: 'https://test.example.com/auth/callback',
  customApplicationLoginPageUrl: 'https://test.example.com/custom-login',
  isApplicationCustomDomainActive: true,
  loginUrlTenantDomainSuffix: null,
};

let mockWristbandService: jest.Mocked<WristbandService>;
let consoleLogSpy: jest.SpyInstance;

const initWristbandServiceMock = (sdkConfig: SdkConfiguration) => {
  mockWristbandService = {
    getSdkConfiguration: jest.fn().mockResolvedValue(sdkConfig),
  } as unknown as jest.Mocked<WristbandService>;
  MockWristbandService.mockImplementation(() => {
    return mockWristbandService;
  });
};

describe('ConfigResolver', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
  });
  afterEach(() => {
    consoleLogSpy.mockRestore();
  });

  describe('Constructor - Required Fields Validation', () => {
    it('should validate clientId is present', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, clientId: '' });
      }).toThrow('The [clientId] config must have a value.');
    });

    it('should validate clientId is not just whitespace', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, clientId: '   ' });
      }).toThrow('The [clientId] config must have a value.');
    });

    it('should validate clientSecret is present', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, clientSecret: '' });
      }).toThrow('The [clientSecret] config must have a value.');
    });

    it('should validate clientSecret is not just whitespace', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, clientSecret: '   ' });
      }).toThrow('The [clientSecret] config must have a value.');
    });

    it('should validate loginStateSecret length when provided', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, loginStateSecret: 'short' });
      }).toThrow('The [loginStateSecret] config must have a value of at least 32 characters.');
    });

    it('should allow undefined loginStateSecret (falls back to clientSecret)', () => {
      const config = { ...validAuthConfig };
      delete config.loginStateSecret;
      expect(() => {
        return new ConfigResolver(config);
      }).not.toThrow();
    });

    it('should validate wristbandApplicationVanityDomain is present', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, wristbandApplicationVanityDomain: '' });
      }).toThrow('The [wristbandApplicationVanityDomain] config must have a value.');
    });

    it('should validate wristbandApplicationVanityDomain is not just whitespace', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, wristbandApplicationVanityDomain: '   ' });
      }).toThrow('The [wristbandApplicationVanityDomain] config must have a value.');
    });

    it('should validate tokenExpirationBuffer is not negative when provided', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, tokenExpirationBuffer: -1 });
      }).toThrow('The [tokenExpirationBuffer] config must be greater than or equal to 0.');
    });
  });

  describe('Constructor - Auto-configure Disabled Validation', () => {
    const disabledConfig = { ...validAuthConfig, autoConfigureEnabled: false };

    it('should validate loginUrl is present when auto-configure disabled', () => {
      expect(() => {
        return new ConfigResolver(disabledConfig);
      }).toThrow('The [loginUrl] config must have a value when auto-configure is disabled.');
    });

    it('should validate redirectUri is present when auto-configure disabled', () => {
      const config = { ...disabledConfig, loginUrl: 'https://test.com/login' };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow('The [redirectUri] config must have a value when auto-configure is disabled.');
    });

    it('should validate tenant domain token when parseTenantFromRootDomain is provided', () => {
      const config = {
        ...disabledConfig,
        loginUrl: 'https://test.com/login',
        redirectUri: 'https://test.com/callback',
        parseTenantFromRootDomain: 'test.com',
      };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        'The [loginUrl] must contain the "{tenant_domain}" token when using the [parseTenantFromRootDomain] config.'
      );
    });

    it('should validate redirectUri has tenant domain token when parseTenantFromRootDomain is provided', () => {
      const config = {
        ...disabledConfig,
        loginUrl: `https://{tenant_domain}.test.com/login`,
        redirectUri: 'https://test.com/callback',
        parseTenantFromRootDomain: 'test.com',
      };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        'The [redirectUri] must contain the "{tenant_domain}" token when using the [parseTenantFromRootDomain] config.'
      );
    });

    it('should validate loginUrl does not have tenant domain token when parseTenantFromRootDomain absent', () => {
      const config = {
        ...disabledConfig,
        loginUrl: `https://{tenant_domain}.test.com/login`,
        redirectUri: 'https://test.com/callback',
      };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        'The [loginUrl] cannot contain the "{tenant_domain}" token when the [parseTenantFromRootDomain] is absent.'
      );
    });

    it('should validate redirectUri does not have tenant domain token when parseTenantFromRootDomain absent', () => {
      const config = {
        ...disabledConfig,
        loginUrl: 'https://test.com/login',
        redirectUri: `https://{tenant_domain}.test.com/callback`,
      };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        'The [redirectUri] cannot contain the "{tenant_domain}" token when the [parseTenantFromRootDomain] is absent.'
      );
    });

    it('should pass validation with correct configuration', () => {
      const config = {
        ...disabledConfig,
        loginUrl: `https://{tenant_domain}.test.com/login`,
        redirectUri: `https://{tenant_domain}.test.com/callback`,
        parseTenantFromRootDomain: 'test.com',
      };
      expect(() => {
        return new ConfigResolver(config);
      }).not.toThrow();
    });
  });

  describe('Constructor - Auto-configure Enabled Partial Validation', () => {
    it('should validate manually provided loginUrl with parseTenantFromRootDomain', () => {
      const config = { ...validAuthConfig, loginUrl: 'https://test.com/login', parseTenantFromRootDomain: 'test.com' };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        'The [loginUrl] must contain the "{tenant_domain}" token when using the [parseTenantFromRootDomain] config.'
      );
    });

    it('should validate manually provided redirectUri with parseTenantFromRootDomain', () => {
      const config = {
        ...validAuthConfig,
        redirectUri: 'https://test.com/callback',
        parseTenantFromRootDomain: 'test.com',
      };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        'The [redirectUri] must contain the "{tenant_domain}" token when using the [parseTenantFromRootDomain] config.'
      );
    });

    it('should validate manually provided loginUrl without parseTenantFromRootDomain', () => {
      const config = { ...validAuthConfig, loginUrl: `https://{tenant_domain}.test.com/login` };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        'The [loginUrl] cannot contain the "{tenant_domain}" token when the [parseTenantFromRootDomain] is absent.'
      );
    });

    it('should validate manually provided redirectUri without parseTenantFromRootDomain', () => {
      const config = { ...validAuthConfig, redirectUri: `https://{tenant_domain}.test.com/callback` };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        'The [redirectUri] cannot contain the "{tenant_domain}" token when the [parseTenantFromRootDomain] is absent.'
      );
    });

    it('should pass validation with correct manual overrides', () => {
      const config = {
        ...validAuthConfig,
        loginUrl: `https://{tenant_domain}.test.com/login`,
        parseTenantFromRootDomain: 'test.com',
      };
      expect(() => {
        return new ConfigResolver(config);
      }).not.toThrow();
    });
  });

  describe('Static Configuration Getters', () => {
    let resolver: ConfigResolver;

    beforeEach(() => {
      resolver = new ConfigResolver(validAuthConfig);
    });

    it('should return clientId', () => {
      expect(resolver.getClientId()).toBe('test-client-id');
    });

    it('should return clientSecret', () => {
      expect(resolver.getClientSecret()).toBe('test-client-secret');
    });

    it('should return loginStateSecret when provided', () => {
      expect(resolver.getLoginStateSecret()).toBe('this-is-a-very-long-login-state-secret-that-meets-requirements');
    });

    it('should return clientSecret as loginStateSecret when not provided', () => {
      const config = { ...validAuthConfig };
      delete config.loginStateSecret;
      resolver = new ConfigResolver(config);
      expect(resolver.getLoginStateSecret()).toBe('test-client-secret');
    });

    it('should return wristbandApplicationVanityDomain', () => {
      expect(resolver.getWristbandApplicationVanityDomain()).toBe('test.wristband.dev');
    });

    it('should return dangerouslyDisableSecureCookies default false', () => {
      expect(resolver.getDangerouslyDisableSecureCookies()).toBe(false);
    });

    it('should return dangerouslyDisableSecureCookies when set to true', () => {
      resolver = new ConfigResolver({ ...validAuthConfig, dangerouslyDisableSecureCookies: true });
      expect(resolver.getDangerouslyDisableSecureCookies()).toBe(true);
    });

    it('should return default scopes', () => {
      expect(resolver.getScopes()).toEqual(['openid', 'offline_access', 'email']);
    });

    it('should return custom scopes when provided', () => {
      resolver = new ConfigResolver({ ...validAuthConfig, scopes: ['custom', 'scope'] });
      expect(resolver.getScopes()).toEqual(['custom', 'scope']);
    });

    it('should return default scopes when empty array provided', () => {
      resolver = new ConfigResolver({ ...validAuthConfig, scopes: [] });
      expect(resolver.getScopes()).toEqual(['openid', 'offline_access', 'email']);
    });

    it('should return autoConfigureEnabled default true', () => {
      expect(resolver.getAutoConfigureEnabled()).toBe(true);
    });

    it('should return autoConfigureEnabled when explicitly set to true', () => {
      resolver = new ConfigResolver({ ...validAuthConfig, autoConfigureEnabled: true });
      expect(resolver.getAutoConfigureEnabled()).toBe(true);
    });

    it('should return autoConfigureEnabled when set to false', () => {
      const config = {
        ...validAuthConfig,
        autoConfigureEnabled: false,
        loginUrl: 'https://test.com/login',
        redirectUri: 'https://test.com/callback',
      };
      resolver = new ConfigResolver(config);
      expect(resolver.getAutoConfigureEnabled()).toBe(false);
    });

    it('should return default tokenExpirationBuffer', () => {
      expect(resolver.getTokenExpirationBuffer()).toBe(60);
    });

    it('should return custom tokenExpirationBuffer when provided', () => {
      resolver = new ConfigResolver({ ...validAuthConfig, tokenExpirationBuffer: 120 });
      expect(resolver.getTokenExpirationBuffer()).toBe(120);
    });
  });

  describe('Dynamic Configuration Getters - Auto-configure Disabled', () => {
    describe('With tenant domain configuration', () => {
      let resolver: ConfigResolver;

      beforeEach(() => {
        const config = {
          ...validAuthConfig,
          autoConfigureEnabled: false,
          loginUrl: 'https://{tenant_domain}.manual.com/login',
          redirectUri: 'https://{tenant_domain}.manual.com/callback',
          customApplicationLoginPageUrl: 'https://manual.com/custom-login',
          isApplicationCustomDomainActive: true,
          parseTenantFromRootDomain: 'manual.com',
        };
        resolver = new ConfigResolver(config);
      });

      it('should return manual customApplicationLoginPageUrl', async () => {
        expect(await resolver.getCustomApplicationLoginPageUrl()).toBe('https://manual.com/custom-login');
      });

      it('should return manual isApplicationCustomDomainActive', async () => {
        expect(await resolver.getIsApplicationCustomDomainActive()).toBe(true);
      });

      it('should return manual loginUrl', async () => {
        expect(await resolver.getLoginUrl()).toBe('https://{tenant_domain}.manual.com/login');
      });

      it('should return manual parseTenantFromRootDomain', async () => {
        expect(await resolver.getParseTenantFromRootDomain()).toBe('manual.com');
      });

      it('should return manual redirectUri', async () => {
        expect(await resolver.getRedirectUri()).toBe('https://{tenant_domain}.manual.com/callback');
      });
    });

    describe('Without tenant domain configuration', () => {
      let resolver: ConfigResolver;

      beforeEach(() => {
        const config = {
          ...validAuthConfig,
          autoConfigureEnabled: false,
          loginUrl: 'https://manual.com/login',
          redirectUri: 'https://manual.com/callback',
        };
        resolver = new ConfigResolver(config);
      });

      it('should return empty string for missing customApplicationLoginPageUrl', async () => {
        expect(await resolver.getCustomApplicationLoginPageUrl()).toBe('');
      });

      it('should return false for missing isApplicationCustomDomainActive', async () => {
        expect(await resolver.getIsApplicationCustomDomainActive()).toBe(false);
      });

      it('should return manual loginUrl', async () => {
        expect(await resolver.getLoginUrl()).toBe('https://manual.com/login');
      });

      it('should return empty string for missing parseTenantFromRootDomain', async () => {
        expect(await resolver.getParseTenantFromRootDomain()).toBe('');
      });

      it('should return manual redirectUri', async () => {
        expect(await resolver.getRedirectUri()).toBe('https://manual.com/callback');
      });
    });

    describe('With partial manual configuration', () => {
      it('should return manual customApplicationLoginPageUrl when provided', async () => {
        const config = {
          ...validAuthConfig,
          autoConfigureEnabled: false,
          loginUrl: 'https://manual.com/login',
          redirectUri: 'https://manual.com/callback',
          customApplicationLoginPageUrl: 'https://custom.manual.com/login',
        };
        const resolver = new ConfigResolver(config);
        expect(await resolver.getCustomApplicationLoginPageUrl()).toBe('https://custom.manual.com/login');
      });

      it('should return manual isApplicationCustomDomainActive when provided', async () => {
        const config = {
          ...validAuthConfig,
          autoConfigureEnabled: false,
          loginUrl: 'https://manual.com/login',
          redirectUri: 'https://manual.com/callback',
          isApplicationCustomDomainActive: false,
        };
        const resolver = new ConfigResolver(config);
        expect(await resolver.getIsApplicationCustomDomainActive()).toBe(false);
      });

      it('should return manual parseTenantFromRootDomain when provided', async () => {
        const config = {
          ...validAuthConfig,
          autoConfigureEnabled: false,
          loginUrl: 'https://{tenant_domain}.manual.com/login',
          redirectUri: 'https://{tenant_domain}.manual.com/callback',
          parseTenantFromRootDomain: 'manual.com',
        };
        const resolver = new ConfigResolver(config);
        expect(await resolver.getParseTenantFromRootDomain()).toBe('manual.com');
      });
    });
  });

  describe('Dynamic Configuration - Auto-configure Enabled', () => {
    let resolver: ConfigResolver;

    beforeEach(() => {
      initWristbandServiceMock(validSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);
    });

    it('should return auto-configured values', async () => {
      mockWristbandService.getSdkConfiguration.mockResolvedValue(validSdkConfig);

      const [customUrl, isCustomDomain, loginUrl, parseTenant, redirectUri] = await Promise.all([
        resolver.getCustomApplicationLoginPageUrl(),
        resolver.getIsApplicationCustomDomainActive(),
        resolver.getLoginUrl(),
        resolver.getParseTenantFromRootDomain(),
        resolver.getRedirectUri(),
      ]);

      expect(customUrl).toBe('https://test.example.com/custom-login');
      expect(isCustomDomain).toBe(true);
      expect(loginUrl).toBe('https://test.example.com/auth/login');
      expect(parseTenant).toBe('');
      expect(redirectUri).toBe('https://test.example.com/auth/callback');
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });

    it('should return manual values over auto-configured values', async () => {
      const config = {
        ...validAuthConfig,
        loginUrl: 'https://manual.com/login',
        customApplicationLoginPageUrl: 'https://manual.com/custom-login',
      };
      resolver = new ConfigResolver(config);
      mockWristbandService.getSdkConfiguration.mockResolvedValue(validSdkConfig);

      const [customUrl, loginUrl, redirectUri] = await Promise.all([
        resolver.getCustomApplicationLoginPageUrl(),
        resolver.getLoginUrl(),
        resolver.getRedirectUri(),
      ]);

      expect(customUrl).toBe('https://manual.com/custom-login');
      expect(loginUrl).toBe('https://manual.com/login');
      expect(redirectUri).toBe('https://test.example.com/auth/callback'); // From auto-config
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });

    it('should handle null values in auto-config response', async () => {
      const partialSdkConfig: SdkConfiguration = {
        loginUrl: 'https://test.example.com/auth/login',
        redirectUri: 'https://test.example.com/auth/callback',
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: null,
      };
      mockWristbandService.getSdkConfiguration.mockResolvedValue(partialSdkConfig);

      const [customUrl, isCustomDomain, parseTenant] = await Promise.all([
        resolver.getCustomApplicationLoginPageUrl(),
        resolver.getIsApplicationCustomDomainActive(),
        resolver.getParseTenantFromRootDomain(),
      ]);

      expect(customUrl).toBe('');
      expect(isCustomDomain).toBe(false);
      expect(parseTenant).toBe('');
    });

    it('should throw error when loginUrl missing from auto-config and not manually provided', async () => {
      const invalidSdkConfig = { redirectUri: 'https://test.example.com/auth/callback' } as SdkConfiguration;
      initWristbandServiceMock(invalidSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);

      try {
        await resolver.getLoginUrl();
        fail('Expected WristbandError to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(WristbandError);
        expect(error.message).toBe('SDK configuration response missing required field: loginUrl');
      }
    });

    it('should throw error when redirectUri missing from auto-config and not manually provided', async () => {
      const invalidSdkConfig = { loginUrl: 'https://test.example.com/auth/login' } as SdkConfiguration;
      initWristbandServiceMock(invalidSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);

      try {
        await resolver.getLoginUrl();
        fail('Expected WristbandError to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(WristbandError);
        expect(error.message).toBe('SDK configuration response missing required field: redirectUri');
      }
    });
  });

  describe('fetchSdkConfiguration - Retry Logic', () => {
    let resolver: ConfigResolver;

    beforeEach(() => {
      initWristbandServiceMock(validSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);
    });

    it('should succeed on first attempt', async () => {
      const result = await resolver.getLoginUrl();
      expect(result).toBe('https://test.example.com/auth/login');
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });

    it('should retry on failure and succeed on second attempt', async () => {
      mockWristbandService.getSdkConfiguration
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValue(validSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);

      const result = await resolver.getLoginUrl();
      expect(result).toBe('https://test.example.com/auth/login');
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(2);
    });

    it('should retry on failure and succeed on third attempt', async () => {
      mockWristbandService.getSdkConfiguration
        .mockRejectedValueOnce(new Error('Network error 1'))
        .mockRejectedValueOnce(new Error('Network error 2'))
        .mockResolvedValue(validSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);

      const result = await resolver.getLoginUrl();
      expect(result).toBe('https://test.example.com/auth/login');
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(3);
    });

    it('should fail after 3 attempts', async () => {
      const error1 = new Error('Network error 1');
      const error2 = new Error('Network error 2');
      const error3 = new Error('Network error 3');

      mockWristbandService.getSdkConfiguration
        .mockRejectedValueOnce(error1)
        .mockRejectedValueOnce(error2)
        .mockRejectedValueOnce(error3);
      resolver = new ConfigResolver(validAuthConfig);

      await expect(resolver.getLoginUrl()).rejects.toThrow(
        'Failed to fetch SDK configuration after 3 attempts: Network error 3'
      );
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(3);
    });

    it('should wait 100ms between retry attempts', async () => {
      const startTime = Date.now();
      mockWristbandService.getSdkConfiguration
        .mockRejectedValueOnce(new Error('Network error 1'))
        .mockRejectedValueOnce(new Error('Network error 2'))
        .mockResolvedValue(validSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);

      await resolver.getLoginUrl();
      const endTime = Date.now();

      // Account for time drift in CI/CD env
      expect(endTime - startTime).toBeGreaterThanOrEqual(101);
    });

    it('should handle unknown error type', async () => {
      mockWristbandService.getSdkConfiguration.mockRejectedValue('string error');
      resolver = new ConfigResolver(validAuthConfig);
      await expect(resolver.getLoginUrl()).rejects.toThrow(
        'Failed to fetch SDK configuration after 3 attempts: Unknown error'
      );
    });
  });

  describe('validateAllDynamicConfigs', () => {
    let resolver: ConfigResolver;

    beforeEach(() => {
      resolver = new ConfigResolver(validAuthConfig);
    });

    it('should validate required fields in SDK config', async () => {
      const invalidSdkConfig = { redirectUri: 'https://test.com/callback' } as SdkConfiguration;
      initWristbandServiceMock(invalidSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);
      expect(() => {
        return resolver['validateAllDynamicConfigs'](invalidSdkConfig);
      }).toThrow('SDK configuration response missing required field: loginUrl');
    });

    it('should validate redirectUri is present', async () => {
      const invalidSdkConfig = { loginUrl: 'https://test.com/login' } as SdkConfiguration;
      initWristbandServiceMock(invalidSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);
      expect(() => {
        return resolver['validateAllDynamicConfigs'](invalidSdkConfig);
      }).toThrow('SDK configuration response missing required field: redirectUri');
    });

    it('should validate resolved config with parseTenantFromRootDomain', async () => {
      const manualConfig = { ...validAuthConfig, parseTenantFromRootDomain: 'test.com' };
      resolver = new ConfigResolver(manualConfig);

      const invalidSdkConfig: SdkConfiguration = {
        loginUrl: 'https://test.com/login', // Missing token
        redirectUri: 'https://test.com/callback', // Missing token
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: null,
      };

      expect(() => {
        return resolver['validateAllDynamicConfigs'](invalidSdkConfig);
      }).toThrow(
        'The resolved [loginUrl] must contain the "{tenant_domain}" token when using [parseTenantFromRootDomain].'
      );
    });

    it('should validate resolved redirectUri with parseTenantFromRootDomain', async () => {
      const manualConfig = { ...validAuthConfig, parseTenantFromRootDomain: 'test.com' };
      resolver = new ConfigResolver(manualConfig);

      const invalidSdkConfig: SdkConfiguration = {
        loginUrl: `https://{tenant_domain}.test.com/login`,
        redirectUri: 'https://test.com/callback', // Missing token
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: null,
      };

      expect(() => {
        return resolver['validateAllDynamicConfigs'](invalidSdkConfig);
      }).toThrow(
        'The resolved [redirectUri] must contain the "{tenant_domain}" token when using [parseTenantFromRootDomain].'
      );
    });

    it('should validate resolved loginUrl config without parseTenantFromRootDomain', async () => {
      const invalidSdkConfig: SdkConfiguration = {
        loginUrl: `https://{tenant_domain}.test.com/login`, // Has token but shouldn't
        redirectUri: 'https://test.com/callback',
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: null,
      };

      expect(() => {
        return resolver['validateAllDynamicConfigs'](invalidSdkConfig);
      }).toThrow(
        'The resolved [loginUrl] cannot contain the "{tenant_domain}" token when [parseTenantFromRootDomain] is absent.'
      );
    });

    it('should validate resolved redirectUri without parseTenantFromRootDomain', async () => {
      const invalidSdkConfig: SdkConfiguration = {
        loginUrl: 'https://test.com/login',
        redirectUri: `https://{tenant_domain}.test.com/callback`, // Has token but shouldn't
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: null,
      };

      expect(() => {
        return resolver['validateAllDynamicConfigs'](invalidSdkConfig);
      }).toThrow(
        'The resolved [redirectUri] cannot contain the "{tenant_domain}" token when [parseTenantFromRootDomain] is absent.'
      );
    });

    it('should pass validation with correct resolved config for manual parseTenantFromRootDomain', async () => {
      const manualConfig = { ...validAuthConfig, parseTenantFromRootDomain: 'test.com' };
      resolver = new ConfigResolver(manualConfig);

      const sdkConfig: SdkConfiguration = {
        loginUrl: `https://{tenant_domain}.test.com/login`,
        redirectUri: `https://{tenant_domain}.test.com/callback`,
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: 'test.com',
      };

      expect(resolver['validateAllDynamicConfigs'](sdkConfig)).toBeUndefined();
    });

    it('should use manual config values over SDK config values for validation', async () => {
      const manualConfig = {
        ...validAuthConfig,
        loginUrl: `https://{tenant_domain}.manual.com/login`,
        parseTenantFromRootDomain: 'manual.com',
      };
      resolver = new ConfigResolver(manualConfig);

      const sdkConfig: SdkConfiguration = {
        loginUrl: 'https://sdk.com/login', // This would fail validation, but manual takes precedence
        redirectUri: `https://{tenant_domain}.sdk.com/callback`,
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: 'sdk.com',
      };

      expect(() => {
        return resolver['validateAllDynamicConfigs'](sdkConfig);
      }).not.toThrow();
    });
  });

  describe('Caching and Promise Deduplication', () => {
    let resolver: ConfigResolver;

    beforeEach(() => {
      resolver = new ConfigResolver(validAuthConfig);
    });

    it('should cache SDK config after first successful fetch', async () => {
      mockWristbandService.getSdkConfiguration.mockResolvedValue(validSdkConfig);

      await resolver.getLoginUrl();
      await resolver.getRedirectUri();
      await resolver.getCustomApplicationLoginPageUrl();

      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });

    it('should deduplicate concurrent requests', async () => {
      mockWristbandService.getSdkConfiguration.mockImplementation(() => {
        return new Promise((resolve) => {
          setTimeout(() => {
            return resolve(validSdkConfig);
          }, 100);
        });
      });

      const promises = [resolver.getLoginUrl(), resolver.getRedirectUri(), resolver.getCustomApplicationLoginPageUrl()];

      await Promise.all(promises);
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });

    it('should reset promise on error to allow retry', async () => {
      mockWristbandService.getSdkConfiguration
        .mockRejectedValueOnce(new Error('First error'))
        .mockRejectedValueOnce(new Error('Second error'))
        .mockRejectedValueOnce(new Error('Third error'))
        .mockResolvedValue(validSdkConfig);

      // First call should fail after 3 attempts
      await expect(resolver.getLoginUrl()).rejects.toThrow();
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(3);

      // Second call should succeed on first attempt (new set of 3 attempts)
      const result = await resolver.getRedirectUri();
      expect(result).toBe('https://test.example.com/auth/callback');
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(4);
    });

    it('should use preloadSdkConfig to eagerly load config', async () => {
      mockWristbandService.getSdkConfiguration.mockResolvedValue(validSdkConfig);

      await resolver.preloadSdkConfig();
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);

      // Subsequent calls should use cache
      await resolver.getLoginUrl();
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });
  });

  describe('Integration Edge Cases', () => {
    it('should handle boolean values correctly for isApplicationCustomDomainActive', async () => {
      // Test explicit false value
      let config = { ...validAuthConfig, isApplicationCustomDomainActive: false };
      let resolver = new ConfigResolver(config);
      expect(await resolver.getIsApplicationCustomDomainActive()).toBe(false);

      // Test explicit true value
      config = { ...validAuthConfig, isApplicationCustomDomainActive: true };
      resolver = new ConfigResolver(config);
      expect(await resolver.getIsApplicationCustomDomainActive()).toBe(true);

      // Test undefined value with auto-config false value
      resolver = new ConfigResolver(validAuthConfig);
      mockWristbandService.getSdkConfiguration.mockResolvedValue({
        ...validSdkConfig,
        isApplicationCustomDomainActive: false,
      });
      expect(await resolver.getIsApplicationCustomDomainActive()).toBe(false);

      // Test undefined value with auto-config true value
      resolver = new ConfigResolver(validAuthConfig);
      mockWristbandService.getSdkConfiguration.mockResolvedValue({
        ...validSdkConfig,
        isApplicationCustomDomainActive: true,
      });
      expect(await resolver.getIsApplicationCustomDomainActive()).toBe(true);
    });

    it('should handle empty string values correctly', async () => {
      const emptySdkConfig = { ...validSdkConfig, customApplicationLoginPageUrl: null };
      initWristbandServiceMock(emptySdkConfig);

      const config = { ...validAuthConfig, customApplicationLoginPageUrl: '', parseTenantFromRootDomain: '' };
      const resolver = new ConfigResolver(config);

      expect(await resolver.getCustomApplicationLoginPageUrl()).toBe('');
      expect(await resolver.getParseTenantFromRootDomain()).toBe('');
    });

    it('should handle mixed manual and auto-config with empty SDK values', async () => {
      const config = { ...validAuthConfig, loginUrl: 'https://manual.com/login' };
      const resolver = new ConfigResolver(config);

      const sdkConfig: SdkConfiguration = {
        loginUrl: 'https://sdk.com/login',
        redirectUri: 'https://sdk.com/callback',
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: null,
      };
      mockWristbandService.getSdkConfiguration.mockResolvedValue(sdkConfig);

      expect(await resolver.getLoginUrl()).toBe('https://manual.com/login'); // Manual
      expect(await resolver.getRedirectUri()).toBe('https://sdk.com/callback'); // Auto-config
      expect(await resolver.getCustomApplicationLoginPageUrl()).toBe(''); // Auto-config empty
      expect(await resolver.getParseTenantFromRootDomain()).toBe(''); // Auto-config empty
    });
  });
});
