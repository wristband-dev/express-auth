/* eslint-disable import/no-extraneous-dependencies */

import { AuthService } from '../../src/auth-service';
import { WristbandService } from '../../src/wristband-service';
import { ConfigResolver } from '../../src/config-resolver';
import { AuthConfig } from '../../src/types';

// Mock the dependencies
jest.mock('../../src/wristband-service');
jest.mock('../../src/config-resolver');

const MockedWristbandService = WristbandService as jest.MockedClass<typeof WristbandService>;
const MockedConfigResolver = ConfigResolver as jest.MockedClass<typeof ConfigResolver>;

describe('AuthService - validateTenantCustomDomain', () => {
  let authService: AuthService;
  let mockConfigResolver: jest.Mocked<ConfigResolver>;
  let mockWristbandService: jest.Mocked<WristbandService>;

  const authConfig: AuthConfig = {
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    wristbandApplicationVanityDomain: 'test.wristband.dev',
  };
  const tenantCustomDomain = 'auth.yourapp.io';

  beforeEach(() => {
    jest.clearAllMocks();
    mockConfigResolver = {
      getWristbandApplicationVanityDomain: jest.fn().mockReturnValue('test.wristband.dev'),
      getClientId: jest.fn().mockReturnValue('test-client-id'),
      getClientSecret: jest.fn().mockReturnValue('test-client-secret'),
    } as any;
    mockWristbandService = { validateTenantCustomDomain: jest.fn() } as any;
    MockedConfigResolver.mockImplementation(() => {
      return mockConfigResolver;
    });
    MockedWristbandService.mockImplementation(() => {
      return mockWristbandService;
    });
    authService = new AuthService(authConfig);
  });

  test('Returns true when the tenant custom domain is valid', async () => {
    mockWristbandService.validateTenantCustomDomain.mockResolvedValue(true);

    const result = await authService.validateTenantCustomDomain(tenantCustomDomain);

    expect(result).toBe(true);
    expect(mockWristbandService.validateTenantCustomDomain).toHaveBeenCalledWith(tenantCustomDomain);
  });

  test('Returns false when the tenant custom domain is invalid', async () => {
    mockWristbandService.validateTenantCustomDomain.mockResolvedValue(false);

    const result = await authService.validateTenantCustomDomain(tenantCustomDomain);

    expect(result).toBe(false);
  });

  test('Propagates error from WristbandService.validateTenantCustomDomain', async () => {
    const error = new Error('Tenant custom domain is required');
    mockWristbandService.validateTenantCustomDomain.mockRejectedValue(error);

    await expect(authService.validateTenantCustomDomain('')).rejects.toThrow('Tenant custom domain is required');
  });
});
