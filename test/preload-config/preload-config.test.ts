/* eslint-disable import/no-extraneous-dependencies */

import { AuthService } from '../../src/auth-service';
import { WristbandService } from '../../src/wristband-service';
import { ConfigResolver } from '../../src/config-resolver';
import { AuthConfig } from '../../src/types';
import { WristbandError } from '../../src/error';

// Mock the dependencies
jest.mock('../../src/wristband-service');
jest.mock('../../src/config-resolver');

const MockedWristbandService = WristbandService as jest.MockedClass<typeof WristbandService>;
const MockedConfigResolver = ConfigResolver as jest.MockedClass<typeof ConfigResolver>;

describe('AuthService - preloadConfig', () => {
  let authService: AuthService;
  let mockConfigResolver: jest.Mocked<ConfigResolver>;
  let mockWristbandService: jest.Mocked<WristbandService>;

  const authConfig: AuthConfig = {
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    wristbandApplicationVanityDomain: 'test.wristband.dev',
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockConfigResolver = {
      getAutoConfigureEnabled: jest.fn(),
      preloadSdkConfig: jest.fn(),
      getWristbandApplicationVanityDomain: jest.fn().mockReturnValue('test.wristband.dev'),
      getClientId: jest.fn().mockReturnValue('test-client-id'),
      getClientSecret: jest.fn().mockReturnValue('test-client-secret'),
    } as any;
    mockWristbandService = { getSdkConfiguration: jest.fn() } as any;
    MockedConfigResolver.mockImplementation(() => {
      return mockConfigResolver;
    });
    MockedWristbandService.mockImplementation(() => {
      return mockWristbandService;
    });
    authService = new AuthService(authConfig);
  });

  describe('preloadConfig', () => {
    test('Successfully preloads config when auto-configure is enabled', async () => {
      mockConfigResolver.getAutoConfigureEnabled.mockReturnValue(true);
      mockConfigResolver.preloadSdkConfig.mockResolvedValue();
      await authService.preloadConfig();
      expect(mockConfigResolver.getAutoConfigureEnabled).toHaveBeenCalledTimes(1);
      expect(mockConfigResolver.preloadSdkConfig).toHaveBeenCalledTimes(1);
    });

    test('Throws WristbandError when auto-configure is disabled', async () => {
      mockConfigResolver.getAutoConfigureEnabled.mockReturnValue(false);
      await expect(authService.preloadConfig()).rejects.toThrow(WristbandError);
      await expect(authService.preloadConfig()).rejects.toThrow(
        'Cannot preload configs when autoConfigureEnabled is false. Use createWristbandAuth() instead.'
      );
      expect(mockConfigResolver.preloadSdkConfig).not.toHaveBeenCalled();
    });

    test('Propagates error from ConfigResolver.preloadSdkConfig', async () => {
      const sdkError = new Error('SDK configuration fetch failed');
      mockConfigResolver.getAutoConfigureEnabled.mockReturnValue(true);
      mockConfigResolver.preloadSdkConfig.mockRejectedValue(sdkError);
      await expect(authService.preloadConfig()).rejects.toThrow('SDK configuration fetch failed');
      expect(mockConfigResolver.preloadSdkConfig).toHaveBeenCalledTimes(1);
    });

    test('Propagates WristbandError from ConfigResolver.preloadSdkConfig', async () => {
      const wristbandError = new WristbandError('Invalid SDK configuration');
      mockConfigResolver.getAutoConfigureEnabled.mockReturnValue(true);
      mockConfigResolver.preloadSdkConfig.mockRejectedValue(wristbandError);
      await expect(authService.preloadConfig()).rejects.toThrow(WristbandError);
      await expect(authService.preloadConfig()).rejects.toThrow('Invalid SDK configuration');
      expect(mockConfigResolver.preloadSdkConfig).toHaveBeenCalledTimes(2);
    });

    test('Handles network timeout errors from preloadSdkConfig', async () => {
      const timeoutError = new Error('Network timeout');
      timeoutError.name = 'TimeoutError';
      mockConfigResolver.getAutoConfigureEnabled.mockReturnValue(true);
      mockConfigResolver.preloadSdkConfig.mockRejectedValue(timeoutError);
      await expect(authService.preloadConfig()).rejects.toThrow('Network timeout');
      expect(mockConfigResolver.preloadSdkConfig).toHaveBeenCalledTimes(1);
    });
  });

  describe('Error Handling Edge Cases', () => {
    test('Handles undefined return from getAutoConfigureEnabled', async () => {
      mockConfigResolver.getAutoConfigureEnabled.mockReturnValue(undefined as any);
      await expect(authService.preloadConfig()).rejects.toThrow(WristbandError);
      expect(mockConfigResolver.preloadSdkConfig).not.toHaveBeenCalled();
    });

    test('Handles null return from getAutoConfigureEnabled', async () => {
      mockConfigResolver.getAutoConfigureEnabled.mockReturnValue(null as any);
      await expect(authService.preloadConfig()).rejects.toThrow(WristbandError);
      expect(mockConfigResolver.preloadSdkConfig).not.toHaveBeenCalled();
    });
  });
});
