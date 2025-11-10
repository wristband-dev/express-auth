import { AuthConfig } from './types';
import { WristbandAuth, WristbandAuthImpl } from './wristband-auth';

/**
 * Wristband SDK function to create an instance of WristbandAuth with lazy auto-configuration.
 *
 * Auto-configuration is enabled by default and will fetch missing configuration values from the
 * Wristband SDK Configuration Endpoint when any auth method is first called. Manual configuration
 * values take precedence over auto-configured values. Set `autoConfigureEnabled: false` to disable.
 *
 * @param {AuthConfig} authConfig - Configuration for Wristband authentication. Required fields:
 *   clientId, clientSecret, wristbandApplicationVanityDomain.
 * @returns {WristbandAuth} An instance of WristbandAuth with lazy configuration resolution, if enabled.
 *
 * @example
 * // Minimal config with auto-configure (default behavior)
 * const auth = createWristbandAuth({
 *   clientId: "your-client-id",
 *   clientSecret: "your-secret",
 *   wristbandApplicationVanityDomain: "auth.yourapp.io"
 * });
 *
 * @example
 * // Manual override with auto-configure for remaining fields
 * const auth = createWristbandAuth({
 *   clientId: "your-client-id",
 *   clientSecret: "your-secret",
 *   wristbandApplicationVanityDomain: "auth.yourapp.io",
 *   loginUrl: "https://yourapp.io/auth/login", // Manual override
 *   // redirectUri will be auto-configured
 * });
 *
 *  @example
 * // Auto-configure disabled
 * const auth = createWristbandAuth({
 *   autoConfigureEnabled: false,
 *   clientId: "your-client-id",
 *   clientSecret: "your-secret",
 *   wristbandApplicationVanityDomain: "auth.custom.com",
 *   // Must manually configure non-auto-configurable fields
 *   loginUrl: "https://custom.com/auth/login",
 *   redirectUri: "https://custom.com/auth/callback",
 *   isApplicationCustomDomainActive: true,
 * });
 */
export function createWristbandAuth(authConfig: AuthConfig): WristbandAuth {
  return new WristbandAuthImpl(authConfig);
}

/**
 * Wristband SDK function to create an instance of WristbandAuth with eager auto-configuration.
 *
 * Unlike `createWristbandAuth`, this function immediately fetches and resolves all auto-configuration
 * values from the Wristband SDK Configuration Endpoint during initialization. This is useful when you
 * want to fail fast if auto-configuration is unavailable, or when you need configuration values
 * resolved before making any auth method calls. Manual configuration values take precedence over
 * auto-configured values.
 *
 * @param {AuthConfig} authConfig - Configuration for Wristband authentication. Required fields:
 *   clientId, clientSecret, wristbandApplicationVanityDomain.
 * @returns {Promise<WristbandAuth>} A Promise that resolves to an instance of WristbandAuth with
 *   all configuration values already resolved and validated.
 *
 * @throws {WristbandError} When auto-configuration endpoint is unreachable or returns invalid data.
 * @throws {TypeError} When required configuration values cannot be resolved.
 *
 * @example
 * // Eager auto-configure with error handling
 * try {
 *   const wristbandAuth = await discoverWristbandAuth({
 *     clientId: "your-client-id",
 *     clientSecret: "your-secret",
 *     wristbandApplicationVanityDomain: "auth.yourapp.io"
 *   });
 *   // Configuration is already resolved and validated
 * } catch (error) {
 *   console.error('Auto-configuration failed:', error.message);
 * }
 */
export async function discoverWristbandAuth(authConfig: AuthConfig): Promise<WristbandAuth> {
  return WristbandAuthImpl.createWithDiscovery(authConfig);
}
