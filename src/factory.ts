import { AuthConfig } from '@wristband/typescript-auth';
import { WristbandAuth, WristbandAuthImpl } from './wristband-auth';

/**
 * Wristband SDK function to create an instance of WristbandAuth with lazy auto-configuration.
 */
export function createWristbandAuth(authConfig: AuthConfig): WristbandAuth {
  return new WristbandAuthImpl(authConfig);
}

/**
 * Wristband SDK function to create an instance of WristbandAuth with eager auto-configuration.
 */
export async function discoverWristbandAuth(authConfig: AuthConfig): Promise<WristbandAuth> {
  return WristbandAuthImpl.createWithDiscovery(authConfig);
}
