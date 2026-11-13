import { Request } from 'express';
import type { NodeRequest } from '@wristband/typescript-auth';

/**
 * Removes the port from a host value, using the same logic Express uses for req.hostname
 * (including support for bracketed IPv6 literals like "[::1]:3000").
 */
export function stripPort(host: string): string {
  const offset = host[0] === '[' ? host.indexOf(']') + 1 : 0;
  const index = host.indexOf(':', offset);
  return index !== -1 ? host.substring(0, index) : host;
}

/**
 * Resolves the host (including any port) the browser used for the incoming request.
 *
 * Express's req.hostname already respects the app's "trust proxy" setting: it reads
 * X-Forwarded-Host only when the sender is trusted, and the Host header otherwise. However,
 * req.hostname drops the port, and in Express 4 req.host is deprecated and drops it too.
 * This function returns whichever header Express chose for req.hostname, with its port intact.
 */
export function getRequestHost(req: Request): string {
  const { hostname } = req;

  // Should never happen (defensive measure)
  if (!hostname) {
    return '';
  }

  // Check the Host header first so an untrusted X-Forwarded-Host can never supply the port
  // when both headers share the same hostname.
  const host = req.get('host');
  if (host && stripPort(host) === hostname) {
    return host;
  }

  // Express only takes the first value when X-Forwarded-Host contains a comma-separated list.
  const forwardedHost = req.get('x-forwarded-host')?.split(',')[0].trim();
  if (forwardedHost && stripPort(forwardedHost) === hostname) {
    return forwardedHost;
  }

  return hostname;
}

/**
 * Adapts an Express request for @wristband/typescript-auth.
 *
 * The core reads the host from the Host header and the protocol from X-Forwarded-Proto. Express has already chosen
 * both according to the app's "trust proxy" setting (req.hostname, req.protocol), so the core gets a view of the
 * request where those headers carry Express's choice, and X-Forwarded-Host is dropped so it is never read directly.
 */
export function toCoreRequest(req: Request): NodeRequest {
  const headers: Record<string, string | string[] | undefined> = {
    ...req.headers,
    host: getRequestHost(req),
    'x-forwarded-proto': req.protocol,
  };
  delete headers['x-forwarded-host'];
  return {
    headers,
    query: req.query,
    socket: req.socket,
    url: req.originalUrl || req.url,
  } as NodeRequest;
}
