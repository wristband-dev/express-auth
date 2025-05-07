import { Request, Response } from 'express';

/**
 * Helper function to append a cookie string to the Set-Cookie header.
 * Handles various cases of existing cookie headers.
 *
 * @param res - Express Response object.
 * @param cookieString - The formatted cookie string to add.
 */
function appendCookieToHeader(res: Response, cookieString: string): void {
  // Get existing Set-Cookie headers
  const existingCookies = res.getHeader('Set-Cookie');

  if (!existingCookies) {
    // No cookies set yet, just set this one
    res.setHeader('Set-Cookie', cookieString);
  } else if (Array.isArray(existingCookies)) {
    // Add to the existing array
    res.setHeader('Set-Cookie', [...existingCookies, cookieString]);
  } else {
    // Convert existing cookie to array and add this one
    res.setHeader('Set-Cookie', [existingCookies.toString(), cookieString]);
  }
}

/**
 * Parses cookies from an Express request without relying on cookie-parser middleware
 *
 * Extracts and parses the Cookie header from the request, handling edge cases such as:
 * - Missing Cookie header
 * - Cookie values containing equals signs
 * - URL encoded values
 * - Whitespace around separators
 *
 * @param req - Express Request object
 * @returns An object containing all cookies as key-value pairs
 * @example
 * // Returns { token: "abc123", session: "xyz789" }
 * const cookies = parseCookies(req);
 * const sessionId = cookies.session;
 */
export const parseCookies = (req: Request): Record<string, string> => {
  const cookieHeader = req.headers.cookie;
  const cookies: Record<string, string> = {};

  if (!cookieHeader) {
    return cookies;
  }

  cookieHeader.split(';').forEach((cookie) => {
    const parts = cookie.split('=');
    const name = parts[0].trim();
    const value = parts.slice(1).join('=').trim();
    cookies[name] = decodeURIComponent(value);
  });

  return cookies;
};

/**
 * Sets a cookie using direct header manipulation instead of cookie-parser middleware
 *
 * @param res - Express Response object
 * @param name - Name of the cookie
 * @param value - Value to store in the cookie (will be encoded)
 * @param options - Cookie options
 * @param options.maxAge - Cookie lifetime in milliseconds
 * @param options.dangerouslyDisableSecureCookies - Whether to omit the Secure flag
 */
export function setCookie(
  res: Response,
  name: string,
  value: string,
  options: {
    maxAge?: number;
    dangerouslyDisableSecureCookies?: boolean;
  } = {}
): void {
  // Fallback to default options if not provided
  const { maxAge = 3600, dangerouslyDisableSecureCookies = false } = options;
  const cookieString = `${name}=${encodeURIComponent(value)}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax${
    dangerouslyDisableSecureCookies ? '' : '; Secure'
  }`;

  appendCookieToHeader(res, cookieString);
}

/**
 * Clears a cookie by setting its Max-Age to 0 and maintaining security properties
 *
 * @param res - Express Response object
 * @param cookieName - Name of the cookie to clear
 * @param dangerouslyDisableSecureCookies - Whether to omit the Secure flag (defaults to false)
 */
export function clearCookie(res: Response, cookieName: string, dangerouslyDisableSecureCookies = false): void {
  const cookieString = `${cookieName}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${
    dangerouslyDisableSecureCookies ? '' : '; Secure'
  }`;

  appendCookieToHeader(res, cookieString);
}
