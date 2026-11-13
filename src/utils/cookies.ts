import { Request } from 'express';

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
