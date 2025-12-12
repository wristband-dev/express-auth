/* eslint-disable import/no-extraneous-dependencies */

import httpMocks from 'node-mocks-http';
import { Response } from 'express';
import { parseCookies, setCookie, clearCookie } from '../../src/utils/cookies';

describe('Cookie Utils', () => {
  describe('parseCookies', () => {
    test('Parses single cookie correctly', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: 'sessionId=abc123',
        },
      }) as any;

      const result = parseCookies(req);

      expect(result).toEqual({
        sessionId: 'abc123',
      });
    });

    test('Parses multiple cookies correctly', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: 'sessionId=abc123; token=xyz789; userId=456',
        },
      }) as any;

      const result = parseCookies(req);

      expect(result).toEqual({
        sessionId: 'abc123',
        token: 'xyz789',
        userId: '456',
      });
    });

    test('Handles cookie values with equals signs', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: 'data=key=value=test; simple=basic',
        },
      }) as any;

      const result = parseCookies(req);

      expect(result).toEqual({
        data: 'key=value=test',
        simple: 'basic',
      });
    });

    test('Handles URL encoded values', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: 'encoded=hello%20world%21; special=%3D%26%25',
        },
      }) as any;

      const result = parseCookies(req);

      expect(result).toEqual({
        encoded: 'hello world!',
        special: '=&%',
      });
    });

    test('Handles whitespace around separators', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: ' sessionId = abc123 ; token = xyz789 ; userId = 456 ',
        },
      }) as any;

      const result = parseCookies(req);

      expect(result).toEqual({
        sessionId: 'abc123',
        token: 'xyz789',
        userId: '456',
      });
    });

    test('Returns empty object when no cookie header', () => {
      const req = httpMocks.createRequest({
        headers: {},
      }) as any;

      const result = parseCookies(req);

      expect(result).toEqual({});
    });

    test('Returns empty object when cookie header is empty string', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: '',
        },
      }) as any;

      const result = parseCookies(req);

      expect(result).toEqual({});
    });

    test('Handles empty cookie values', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: 'empty=; hasValue=test; alsoEmpty=',
        },
      }) as any;

      const result = parseCookies(req);

      expect(result).toEqual({
        empty: '',
        hasValue: 'test',
        alsoEmpty: '',
      });
    });

    test('Handles cookie names with special characters', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: 'login#state#123=value1; user_id=value2; session-token=value3',
        },
      }) as any;

      const result = parseCookies(req);

      expect(result).toEqual({
        'login#state#123': 'value1',
        user_id: 'value2',
        'session-token': 'value3',
      });
    });

    test('Handles malformed cookies gracefully', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: 'valid=test; ; =empty; novalue; another=valid',
        },
      }) as any;

      const result = parseCookies(req);

      expect(result).toEqual({
        valid: 'test',
        '': 'empty',
        novalue: '',
        another: 'valid',
      });
    });
  });

  describe('setCookie', () => {
    let res: Response;

    beforeEach(() => {
      res = httpMocks.createResponse();
    });

    test('Sets basic cookie with default options', () => {
      setCookie(res, 'sessionId', 'abc123');

      const setCookieHeader = res.getHeader('Set-Cookie');
      expect(setCookieHeader).toBe('sessionId=abc123; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax; Secure');
    });

    test('Sets cookie with custom maxAge', () => {
      setCookie(res, 'token', 'xyz789', { maxAge: 7200 });

      const setCookieHeader = res.getHeader('Set-Cookie');
      expect(setCookieHeader).toBe('token=xyz789; HttpOnly; Path=/; Max-Age=7200; SameSite=Lax; Secure');
    });

    test('Sets cookie without Secure flag when dangerouslyDisableSecureCookies is true', () => {
      setCookie(res, 'sessionId', 'abc123', { dangerouslyDisableSecureCookies: true });

      const setCookieHeader = res.getHeader('Set-Cookie');
      expect(setCookieHeader).toBe('sessionId=abc123; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax');
    });

    test('Encodes cookie value with special characters', () => {
      setCookie(res, 'data', 'hello world!@#$%^&*()');

      const setCookieHeader = res.getHeader('Set-Cookie');
      expect(setCookieHeader).toBe(
        'data=hello%20world!%40%23%24%25%5E%26*(); HttpOnly; Path=/; Max-Age=3600; SameSite=Lax; Secure'
      );
    });

    test('Handles empty cookie value', () => {
      setCookie(res, 'empty', '');

      const setCookieHeader = res.getHeader('Set-Cookie');
      expect(setCookieHeader).toBe('empty=; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax; Secure');
    });

    test('Sets multiple cookies (no existing cookies)', () => {
      setCookie(res, 'first', 'value1');
      setCookie(res, 'second', 'value2');

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect(setCookieHeaders).toHaveLength(2);
      expect(setCookieHeaders[0]).toBe('first=value1; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax; Secure');
      expect(setCookieHeaders[1]).toBe('second=value2; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax; Secure');
    });

    test('Appends to existing cookie array', () => {
      // Simulate existing cookies as array
      res.setHeader('Set-Cookie', ['existing=cookie1', 'another=cookie2']);

      setCookie(res, 'new', 'value');

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect(setCookieHeaders).toHaveLength(3);
      expect(setCookieHeaders[0]).toBe('existing=cookie1');
      expect(setCookieHeaders[1]).toBe('another=cookie2');
      expect(setCookieHeaders[2]).toBe('new=value; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax; Secure');
    });

    test('Converts existing single cookie to array', () => {
      // Simulate existing single cookie
      res.setHeader('Set-Cookie', 'existing=cookie1');

      setCookie(res, 'new', 'value');

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect(setCookieHeaders).toHaveLength(2);
      expect(setCookieHeaders[0]).toBe('existing=cookie1');
      expect(setCookieHeaders[1]).toBe('new=value; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax; Secure');
    });

    test('Sets cookie with maxAge 0', () => {
      setCookie(res, 'expiring', 'value', { maxAge: 0 });

      const setCookieHeader = res.getHeader('Set-Cookie');
      expect(setCookieHeader).toBe('expiring=value; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure');
    });

    test('Sets cookie with both custom options', () => {
      setCookie(res, 'test', 'value', { maxAge: 1800, dangerouslyDisableSecureCookies: true });

      const setCookieHeader = res.getHeader('Set-Cookie');
      expect(setCookieHeader).toBe('test=value; HttpOnly; Path=/; Max-Age=1800; SameSite=Lax');
    });
  });

  describe('clearCookie', () => {
    let res: Response;

    beforeEach(() => {
      res = httpMocks.createResponse();
    });

    test('Clears cookie with default secure flag', () => {
      clearCookie(res, 'sessionId');

      const setCookieHeader = res.getHeader('Set-Cookie');
      expect(setCookieHeader).toBe('sessionId=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure');
    });

    test('Clears cookie without secure flag when dangerouslyDisableSecureCookies is true', () => {
      clearCookie(res, 'sessionId', true);

      const setCookieHeader = res.getHeader('Set-Cookie');
      expect(setCookieHeader).toBe('sessionId=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax');
    });

    test('Clears multiple cookies', () => {
      clearCookie(res, 'first');
      clearCookie(res, 'second');

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect(setCookieHeaders).toHaveLength(2);
      expect(setCookieHeaders[0]).toBe('first=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure');
      expect(setCookieHeaders[1]).toBe('second=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure');
    });

    test('Appends clear cookie to existing cookies', () => {
      // Simulate existing cookies
      res.setHeader('Set-Cookie', ['keep=value1', 'also-keep=value2']);

      clearCookie(res, 'remove');

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect(setCookieHeaders).toHaveLength(3);
      expect(setCookieHeaders[0]).toBe('keep=value1');
      expect(setCookieHeaders[1]).toBe('also-keep=value2');
      expect(setCookieHeaders[2]).toBe('remove=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure');
    });

    test('Clears cookie with special characters in name', () => {
      clearCookie(res, 'login#state#123');

      const setCookieHeader = res.getHeader('Set-Cookie');
      expect(setCookieHeader).toBe('login#state#123=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure');
    });
  });

  describe('appendCookieToHeader (implicit testing through setCookie/clearCookie)', () => {
    let res: Response;

    beforeEach(() => {
      res = httpMocks.createResponse();
    });

    test('Handles non-array existing header correctly', () => {
      // Set a non-array header value (number)
      res.setHeader('Set-Cookie', 12345 as any);

      setCookie(res, 'new', 'value');

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect(setCookieHeaders).toHaveLength(2);
      expect(setCookieHeaders[0]).toBe('12345');
      expect(setCookieHeaders[1]).toBe('new=value; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax; Secure');
    });

    test('Handles object existing header correctly', () => {
      // Set an object header value
      res.setHeader('Set-Cookie', {
        toString: () => {
          return 'object-cookie=test';
        },
      } as any);

      setCookie(res, 'new', 'value');

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect(setCookieHeaders).toHaveLength(2);
      expect(setCookieHeaders[0]).toBe('object-cookie=test');
      expect(setCookieHeaders[1]).toBe('new=value; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax; Secure');
    });
  });

  describe('Integration Tests', () => {
    test('Parse cookies from request and set new cookies in response', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: 'existing=value1; another=value2',
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      // Parse existing cookies
      const cookies = parseCookies(req);
      expect(cookies.existing).toBe('value1');
      expect(cookies.another).toBe('value2');

      // Set new cookie
      setCookie(res, 'newCookie', 'newValue');

      const setCookieHeader = res.getHeader('Set-Cookie');
      expect(setCookieHeader).toBe('newCookie=newValue; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax; Secure');
    });

    test('Clear existing cookie that was parsed from request', () => {
      const req = httpMocks.createRequest({
        headers: {
          cookie: 'sessionId=abc123; token=xyz789',
        },
      }) as any;
      const res = httpMocks.createResponse() as any;

      // Parse cookies to verify they exist
      const cookies = parseCookies(req);
      expect(cookies.sessionId).toBe('abc123');
      expect(cookies.token).toBe('xyz789');

      // Clear one of them
      clearCookie(res, 'sessionId');

      const setCookieHeader = res.getHeader('Set-Cookie');
      expect(setCookieHeader).toBe('sessionId=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure');
    });

    test('Set and clear cookies in same response', () => {
      const res = httpMocks.createResponse() as any;

      setCookie(res, 'keep', 'keepValue');
      clearCookie(res, 'remove');
      setCookie(res, 'another', 'anotherValue', { dangerouslyDisableSecureCookies: true });

      const setCookieHeaders = res.getHeader('Set-Cookie') as string[];
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect(setCookieHeaders).toHaveLength(3);
      expect(setCookieHeaders[0]).toBe('keep=keepValue; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax; Secure');
      expect(setCookieHeaders[1]).toBe('remove=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure');
      expect(setCookieHeaders[2]).toBe('another=anotherValue; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax');
    });
  });
});
