/* eslint-disable import/no-extraneous-dependencies */

import httpMocks from 'node-mocks-http';
import { parseCookies } from '../../src/utils/cookies';

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
});
