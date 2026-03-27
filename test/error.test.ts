import { WristbandError, InvalidGrantError, FetchError } from '../src/error';

describe('Error Classes', () => {
  describe('WristbandError', () => {
    test('Creates error with error code and description', () => {
      const error = new WristbandError('test_error', 'Test error description');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.name).toBe('WristbandError');
      expect(error.message).toBe('Test error description');
      expect(error.code).toBe('test_error');
      expect(error.errorDescription).toBe('Test error description');
    });

    test('Creates error with only error code', () => {
      const error = new WristbandError('another_error');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.name).toBe('WristbandError');
      expect(error.message).toBe('another_error');
      expect(error.code).toBe('another_error');
      expect(error.errorDescription).toBeUndefined();
    });

    test('Creates error with original error cause', () => {
      const originalError = new Error('Network timeout');
      const error = new WristbandError('network_error', 'Failed to connect', originalError);

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.name).toBe('WristbandError');
      expect(error.message).toBe('Failed to connect');
      expect(error.code).toBe('network_error');
      expect(error.errorDescription).toBe('Failed to connect');
      expect(error.originalError).toBe(originalError);
      expect(error.originalError?.message).toBe('Network timeout');
    });

    test('Creates error with empty string description', () => {
      const error = new WristbandError('empty_desc_error', '');

      expect(error).toBeInstanceOf(WristbandError);
      expect(error.message).toBe('empty_desc_error'); // Falls back to code when description is empty
      expect(error.code).toBe('empty_desc_error');
      expect(error.errorDescription).toBe('');
      expect(error.originalError).toBeUndefined();
    });

    test('Creates error with only code and originalError', () => {
      const originalError = new TypeError('Invalid type');
      const error = new WristbandError('type_error', undefined, originalError);

      expect(error).toBeInstanceOf(WristbandError);
      expect(error.message).toBe('type_error');
      expect(error.code).toBe('type_error');
      expect(error.errorDescription).toBeUndefined();
      expect(error.originalError).toBe(originalError);
    });

    test('Error can be thrown and caught', () => {
      expect(() => {
        throw new WristbandError('thrown_error', 'This error was thrown');
      }).toThrow(WristbandError);
    });

    test('Error has correct prototype chain', () => {
      const error = new WristbandError('proto_test');

      expect(error instanceof WristbandError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });
  });

  describe('InvalidGrantError', () => {
    test('Creates error with description', () => {
      const error = new InvalidGrantError('The grant is invalid');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(error.code).toBe('invalid_grant');
      expect(error.errorDescription).toBe('The grant is invalid');
      expect(error.message).toBe('The grant is invalid');
    });

    test('Creates error without description', () => {
      const error = new InvalidGrantError();

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(error.code).toBe('invalid_grant');
      expect(error.errorDescription).toBe('');
      expect(error.message).toBe('invalid_grant'); // Falls back to code
    });

    test('Creates error with empty string description', () => {
      const error = new InvalidGrantError('');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(error.code).toBe('invalid_grant');
      expect(error.errorDescription).toBe('');
      expect(error.message).toBe('invalid_grant');
    });

    test('Error can be thrown and caught', () => {
      expect(() => {
        throw new InvalidGrantError('Invalid authorization code');
      }).toThrow(InvalidGrantError);
    });

    test('Error has correct prototype chain', () => {
      const error = new InvalidGrantError('test');

      expect(error instanceof InvalidGrantError).toBe(true);
      expect(error instanceof WristbandError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    test('Error always has invalid_grant as error code', () => {
      const error1 = new InvalidGrantError('First error');
      const error2 = new InvalidGrantError('Second error');
      const error3 = new InvalidGrantError();

      expect(error1.code).toBe('invalid_grant');
      expect(error2.code).toBe('invalid_grant');
      expect(error3.code).toBe('invalid_grant');
    });

    test('InvalidGrantError does not support originalError', () => {
      const error = new InvalidGrantError('Test');
      expect(error.originalError).toBeUndefined();
    });

    test('Error has correct name property', () => {
      const error = new InvalidGrantError('Test');
      expect(error.name).toBe('WristbandError'); // Inherits from WristbandError
    });
  });

  describe('FetchError', () => {
    test('Creates error with response and body', () => {
      const mockResponse = new Response(null, { status: 400 });
      const body = { error: 'invalid_grant', error_description: 'Invalid grant' };
      const error = new FetchError(mockResponse, body);

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(FetchError);
      expect(error.name).toBe('FetchError');
      expect(error.message).toBe('Fetch Error');
      expect(error.response).toBe(mockResponse);
      expect(error.body).toBe(body);
    });

    test('Creates error with undefined body', () => {
      const mockResponse = new Response(null, { status: 204 });
      const error = new FetchError(mockResponse, undefined);

      expect(error).toBeInstanceOf(FetchError);
      expect(error.response).toBe(mockResponse);
      expect(error.body).toBeUndefined();
    });

    test('Creates error with null body', () => {
      const mockResponse = new Response(null, { status: 500 });
      const error = new FetchError(mockResponse, null);

      expect(error).toBeInstanceOf(FetchError);
      expect(error.response).toBe(mockResponse);
      expect(error.body).toBeNull();
    });

    test('Creates error with string body', () => {
      const mockResponse = new Response(null, { status: 503 });
      const error = new FetchError(mockResponse, 'Service Unavailable');

      expect(error).toBeInstanceOf(FetchError);
      expect(error.body).toBe('Service Unavailable');
    });

    test('Response and body properties are readonly', () => {
      const mockResponse = new Response(null, { status: 400 });
      const error = new FetchError(mockResponse, { error: 'bad_request' });

      // TypeScript readonly enforced at compile time; verify values are stable at runtime
      expect(error.response).toBe(mockResponse);
      expect(error.body).toEqual({ error: 'bad_request' });
    });

    test('Works with generic response type', () => {
      interface MockResponse {
        status: number;
        ok: boolean;
      }
      const mockResponse: MockResponse = { status: 401, ok: false };
      const error = new FetchError<MockResponse>(mockResponse, { error: 'unauthorized' });

      expect(error.response?.status).toBe(401);
      expect(error.response?.ok).toBe(false);
    });

    test('Error can be thrown and caught', () => {
      const mockResponse = new Response(null, { status: 400 });
      expect(() => {
        throw new FetchError(mockResponse, { error: 'bad_request' });
      }).toThrow(FetchError);
    });

    test('Error has correct prototype chain', () => {
      const mockResponse = new Response(null, { status: 400 });
      const error = new FetchError(mockResponse, null);

      expect(error instanceof FetchError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    test('instanceof check works for downstream error handling', () => {
      const mockResponse = new Response(null, { status: 400 });
      const fetchError = new FetchError(mockResponse, { error: 'invalid_grant' });
      const regularError = new Error('regular error');

      expect(fetchError instanceof FetchError).toBe(true);
      expect(regularError instanceof FetchError).toBe(false);
    });

    test('Body with invalid_grant error is accessible', () => {
      const mockResponse = new Response(null, { status: 400 });
      const body = { error: 'invalid_grant', error_description: 'The authorization code has expired' };
      const error = new FetchError(mockResponse, body);

      expect(error.body.error).toBe('invalid_grant');
      expect(error.body.error_description).toBe('The authorization code has expired');
    });

    test('Response status is accessible via response property', () => {
      const mockResponse = new Response(null, { status: 401 });
      const error = new FetchError(mockResponse, { error: 'unauthorized' });

      expect(error.response?.status).toBe(401);
    });
  });
});
