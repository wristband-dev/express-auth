import { WristbandError, InvalidGrantError } from '../src/error';

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
});
