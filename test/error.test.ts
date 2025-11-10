import { WristbandError, InvalidGrantError } from '../src/error';

describe('Error Classes', () => {
  describe('WristbandError', () => {
    test('Creates error with error code and description', () => {
      const error = new WristbandError('test_error', 'Test error description');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.name).toBe('WristbandError');
      expect(error.message).toBe('test_error');
      expect(error.getError()).toBe('test_error');
      expect(error.getErrorDescription()).toBe('Test error description');
    });

    test('Creates error with only error code', () => {
      const error = new WristbandError('another_error');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.name).toBe('WristbandError');
      expect(error.message).toBe('another_error');
      expect(error.getError()).toBe('another_error');
      expect(error.getErrorDescription()).toBeUndefined();
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
      expect(error.getError()).toBe('invalid_grant');
      expect(error.getErrorDescription()).toBe('The grant is invalid');
    });

    test('Creates error without description', () => {
      const error = new InvalidGrantError();

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(error.getError()).toBe('invalid_grant');
      expect(error.getErrorDescription()).toBe('');
    });

    test('Creates error with empty string description', () => {
      const error = new InvalidGrantError('');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(error.getError()).toBe('invalid_grant');
      expect(error.getErrorDescription()).toBe('');
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

      expect(error1.getError()).toBe('invalid_grant');
      expect(error2.getError()).toBe('invalid_grant');
      expect(error3.getError()).toBe('invalid_grant');
    });
  });
});
