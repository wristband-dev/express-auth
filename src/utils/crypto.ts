import { Base64 } from './base64';
import { LoginState } from '../types';
import { CryptoError } from '../error/crypto-error';

// Ensure we're using Web Crypto API across all environments
// eslint-disable-next-line n/no-unsupported-features/node-builtins
const webCrypto = globalThis.crypto;
if (!webCrypto?.subtle) {
  throw new CryptoError(
    'NODE_CRYPTO_UNAVAILABLE',
    'Web Crypto API is not available. This environment requires global crypto.subtle support.'
  );
}

/**
 * Cryptographic utilities for secure cookie encryption and decryption.
 *
 * Provides asynchronous (Web Crypto API) methods
 * for encrypting data into tamper-proof, time-limited cookies. Uses AES-256-GCM
 * authenticated encryption with HKDF key derivation for maximum security.
 *
 * @remarks
 * **Security Features:**
 * - AES-256-GCM authenticated encryption (confidentiality + integrity in one operation)
 * - HKDF-SHA256 key derivation with domain separation
 * - Random 96-bit IV per encryption (never reused)
 * - 128-bit authentication tag for tamper detection
 * - Timestamp-based TTL validation with clock skew tolerance
 * - Support for zero-downtime secret rotation
 *
 * **Cross-Platform Compatibility:**
 * - Node.js 22+, Deno, Bun, Cloudflare Workers, browsers
 * - Binary format is identical across all platforms for seamless interoperability
 *
 * **Binary Cookie Format:**
 * ```
 * [version:1][timestamp:8][iv:12][encrypted_data + auth_tag:variable]
 * ```
 * All values are base64-urlencoded for safe cookie storage.
 *
 * @example
 * ```typescript
 * // Async encryption (works everywhere)
 * const data = { userId: '123', role: 'admin' };
 * const encrypted = await CookieCrypto.encrypt(data, secret);
 *
 * // Async decryption with TTL validation (1 hour)
 * const decrypted = await CookieCrypto.decrypt(encrypted, secret, 3600);
 * ```
 *
 * @see {@link https://tools.ietf.org/html/rfc5869 | RFC 5869 - HKDF}
 * @see {@link https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf | NIST SP 800-38D - GCM}
 */
export class CookieCrypto {
  /** AES-GCM algorithm identifier */
  private static readonly ALGORITHM = 'AES-GCM';
  /** HKDF info parameter for domain separation */
  private static readonly INFO = 'aes-gcm-encryption';
  /** AES key length in bits (256-bit security) */
  private static readonly KEY_LENGTH = 256;
  /** HKDF salt for key derivation (version-specific) */
  private static readonly SALT = 'wristband-login-state-v1';
  /** Clock skew tolerance in milliseconds (60 seconds) */
  private static readonly TIMESTAMP_SKEW_MS = 60000;
  /** Binary format version for future compatibility */
  private static readonly VERSION = 1;

  // Maximum size: 4KB browser cookie limit
  private static readonly MAX_COOKIE_SIZE_BYTES = 4096;
  // Minimum size: version(1) + timestamp(8) + iv(12) + tag(16) + empty "{}"(2) = 39 bytes minimum
  private static readonly MIN_COOKIE_SIZE_BYTES = 39;

  /** Reusable text encoder instance */
  private static readonly encoder = new TextEncoder();
  /** Reusable text decoder instance */
  private static readonly decoder = new TextDecoder();

  /**
   * Derive a CryptoKey from a secret string using HKDF-SHA256.
   *
   * HKDF (HMAC-based Key Derivation Function, RFC 5869) is the standard approach
   * for deriving cryptographic keys from high-entropy secrets. While HMAC-SHA256
   * alone would be functionally secure for this purpose, HKDF provides:
   *
   * 1. **Standardization** - RFC 5869 is the accepted standard for key derivation
   * 2. **Clear semantics** - Explicitly designed for key derivation, not message authentication
   * 3. **Domain separation** - The `info` parameter prevents derived keys from being
   *    reused across different contexts (e.g., encryption vs signing)
   * 4. **Future-proofing** - Easy to derive multiple independent keys from one secret
   *
   * For cookies with 32+ character secrets, the security difference between
   * HKDF and raw HMAC is negligible, but HKDF is considered best practice.
   *
   * Note: We use a single derived key with AES-GCM (authenticated encryption), which
   * handles both confidentiality and integrity in one operation. No separate MAC key
   * is needed, unlike older approaches (AES-CBC + HMAC) which require two keys.
   *
   * @param secret - High-entropy secret (min 32 chars, validated elsewhere)
   * @returns CryptoKey suitable for AES-GCM encryption/decryption
   * @throws {CryptoError} If key derivation fails.
   *
   * @see https://tools.ietf.org/html/rfc5869 - HKDF specification
   */
  // eslint-disable-next-line n/no-unsupported-features/node-builtins
  private static async deriveKey(secret: string): Promise<CryptoKey> {
    this.validateSecret(secret);

    try {
      // Import secret as HKDF base key
      const secretBytes = this.encoder.encode(secret);
      const baseKey = await webCrypto.subtle.importKey('raw', secretBytes, 'HKDF', false, ['deriveKey']);

      // Use HKDF to derive AES-GCM key
      const salt = this.encoder.encode(this.SALT);
      const info = this.encoder.encode(this.INFO);

      return webCrypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt, info },
        baseKey,
        { name: this.ALGORITHM, length: this.KEY_LENGTH },
        false,
        ['encrypt', 'decrypt']
      );
    } catch {
      throw new CryptoError('ENCRYPTION_FAILED', 'Failed to derive encryption key from secret');
    }
  }

  /**
   * Asynchronously encrypt data into a secure, base64-urlencoded cookie value.
   *
   * Uses AES-256-GCM authenticated encryption with a randomly generated IV for each
   * encryption operation. The resulting cookie includes version metadata, encryption
   * timestamp, IV, and encrypted data with authentication tag.
   *
   * This method works across all JavaScript environments (Node.js, Deno, Bun,
   * Cloudflare Workers, browsers) using the Web Crypto API.
   *
   * @param data - Data object to encrypt (will be JSON-serialized)
   * @param secret - High-entropy secret string (minimum 32 characters recommended)
   * @returns Promise resolving to base64-urlencoded encrypted cookie string
   * @throws {CryptoError} If encryption fails or Web Crypto API is unavailable
   *
   * @remarks
   * - Generates a fresh random 96-bit IV for each encryption (never reuses IVs)
   * - Embeds current timestamp for TTL validation during decryption
   * - Output is safe for HTTP cookie storage (base64-urlencoded, no special characters)
   * - Maximum practical size is ~2.7KB of data (4KB cookie limit minus overhead)
   *
   * @example
   * ```typescript
   * const data = { userId: '123', roles: ['admin'], loginTime: Date.now() };
   * const secret = process.env.COOKIE_SECRET; // min 32 chars
   * const encryptedCookie = await CookieCrypto.encrypt(data, secret);
   * // Returns: "AQABkx7f2g...base64..." (ready for Set-Cookie header)
   * ```
   *
   * @see {@link decrypt} for decryption and TTL validation
   */
  static async encrypt(data: LoginState, secret: string): Promise<string> {
    this.validateData(data);
    this.validateSecret(secret);

    try {
      const key = await this.deriveKey(secret);
      const iv = webCrypto.getRandomValues(new Uint8Array(12));

      let dataBytes;
      try {
        dataBytes = this.encoder.encode(JSON.stringify(data));
      } catch {
        throw new CryptoError('ENCRYPTION_FAILED', 'Data must be JSON-serializable');
      }
      if (dataBytes.length > 4096) {
        throw new CryptoError('DATA_TOO_LARGE', `Data too large: ${dataBytes.length} bytes`);
      }

      const encrypted = await webCrypto.subtle.encrypt(
        { name: this.ALGORITHM, iv, tagLength: 128 },
        key,
        dataBytes.buffer
      );

      // Create compact binary format: [version(1)][timestamp(8)][iv(12)][encrypted data + tag(16)]
      // Note: Web Crypto API automatically appends the 16-byte GCM auth tag to encrypted data
      const timestamp = new Uint8Array(8);
      new DataView(timestamp.buffer).setBigUint64(0, BigInt(Date.now()), false);

      const combined = new Uint8Array(1 + 8 + 12 + encrypted.byteLength);
      combined[0] = this.VERSION;
      combined.set(timestamp, 1);
      combined.set(iv, 9);
      combined.set(new Uint8Array(encrypted), 21);

      // Convert to base64 URL
      const encodedValue = Base64.urlEncode(combined);

      // Check actual cookie size is not more than 4KB
      if (encodedValue.length > this.MAX_COOKIE_SIZE_BYTES) {
        throw new CryptoError(
          'DATA_TOO_LARGE',
          `Encrypted data exceeds 4KB cookie limit: ${encodedValue.length} bytes`
        );
      }

      return encodedValue;
    } catch (error) {
      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError('ENCRYPTION_FAILED', 'Failed to encrypt data');
    }
  }

  /**
   * Asynchronously decrypt and validate an encrypted cookie.
   *
   * Decrypts a base64-urlencoded cookie, validates its authentication tag to
   * ensure integrity, and checks that it is not expired based on the
   * embedded timestamp and provided maxAge parameter.
   *
   * This method works across all JavaScript environments using the Web Crypto API.
   *
   * @param encryptedValue - Base64-urlencoded encrypted cookie string (from {@link encrypt})
   * @param secret - Secret string used during encryption (must match)
   * @param maxAge - Maximum cookie age in seconds (e.g., 3600 for 1 hour)
   * @returns Promise resolving to decrypted LoginState object
   * @throws {CryptoError} If decryption fails due to:
   * - Invalid base64 URL encoding
   * - Cookie size exceeds 4KB limit
   * - Malformed cookie structure
   * - Unsupported version number
   * - Expired (timestamp exceeds maxAge + clock skew tolerance)
   * - Authentication tag verification failed (tampered data)
   * - Wrong secret provided
   *
   * @remarks
   * - Includes 60-second clock skew tolerance to handle server time differences
   * - Constant-time operations prevent timing attacks
   * - Any tampering with the cookie causes authentication failure
   * - Failed decryption throws a generic error to avoid leaking information
   *
   * @example
   * ```typescript
   * const encryptedCookie = req.cookies.my_cookie;
   * const secret = process.env.COOKIE_SECRET;
   * const maxAge = 24 * 60 * 60; // 24 hours
   *
   * try {
   *   const data = await CookieCrypto.decrypt(encryptedCookie, secret, maxAge);
   *   console.log('User ID:', data.userId);
   * } catch (err) {
   *   // Cookie invalid, expired, or tampered - require re-authentication
   *   res.redirect('/login');
   * }
   * ```
   *
   * @see {@link encrypt} for encryption
   * @see {@link decryptWithSecrets} for secret rotation support
   */
  static async decrypt(encryptedValue: string, secret: string, maxAge: number): Promise<LoginState> {
    this.validateEncryptedValue(encryptedValue);
    this.validateSecret(secret);
    this.validateMaxAge(maxAge);

    try {
      // Decode
      const bytes = Base64.urlDecode(encryptedValue);

      // Maximum size check (4KB browser cookie limit)
      if (bytes.length > this.MAX_COOKIE_SIZE_BYTES) {
        throw new CryptoError('DATA_TOO_LARGE', 'Cookie exceeds 4KB limit');
      }

      // Minimum size check (39 bytes minimum)
      if (bytes.length < this.MIN_COOKIE_SIZE_BYTES) {
        throw new CryptoError('MALFORMED_DATA', 'Cookie is malformed (too small)');
      }

      // Check version
      const version = bytes[0];
      if (version !== this.VERSION) {
        throw new CryptoError('UNSUPPORTED_VERSION', `Unsupported encryption version: ${version}`);
      }

      // Extract and validate timestamp for TTL
      const timestampBytes = bytes.slice(1, 9);
      const timestamp = Number(new DataView(timestampBytes.buffer).getBigUint64(0, false));
      const maxAgeMs = maxAge * 1000;
      if (Date.now() - timestamp > maxAgeMs + CookieCrypto.TIMESTAMP_SKEW_MS) {
        throw new CryptoError('EXPIRED', 'Cookie has expired');
      }

      // Extract components
      const iv = bytes.slice(9, 21);
      const encryptedData = bytes.slice(21);
      const key = await this.deriveKey(secret);

      const decrypted = await webCrypto.subtle.decrypt(
        { name: this.ALGORITHM, iv, tagLength: 128 },
        key,
        encryptedData
      );

      const jsonString = this.decoder.decode(decrypted);
      return JSON.parse(jsonString) as LoginState;
    } catch (error) {
      if (error instanceof CryptoError) {
        throw error;
      }
      // Any other error (auth tag failure, wrong secret, corrupt data, JSON parse error)
      throw new CryptoError('AUTH_FAILED', 'Failed to decrypt data');
    }
  }

  /**
   * Attempt to decrypt a cookie using multiple secrets for zero-downtime rotation.
   *
   * Tries each secret in order until one successfully decrypts and validates the cookie data.
   * This enables seamless secret rotation by accepting both new and old secrets during
   * a transition period.
   *
   * TTL validation is performed during each decryption attempt.
   *
   * @param encryptedValue - Base64-urlencoded encrypted cookie string
   * @param secrets - Array of secret strings to try (typically [newSecret, oldSecret])
   * @param maxAge - Maximum cookie age in seconds
   *
   * @returns Promise resolving to decrypted LoginState object
   *
   * @throws {Error} If decryption fails with all provided secrets
   *
   * @remarks
   * - Secrets are tried in array order (put most recent first for performance)
   * - Stops immediately on first successful decryption
   * - Failed attempts are silent - only throws if all secrets fail
   * - Useful for gradual secret rotation without user disruption
   *
   * @example
   * ```typescript
   * // During secret rotation period
   * const NEW_SECRET = process.env.NEW_COOKIE_SECRET;
   * const OLD_SECRET = process.env.OLD_COOKIE_SECRET;
   *
   * try {
   *   // Try new secret first, fall back to old secret
   *   const data = await CookieCrypto.decryptWithSecrets(
   *     encryptedCookie,
   *     [NEW_SECRET, OLD_SECRET],
   *     3600
   *   );
   *
   *   // Re-encrypt with new secret to migrate data
   *   const newCookie = await CookieCrypto.encrypt(data, NEW_SECRET);
   *   res.cookie('my_cookie', newCookie);
   * } catch (err) {
   *   // All secrets failed - cookie invalid
   *   res.redirect('/login');
   * }
   * ```
   *
   * @see {@link decrypt} for single-secret decryption
   * @throws {CryptoError} If decryption fails for all provided secrets.
   */
  static async decryptWithSecrets(encryptedValue: string, secrets: string[], maxAge: number): Promise<LoginState> {
    this.validateSecretsList(secrets);

    let lastError: Error | null = null;

    for (const secret of secrets) {
      try {
        return await this.decrypt(encryptedValue, secret, maxAge);
      } catch (error: unknown) {
        // Try the next secret if error encountered
        lastError = error instanceof Error ? error : new Error(String(error));
      }
    }

    throw new CryptoError('DECRYPTION_FAILED', 'Failed to decrypt with provided secrets', lastError);
  }

  /**
   * Validates a list of secrets used for encryption.
   *
   * Ensures the input is an array containing between 1 and 3 non-empty string values.
   * Each secret should later be individually validated with {@link validateSecret}.
   *
   * @param {string[]} secrets - An array of secret strings.
   * @throws {CryptoError} If the input is not an array, empty, or contains more than 3 secrets.
   */
  private static validateSecretsList(secrets: string[]): void {
    if (!secrets || !Array.isArray(secrets)) {
      throw new CryptoError('INVALID_SECRETS_LIST', 'Secrets must be an array');
    }
    if (secrets.length === 0) {
      throw new CryptoError('INVALID_SECRETS_LIST', 'At least one secret is required');
    }
    if (secrets.length > 3) {
      throw new CryptoError('INVALID_SECRETS_LIST', 'Maximum 3 secrets allowed');
    }
  }

  /**
   * Validates a single secret string for strength and format.
   *
   * Ensures the secret is a non-empty string of sufficient length for secure usage.
   *
   * @param {string} secret - The secret string to validate.
   * @throws {CryptoError} If the secret is not a string or is shorter than 32 characters.
   */
  private static validateSecret(secret: string): void {
    if (!secret || typeof secret !== 'string') {
      throw new CryptoError('INVALID_SECRET', 'Secret must be a non-empty string');
    }
    if (secret.length < 32) {
      throw new CryptoError(
        'INVALID_SECRET',
        `Secret must be at least 32 characters for adequate security (current: ${secret.length})`
      );
    }
  }

  /**
   * Validates the maximum age value for token or cookie expiration.
   *
   * Ensures the value is a positive number greater than zero.
   *
   * @param {number} maxAge - The maximum age (in seconds or milliseconds, depending on context).
   * @throws {CryptoError} If maxAge is not a positive number.
   */
  private static validateMaxAge(maxAge: number): void {
    if (typeof maxAge !== 'number' || maxAge <= 0) {
      throw new CryptoError('INVALID_MAX_AGE', 'maxAge must be greater than 0');
    }
  }

  /**
   * Validates data before encryption. Ensures the data is a valid plain object.
   *
   * @param {LoginState} data - The data to validate.
   * @throws {CryptoError} If the data is invalid.
   */
  private static validateData(data: LoginState): void {
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new CryptoError('ENCRYPTION_FAILED', 'Data must be a plain object');
    }
  }

  /**
   * Validates an encrypted cookie value before attempting decryption.
   *
   * Ensures the value is a non-empty string suitable for decoding.
   *
   * @param {string} encryptedValue - The encrypted cookie string to validate.
   * @throws {CryptoError} If the value is invalid.
   */
  private static validateEncryptedValue(encryptedValue: string): void {
    if (!encryptedValue || typeof encryptedValue !== 'string') {
      throw new CryptoError('MALFORMED_DATA', 'Encrypted value must be a non-empty string');
    }
  }
}

/**
 * Generates a random base64url-encoded string from the given number of random bytes.
 */
export function generateRandomString(length: number): string {
  return Base64.urlEncode(webCrypto.getRandomValues(new Uint8Array(length)));
}

/**
 * Creates a PKCE code challenge: the base64url-encoded SHA-256 hash of the code verifier.
 */
export async function createCodeChallenge(codeVerifier: string): Promise<string> {
  const digest = await webCrypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  return Base64.urlEncode(new Uint8Array(digest));
}
