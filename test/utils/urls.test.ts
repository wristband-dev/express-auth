/* eslint-disable import/no-extraneous-dependencies */

import httpMocks from 'node-mocks-http';
import { stripPort, getRequestHost, toCoreRequest } from '../../src/utils/urls';

describe('Auth Utils', () => {
  describe('stripPort', () => {
    test('Removes the port from a host', () => {
      expect(stripPort('acme.myapp.com:3000')).toBe('acme.myapp.com');
    });

    test('Returns a host without a port unchanged', () => {
      expect(stripPort('acme.myapp.com')).toBe('acme.myapp.com');
    });

    test('Removes the port from a bracketed IPv6 host', () => {
      expect(stripPort('[::1]:3000')).toBe('[::1]');
    });

    test('Returns a bracketed IPv6 host without a port unchanged', () => {
      expect(stripPort('[::1]')).toBe('[::1]');
    });
  });

  describe('getRequestHost', () => {
    // Setting "hostname" explicitly simulates Express resolving req.hostname from
    // X-Forwarded-Host, which only happens when the app's "trust proxy" setting trusts the sender.

    test('Returns the Host header with its port when no proxy headers are present', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'acme.myapp.com:3000' },
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com:3000');
    });

    test('Returns X-Forwarded-Host when Express resolved the hostname from it', () => {
      const req = httpMocks.createRequest({
        hostname: 'acme.myapp.com',
        headers: { host: 'localhost:3000', 'x-forwarded-host': 'acme.myapp.com' },
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com');
    });

    test('Keeps the port from X-Forwarded-Host', () => {
      const req = httpMocks.createRequest({
        hostname: 'acme.myapp.com',
        headers: { host: 'localhost:3000', 'x-forwarded-host': 'acme.myapp.com:8443' },
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com:8443');
    });

    test('Uses the first value when X-Forwarded-Host contains a comma-separated list', () => {
      const req = httpMocks.createRequest({
        hostname: 'acme.myapp.com',
        headers: { host: 'localhost:3000', 'x-forwarded-host': 'acme.myapp.com, other.com' },
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com');
    });

    test('Ignores X-Forwarded-Host when Express resolved the hostname from the Host header', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'acme.myapp.com:3000', 'x-forwarded-host': 'evil.com' },
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com:3000');
    });

    test('Prefers the Host header when both headers share the same hostname', () => {
      const req = httpMocks.createRequest({
        headers: { host: 'acme.myapp.com:3000', 'x-forwarded-host': 'acme.myapp.com:9999' },
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com:3000');
    });

    test('Falls back to the hostname when neither header matches it', () => {
      const req = httpMocks.createRequest({
        hostname: 'acme.myapp.com',
      }) as any;

      expect(getRequestHost(req)).toBe('acme.myapp.com');
    });

    test('Returns an empty string when the hostname is missing', () => {
      const req = { headers: {} } as any;

      expect(getRequestHost(req)).toBe('');
    });
  });

  describe('toCoreRequest', () => {
    test('Passes the host and protocol Express chose, and drops X-Forwarded-Host', () => {
      const req = httpMocks.createRequest({
        hostname: 'acme.myapp.com',
        protocol: 'https',
        url: '/auth/login?tenant_name=acme',
        query: { tenant_name: 'acme' },
        headers: { host: 'localhost:3000', 'x-forwarded-host': 'acme.myapp.com:8443', cookie: 'a=b' },
      }) as any;

      const coreRequest = toCoreRequest(req) as any;
      expect(coreRequest.headers.host).toBe('acme.myapp.com:8443');
      expect(coreRequest.headers['x-forwarded-proto']).toBe('https');
      expect(coreRequest.headers['x-forwarded-host']).toBeUndefined();
      expect(coreRequest.headers.cookie).toBe('a=b');
      expect(coreRequest.query).toEqual({ tenant_name: 'acme' });
      expect(coreRequest.url).toBe('/auth/login?tenant_name=acme');
    });

    test('Ignores an untrusted X-Forwarded-Proto and X-Forwarded-Host', () => {
      const req = httpMocks.createRequest({
        protocol: 'http',
        headers: { host: 'acme.myapp.com:3000', 'x-forwarded-host': 'evil.com', 'x-forwarded-proto': 'https' },
      }) as any;

      const coreRequest = toCoreRequest(req) as any;
      expect(coreRequest.headers.host).toBe('acme.myapp.com:3000');
      expect(coreRequest.headers['x-forwarded-proto']).toBe('http');
      expect(coreRequest.headers['x-forwarded-host']).toBeUndefined();
    });
  });
});
