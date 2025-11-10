import nock from 'nock';

import { WristbandService } from '../../src/wristband-service';
import { WristbandUserinfoResponse } from '../../src/types';

const DOMAIN = 'your-wristband-domain';
const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';

describe('WristbandService - UserInfo Claims Mapping', () => {
  let wristbandService: WristbandService;

  beforeEach(() => {
    nock.cleanAll();
    wristbandService = new WristbandService(DOMAIN, CLIENT_ID, CLIENT_SECRET);
  });

  describe('Required Claims (Always Present)', () => {
    test('Maps required OIDC claims to UserInfo fields', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.userId).toBe('user-123');
      expect(result.tenantId).toBe('tenant-456');
      expect(result.applicationId).toBe('app-789');
      expect(result.identityProviderName).toBe('wristband');
      scope.done();
    });

    test('Required claims are always mapped from snake_case to camelCase', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-abc',
        tnt_id: 'tenant-xyz',
        app_id: 'app-def',
        idp_name: 'google',
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      // Verify snake_case is converted to camelCase
      expect(result).toHaveProperty('userId', 'user-abc');
      expect(result).toHaveProperty('tenantId', 'tenant-xyz');
      expect(result).toHaveProperty('applicationId', 'app-def');
      expect(result).toHaveProperty('identityProviderName', 'google');

      // Ensure snake_case properties don't exist in result
      expect(result).not.toHaveProperty('sub');
      expect(result).not.toHaveProperty('tnt_id');
      expect(result).not.toHaveProperty('app_id');
      expect(result).not.toHaveProperty('idp_name');

      scope.done();
    });
  });

  describe('Profile Scope Claims', () => {
    test('Maps all profile scope claims when present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        name: 'John Michael Doe',
        given_name: 'John',
        family_name: 'Doe',
        middle_name: 'Michael',
        nickname: 'Johnny',
        preferred_username: 'johndoe',
        picture: 'https://example.com/profile.jpg',
        gender: 'male',
        birthdate: '1990-01-15',
        zoneinfo: 'America/New_York',
        locale: 'en-US',
        updated_at: 1672531200,
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.fullName).toBe('John Michael Doe');
      expect(result.givenName).toBe('John');
      expect(result.familyName).toBe('Doe');
      expect(result.middleName).toBe('Michael');
      expect(result.nickname).toBe('Johnny');
      expect(result.displayName).toBe('johndoe');
      expect(result.pictureUrl).toBe('https://example.com/profile.jpg');
      expect(result.gender).toBe('male');
      expect(result.birthdate).toBe('1990-01-15');
      expect(result.timeZone).toBe('America/New_York');
      expect(result.locale).toBe('en-US');
      expect(result.updatedAt).toBe(1672531200);
      scope.done();
    });

    test('Profile claims are undefined when not present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        // No profile scope claims
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.fullName).toBeUndefined();
      expect(result.givenName).toBeUndefined();
      expect(result.familyName).toBeUndefined();
      expect(result.middleName).toBeUndefined();
      expect(result.nickname).toBeUndefined();
      expect(result.displayName).toBeUndefined();
      expect(result.pictureUrl).toBeUndefined();
      expect(result.gender).toBeUndefined();
      expect(result.birthdate).toBeUndefined();
      expect(result.timeZone).toBeUndefined();
      expect(result.locale).toBeUndefined();
      expect(result.updatedAt).toBeUndefined();
      scope.done();
    });

    test('Maps partial profile scope claims', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        name: 'Jane Smith',
        given_name: 'Jane',
        locale: 'fr-FR',
        // Other profile claims missing
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.fullName).toBe('Jane Smith');
      expect(result.givenName).toBe('Jane');
      expect(result.locale).toBe('fr-FR');
      expect(result.familyName).toBeUndefined();
      expect(result.middleName).toBeUndefined();
      expect(result.nickname).toBeUndefined();
      scope.done();
    });

    test('Converts profile snake_case claims to camelCase', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        given_name: 'Alice',
        family_name: 'Brown',
        middle_name: 'Marie',
        preferred_username: 'aliceb',
        updated_at: 1672531200,
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.givenName).toBe('Alice');
      expect(result.familyName).toBe('Brown');
      expect(result.middleName).toBe('Marie');
      expect(result.displayName).toBe('aliceb');
      expect(result.updatedAt).toBe(1672531200);

      // Verify snake_case doesn't exist
      expect(result).not.toHaveProperty('given_name');
      expect(result).not.toHaveProperty('family_name');
      expect(result).not.toHaveProperty('middle_name');
      expect(result).not.toHaveProperty('preferred_username');
      expect(result).not.toHaveProperty('updated_at');

      scope.done();
    });
  });

  describe('Email Scope Claims', () => {
    test('Maps email scope claims when present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        email: 'user@example.com',
        email_verified: true,
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.email).toBe('user@example.com');
      expect(result.emailVerified).toBe(true);
      scope.done();
    });

    test('Email claims are undefined when not present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        // No email scope claims
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.email).toBeUndefined();
      expect(result.emailVerified).toBeUndefined();
      scope.done();
    });

    test('Maps email with emailVerified false', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        email: 'unverified@example.com',
        email_verified: false,
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.email).toBe('unverified@example.com');
      expect(result.emailVerified).toBe(false);
      scope.done();
    });

    test('Converts email_verified to emailVerified', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        email: 'test@example.com',
        email_verified: true,
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.emailVerified).toBe(true);
      expect(result).not.toHaveProperty('email_verified');
      scope.done();
    });
  });

  describe('Phone Scope Claims', () => {
    test('Maps phone scope claims when present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        phone_number: '+1234567890',
        phone_number_verified: true,
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.phoneNumber).toBe('+1234567890');
      expect(result.phoneNumberVerified).toBe(true);
      scope.done();
    });

    test('Phone claims are undefined when not present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        // No phone scope claims
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.phoneNumber).toBeUndefined();
      expect(result.phoneNumberVerified).toBeUndefined();
      scope.done();
    });

    test('Maps phone with phoneNumberVerified false', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        phone_number: '+9876543210',
        phone_number_verified: false,
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.phoneNumber).toBe('+9876543210');
      expect(result.phoneNumberVerified).toBe(false);
      scope.done();
    });

    test('Converts phone_number and phone_number_verified to camelCase', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        phone_number: '+1122334455',
        phone_number_verified: true,
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.phoneNumber).toBe('+1122334455');
      expect(result.phoneNumberVerified).toBe(true);
      expect(result).not.toHaveProperty('phone_number');
      expect(result).not.toHaveProperty('phone_number_verified');
      scope.done();
    });
  });

  describe('Roles Scope Claims', () => {
    test('Maps roles when present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        roles: [
          {
            id: 'role-1',
            name: 'app:myapp:admin',
            display_name: 'Admin Role',
          },
          {
            id: 'role-2',
            name: 'app:myapp:user',
            display_name: 'User Role',
          },
        ],
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.roles).toBeDefined();
      expect(result.roles).toHaveLength(2);
      expect(result.roles![0]).toEqual({
        id: 'role-1',
        name: 'app:myapp:admin',
        displayName: 'Admin Role',
      });
      expect(result.roles![1]).toEqual({
        id: 'role-2',
        name: 'app:myapp:user',
        displayName: 'User Role',
      });
      scope.done();
    });

    test('Roles are undefined when not present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        // No roles scope claims
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.roles).toBeUndefined();
      scope.done();
    });

    test('Maps empty roles array', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        roles: [],
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.roles).toBeDefined();
      expect(result.roles).toHaveLength(0);
      scope.done();
    });

    test('Converts role display_name to displayName', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        roles: [
          {
            id: 'role-1',
            name: 'app:myapp:superadmin',
            display_name: 'Super Admin',
          },
        ],
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.roles![0].displayName).toBe('Super Admin');
      expect(result.roles![0]).not.toHaveProperty('display_name');
      scope.done();
    });

    test('Handles role with displayName instead of display_name', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        roles: [
          {
            id: 'role-1',
            name: 'app:myapp:editor',
            displayName: 'Editor Role', // Already camelCase
          },
        ],
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.roles![0].displayName).toBe('Editor Role');
      scope.done();
    });

    test('Maps multiple roles with different formats', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        roles: [
          {
            id: 'role-1',
            name: 'app:myapp:admin',
            display_name: 'Admin',
          },
          {
            id: 'role-2',
            name: 'app:myapp:user',
            displayName: 'User', // Already camelCase
          },
        ],
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.roles).toHaveLength(2);
      expect(result.roles![0].displayName).toBe('Admin');
      expect(result.roles![1].displayName).toBe('User');
      scope.done();
    });
  });

  describe('Custom Claims', () => {
    test('Maps custom claims when present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        custom_claims: {
          department: 'Engineering',
          employeeId: 'EMP-001',
          level: 5,
        },
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.customClaims).toBeDefined();
      expect(result.customClaims).toEqual({
        department: 'Engineering',
        employeeId: 'EMP-001',
        level: 5,
      });
      scope.done();
    });

    test('Custom claims are undefined when not present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        // No custom claims
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.customClaims).toBeUndefined();
      scope.done();
    });

    test('Maps empty custom claims object', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        custom_claims: {},
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.customClaims).toBeDefined();
      expect(result.customClaims).toEqual({});
      scope.done();
    });

    test('Maps custom claims with various data types', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        custom_claims: {
          stringField: 'value',
          numberField: 42,
          booleanField: true,
          arrayField: ['item1', 'item2'],
          objectField: { nested: 'data' },
        },
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.customClaims).toEqual({
        stringField: 'value',
        numberField: 42,
        booleanField: true,
        arrayField: ['item1', 'item2'],
        objectField: { nested: 'data' },
      });
      scope.done();
    });
  });

  describe('Complete UserInfo with All Scopes', () => {
    test('Maps complete userinfo with all scope claims present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        // Required claims
        sub: 'user-full-123',
        tnt_id: 'tenant-full-456',
        app_id: 'app-full-789',
        idp_name: 'okta',
        // Profile scope
        name: 'Alice Marie Johnson',
        given_name: 'Alice',
        family_name: 'Johnson',
        middle_name: 'Marie',
        nickname: 'Ali',
        preferred_username: 'alicej',
        picture: 'https://example.com/alice.jpg',
        gender: 'female',
        birthdate: '1995-05-20',
        zoneinfo: 'Europe/London',
        locale: 'en-GB',
        updated_at: 1672531200,
        // Email scope
        email: 'alice@example.com',
        email_verified: true,
        // Phone scope
        phone_number: '+447123456789',
        phone_number_verified: true,
        // Roles scope
        roles: [
          {
            id: 'role-admin',
            name: 'app:myapp:admin',
            display_name: 'Administrator',
          },
          {
            id: 'role-editor',
            name: 'app:myapp:editor',
            display_name: 'Editor',
          },
        ],
        // Custom claims
        custom_claims: {
          department: 'Product',
          location: 'London',
        },
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      // Required claims
      expect(result.userId).toBe('user-full-123');
      expect(result.tenantId).toBe('tenant-full-456');
      expect(result.applicationId).toBe('app-full-789');
      expect(result.identityProviderName).toBe('okta');
      // Profile claims
      expect(result.fullName).toBe('Alice Marie Johnson');
      expect(result.givenName).toBe('Alice');
      expect(result.familyName).toBe('Johnson');
      expect(result.middleName).toBe('Marie');
      expect(result.nickname).toBe('Ali');
      expect(result.displayName).toBe('alicej');
      expect(result.pictureUrl).toBe('https://example.com/alice.jpg');
      expect(result.gender).toBe('female');
      expect(result.birthdate).toBe('1995-05-20');
      expect(result.timeZone).toBe('Europe/London');
      expect(result.locale).toBe('en-GB');
      expect(result.updatedAt).toBe(1672531200);
      // Email claims
      expect(result.email).toBe('alice@example.com');
      expect(result.emailVerified).toBe(true);
      // Phone claims
      expect(result.phoneNumber).toBe('+447123456789');
      expect(result.phoneNumberVerified).toBe(true);
      // Roles
      expect(result.roles).toHaveLength(2);
      expect(result.roles![0]).toEqual({
        id: 'role-admin',
        name: 'app:myapp:admin',
        displayName: 'Administrator',
      });
      expect(result.roles![1]).toEqual({
        id: 'role-editor',
        name: 'app:myapp:editor',
        displayName: 'Editor',
      });
      // Custom claims
      expect(result.customClaims).toEqual({
        department: 'Product',
        location: 'London',
      });

      scope.done();
    });

    test('Maps minimal userinfo with only required claims', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-minimal',
        tnt_id: 'tenant-minimal',
        app_id: 'app-minimal',
        idp_name: 'wristband',
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      // Required claims present
      expect(result.userId).toBe('user-minimal');
      expect(result.tenantId).toBe('tenant-minimal');
      expect(result.applicationId).toBe('app-minimal');
      expect(result.identityProviderName).toBe('wristband');

      // All optional claims undefined
      expect(result.fullName).toBeUndefined();
      expect(result.email).toBeUndefined();
      expect(result.phoneNumber).toBeUndefined();
      expect(result.roles).toBeUndefined();
      expect(result.customClaims).toBeUndefined();

      scope.done();
    });
  });

  describe('Required Claims Validation', () => {
    test('Throws error when sub claim is missing', async () => {
      const accessToken = 'valid-access-token';
      const invalidResponse = {
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        // missing sub
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, invalidResponse);

      try {
        await wristbandService.getUserInfo(accessToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(TypeError);
        expect((error as TypeError).message).toBe('Invalid userinfo response: missing sub claim');
      }

      scope.done();
    });

    test('Throws error when tnt_id claim is missing', async () => {
      const accessToken = 'valid-access-token';
      const invalidResponse = {
        sub: 'user-123',
        app_id: 'app-789',
        idp_name: 'wristband',
        // missing tnt_id
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, invalidResponse);

      try {
        await wristbandService.getUserInfo(accessToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(TypeError);
        expect((error as TypeError).message).toBe('Invalid userinfo response: missing tnt_id claim');
      }

      scope.done();
    });

    test('Throws error when app_id claim is missing', async () => {
      const accessToken = 'valid-access-token';
      const invalidResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        idp_name: 'wristband',
        // missing app_id
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, invalidResponse);

      try {
        await wristbandService.getUserInfo(accessToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(TypeError);
        expect((error as TypeError).message).toBe('Invalid userinfo response: missing app_id claim');
      }

      scope.done();
    });

    test('Throws error when idp_name claim is missing', async () => {
      const accessToken = 'valid-access-token';
      const invalidResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        // missing idp_name
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, invalidResponse);

      try {
        await wristbandService.getUserInfo(accessToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(TypeError);
        expect((error as TypeError).message).toBe('Invalid userinfo response: missing idp_name claim');
      }

      scope.done();
    });

    test('Throws error when sub claim is not a string', async () => {
      const accessToken = 'valid-access-token';
      const invalidResponse = {
        sub: 12345, // Not a string
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
      };

      const scope = nock(`https://${DOMAIN}`).get('/api/v1/oauth2/userinfo').reply(200, invalidResponse);

      try {
        await wristbandService.getUserInfo(accessToken);
        fail('Expected an error to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(TypeError);
        expect((error as TypeError).message).toBe('Invalid userinfo response: missing sub claim');
      }

      scope.done();
    });
  });
});
