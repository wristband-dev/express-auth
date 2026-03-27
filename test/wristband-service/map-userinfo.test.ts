import { WristbandService } from '../../src/wristband-service';
import { WristbandUserinfoResponse } from '../../src/types';

const DOMAIN = 'your-wristband-domain';
const CLIENT_ID = 'test-client-id';
const CLIENT_SECRET = 'test-client-secret';

function mockFetch(status: number, body: unknown) {
  const bodyText = typeof body === 'string' ? body : JSON.stringify(body);
  global.fetch = jest.fn().mockResolvedValue({
    status,
    ok: status >= 200 && status < 300,
    headers: {
      get: () => {
        return 'application/json';
      },
    },
    text: jest.fn().mockResolvedValue(bodyText),
  });
}

describe('WristbandService - UserInfo Claims Mapping', () => {
  let wristbandService: WristbandService;

  beforeEach(() => {
    wristbandService = new WristbandService(DOMAIN, CLIENT_ID, CLIENT_SECRET);
  });

  afterEach(() => {
    jest.restoreAllMocks();
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
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.userId).toBe('user-123');
      expect(result.tenantId).toBe('tenant-456');
      expect(result.applicationId).toBe('app-789');
      expect(result.identityProviderName).toBe('wristband');
    });

    test('Converts snake_case required claims to camelCase', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-abc',
        tnt_id: 'tenant-xyz',
        app_id: 'app-def',
        idp_name: 'google',
      };
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result).toHaveProperty('userId', 'user-abc');
      expect(result).toHaveProperty('tenantId', 'tenant-xyz');
      expect(result).toHaveProperty('applicationId', 'app-def');
      expect(result).toHaveProperty('identityProviderName', 'google');
      expect(result).not.toHaveProperty('sub');
      expect(result).not.toHaveProperty('tnt_id');
      expect(result).not.toHaveProperty('app_id');
      expect(result).not.toHaveProperty('idp_name');
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
      mockFetch(200, userInfoResponse);

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
    });

    test('Profile claims are undefined when not present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
      };
      mockFetch(200, userInfoResponse);

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
      };
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.fullName).toBe('Jane Smith');
      expect(result.givenName).toBe('Jane');
      expect(result.locale).toBe('fr-FR');
      expect(result.familyName).toBeUndefined();
      expect(result.middleName).toBeUndefined();
      expect(result.nickname).toBeUndefined();
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
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.givenName).toBe('Alice');
      expect(result.familyName).toBe('Brown');
      expect(result.middleName).toBe('Marie');
      expect(result.displayName).toBe('aliceb');
      expect(result.updatedAt).toBe(1672531200);
      expect(result).not.toHaveProperty('given_name');
      expect(result).not.toHaveProperty('family_name');
      expect(result).not.toHaveProperty('middle_name');
      expect(result).not.toHaveProperty('preferred_username');
      expect(result).not.toHaveProperty('updated_at');
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
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.email).toBe('user@example.com');
      expect(result.emailVerified).toBe(true);
    });

    test('Email claims are undefined when not present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
      };
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.email).toBeUndefined();
      expect(result.emailVerified).toBeUndefined();
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
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.email).toBe('unverified@example.com');
      expect(result.emailVerified).toBe(false);
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
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.emailVerified).toBe(true);
      expect(result).not.toHaveProperty('email_verified');
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
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.phoneNumber).toBe('+1234567890');
      expect(result.phoneNumberVerified).toBe(true);
    });

    test('Phone claims are undefined when not present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
      };
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.phoneNumber).toBeUndefined();
      expect(result.phoneNumberVerified).toBeUndefined();
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
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.phoneNumber).toBe('+9876543210');
      expect(result.phoneNumberVerified).toBe(false);
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
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.phoneNumber).toBe('+1122334455');
      expect(result.phoneNumberVerified).toBe(true);
      expect(result).not.toHaveProperty('phone_number');
      expect(result).not.toHaveProperty('phone_number_verified');
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
          { id: 'role-1', name: 'app:myapp:admin', display_name: 'Admin Role' },
          { id: 'role-2', name: 'app:myapp:user', display_name: 'User Role' },
        ],
      };
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.roles).toBeDefined();
      expect(result.roles).toHaveLength(2);
      expect(result.roles![0]).toEqual({ id: 'role-1', name: 'app:myapp:admin', displayName: 'Admin Role' });
      expect(result.roles![1]).toEqual({ id: 'role-2', name: 'app:myapp:user', displayName: 'User Role' });
    });

    test('Roles are undefined when not present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
      };
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.roles).toBeUndefined();
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
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.roles).toBeDefined();
      expect(result.roles).toHaveLength(0);
    });

    test('Converts role display_name to displayName', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        roles: [{ id: 'role-1', name: 'app:myapp:superadmin', display_name: 'Super Admin' }],
      };
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.roles![0].displayName).toBe('Super Admin');
      expect(result.roles![0]).not.toHaveProperty('display_name');
    });

    test('Handles role with displayName instead of display_name', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        roles: [{ id: 'role-1', name: 'app:myapp:editor', displayName: 'Editor Role' }],
      };
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.roles![0].displayName).toBe('Editor Role');
    });

    test('Maps multiple roles with mixed display_name formats', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
        roles: [
          { id: 'role-1', name: 'app:myapp:admin', display_name: 'Admin' },
          { id: 'role-2', name: 'app:myapp:user', displayName: 'User' },
        ],
      };
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.roles).toHaveLength(2);
      expect(result.roles![0].displayName).toBe('Admin');
      expect(result.roles![1].displayName).toBe('User');
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
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.customClaims).toBeDefined();
      expect(result.customClaims).toEqual({
        department: 'Engineering',
        employeeId: 'EMP-001',
        level: 5,
      });
    });

    test('Custom claims are undefined when not present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
      };
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.customClaims).toBeUndefined();
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
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.customClaims).toBeDefined();
      expect(result.customClaims).toEqual({});
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
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.customClaims).toEqual({
        stringField: 'value',
        numberField: 42,
        booleanField: true,
        arrayField: ['item1', 'item2'],
        objectField: { nested: 'data' },
      });
    });
  });

  describe('Complete UserInfo with All Scopes', () => {
    test('Maps complete userinfo with all scope claims present', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-full-123',
        tnt_id: 'tenant-full-456',
        app_id: 'app-full-789',
        idp_name: 'okta',
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
        email: 'alice@example.com',
        email_verified: true,
        phone_number: '+447123456789',
        phone_number_verified: true,
        roles: [
          { id: 'role-admin', name: 'app:myapp:admin', display_name: 'Administrator' },
          { id: 'role-editor', name: 'app:myapp:editor', display_name: 'Editor' },
        ],
        custom_claims: { department: 'Product', location: 'London' },
      };
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.userId).toBe('user-full-123');
      expect(result.tenantId).toBe('tenant-full-456');
      expect(result.applicationId).toBe('app-full-789');
      expect(result.identityProviderName).toBe('okta');
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
      expect(result.email).toBe('alice@example.com');
      expect(result.emailVerified).toBe(true);
      expect(result.phoneNumber).toBe('+447123456789');
      expect(result.phoneNumberVerified).toBe(true);
      expect(result.roles).toHaveLength(2);
      expect(result.roles![0]).toEqual({ id: 'role-admin', name: 'app:myapp:admin', displayName: 'Administrator' });
      expect(result.roles![1]).toEqual({ id: 'role-editor', name: 'app:myapp:editor', displayName: 'Editor' });
      expect(result.customClaims).toEqual({ department: 'Product', location: 'London' });
    });

    test('Maps minimal userinfo with only required claims', async () => {
      const accessToken = 'valid-access-token';
      const userInfoResponse: WristbandUserinfoResponse = {
        sub: 'user-minimal',
        tnt_id: 'tenant-minimal',
        app_id: 'app-minimal',
        idp_name: 'wristband',
      };
      mockFetch(200, userInfoResponse);

      const result = await wristbandService.getUserInfo(accessToken);

      expect(result.userId).toBe('user-minimal');
      expect(result.tenantId).toBe('tenant-minimal');
      expect(result.applicationId).toBe('app-minimal');
      expect(result.identityProviderName).toBe('wristband');
      expect(result.fullName).toBeUndefined();
      expect(result.email).toBeUndefined();
      expect(result.phoneNumber).toBeUndefined();
      expect(result.roles).toBeUndefined();
      expect(result.customClaims).toBeUndefined();
    });
  });

  describe('Required Claims Validation', () => {
    test('Throws TypeError when sub claim is missing', async () => {
      const accessToken = 'valid-access-token';
      const invalidResponse = {
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
      };
      mockFetch(200, invalidResponse);

      await expect(wristbandService.getUserInfo(accessToken)).rejects.toThrow(
        'Invalid userinfo response: missing sub claim'
      );
    });

    test('Throws TypeError when tnt_id claim is missing', async () => {
      const accessToken = 'valid-access-token';
      const invalidResponse = {
        sub: 'user-123',
        app_id: 'app-789',
        idp_name: 'wristband',
      };
      mockFetch(200, invalidResponse);

      await expect(wristbandService.getUserInfo(accessToken)).rejects.toThrow(
        'Invalid userinfo response: missing tnt_id claim'
      );
    });

    test('Throws TypeError when app_id claim is missing', async () => {
      const accessToken = 'valid-access-token';
      const invalidResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        idp_name: 'wristband',
      };
      mockFetch(200, invalidResponse);

      await expect(wristbandService.getUserInfo(accessToken)).rejects.toThrow(
        'Invalid userinfo response: missing app_id claim'
      );
    });

    test('Throws TypeError when idp_name claim is missing', async () => {
      const accessToken = 'valid-access-token';
      const invalidResponse = {
        sub: 'user-123',
        tnt_id: 'tenant-456',
        app_id: 'app-789',
      };
      mockFetch(200, invalidResponse);

      await expect(wristbandService.getUserInfo(accessToken)).rejects.toThrow(
        'Invalid userinfo response: missing idp_name claim'
      );
    });

    test('Throws TypeError when sub claim is not a string', async () => {
      const accessToken = 'valid-access-token';
      const invalidResponse = {
        sub: 12345,
        tnt_id: 'tenant-456',
        app_id: 'app-789',
        idp_name: 'wristband',
      };
      mockFetch(200, invalidResponse);

      await expect(wristbandService.getUserInfo(accessToken)).rejects.toThrow(
        'Invalid userinfo response: missing sub claim'
      );
    });
  });
});
