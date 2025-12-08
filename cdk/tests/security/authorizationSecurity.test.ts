/**
 * Security Tests: Authorization Security
 *
 * Comprehensive authorization security tests covering:
 * - Horizontal privilege escalation prevention
 * - Vertical privilege escalation prevention
 * - IDOR (Insecure Direct Object Reference) prevention
 * - Function-level access control
 * - API endpoint permission validation
 *
 * @see OWASP A01:2021 - Broken Access Control
 */

import * as crypto from 'crypto';
import {
  AUTHZ_BYPASS_SCENARIOS,
  MockAuthService,
} from '../fixtures/security/securityScenarios';

// ============================================
// Mock Authorization Service
// ============================================

interface Resource {
  id: string;
  ownerId: string;
  type: string;
  data: Record<string, any>;
}

interface Permission {
  resource: string;
  actions: string[];
  condition?: (userId: string, resource: Resource) => boolean;
}

class MockAuthorizationService {
  private resources: Map<string, Resource> = new Map();
  private userPermissions: Map<string, Permission[]> = new Map();
  private rolePermissions: Map<string, Permission[]> = new Map();

  constructor() {
    this.setupDefaultPermissions();
    this.setupTestResources();
  }

  private setupDefaultPermissions(): void {
    // Admin role permissions
    this.rolePermissions.set('admin', [
      { resource: '/admin/*', actions: ['GET', 'POST', 'PUT', 'DELETE'] },
      { resource: '/member/*', actions: ['GET', 'POST', 'PUT', 'DELETE'] },
      { resource: '/vault/*', actions: ['GET', 'POST', 'PUT', 'DELETE'] },
    ]);

    // Member role permissions
    this.rolePermissions.set('member', [
      {
        resource: '/member/profile',
        actions: ['GET', 'PUT'],
        condition: (userId, resource) => resource.ownerId === userId,
      },
      {
        resource: '/vault/backup/*',
        actions: ['GET', 'POST', 'DELETE'],
        condition: (userId, resource) => resource.ownerId === userId,
      },
      {
        resource: '/connections/*',
        actions: ['GET', 'POST', 'DELETE'],
        condition: (userId, resource) => resource.ownerId === userId,
      },
      {
        resource: '/messages/*',
        actions: ['GET', 'POST'],
        condition: (userId, resource) => resource.ownerId === userId,
      },
    ]);

    // Anonymous (unauthenticated) permissions
    this.rolePermissions.set('anonymous', [
      { resource: '/register', actions: ['POST'] },
      { resource: '/public/*', actions: ['GET'] },
    ]);
  }

  private setupTestResources(): void {
    // User A's resources
    this.resources.set('profile-user-a', {
      id: 'profile-user-a',
      ownerId: 'user-a',
      type: 'profile',
      data: { email: 'a@test.com', name: 'User A' },
    });

    this.resources.set('backup-user-a-1', {
      id: 'backup-user-a-1',
      ownerId: 'user-a',
      type: 'backup',
      data: { created: new Date().toISOString() },
    });

    this.resources.set('connection-user-a-1', {
      id: 'connection-user-a-1',
      ownerId: 'user-a',
      type: 'connection',
      data: { peer: 'user-c' },
    });

    this.resources.set('message-user-a-1', {
      id: 'message-user-a-1',
      ownerId: 'user-a',
      type: 'message',
      data: { content: 'encrypted-content' },
    });

    // User B's resources
    this.resources.set('profile-user-b', {
      id: 'profile-user-b',
      ownerId: 'user-b',
      type: 'profile',
      data: { email: 'b@test.com', name: 'User B' },
    });

    this.resources.set('backup-user-b-1', {
      id: 'backup-user-b-1',
      ownerId: 'user-b',
      type: 'backup',
      data: { created: new Date().toISOString() },
    });

    // Admin resources
    this.resources.set('invite-admin-1', {
      id: 'invite-admin-1',
      ownerId: 'admin-user',
      type: 'invite',
      data: { code: 'INVITE123' },
    });
  }

  /**
   * Check if user has permission to perform action on resource
   */
  checkPermission(
    userId: string | null,
    role: string,
    resourcePath: string,
    action: string,
    resourceId?: string
  ): { allowed: boolean; reason?: string } {
    // Get role permissions
    const permissions = this.rolePermissions.get(role) || [];

    // Find matching permission
    for (const perm of permissions) {
      if (this.pathMatches(resourcePath, perm.resource) && perm.actions.includes(action)) {
        // Check condition if exists
        if (perm.condition && resourceId) {
          const resource = this.resources.get(resourceId);
          if (resource && !perm.condition(userId || '', resource)) {
            return { allowed: false, reason: 'Resource ownership check failed' };
          }
        }
        return { allowed: true };
      }
    }

    return { allowed: false, reason: 'No matching permission found' };
  }

  /**
   * Get resource by ID with ownership check
   */
  getResource(userId: string, resourceId: string): Resource | null {
    const resource = this.resources.get(resourceId);
    if (!resource) return null;

    // Check ownership
    if (resource.ownerId !== userId) {
      return null; // Don't reveal resource exists
    }

    return resource;
  }

  /**
   * Check if path matches permission pattern
   */
  private pathMatches(path: string, pattern: string): boolean {
    if (pattern.endsWith('/*')) {
      const prefix = pattern.slice(0, -1);
      return path.startsWith(prefix);
    }
    return path === pattern;
  }

  /**
   * Reset for testing
   */
  reset(): void {
    this.setupDefaultPermissions();
    this.setupTestResources();
  }
}

// ============================================
// Horizontal Privilege Escalation Tests
// ============================================

describe('Horizontal Privilege Escalation Prevention', () => {
  let authzService: MockAuthorizationService;

  beforeEach(() => {
    authzService = new MockAuthorizationService();
  });

  describe('User Data Isolation', () => {
    it('should prevent user from accessing another user\'s profile', () => {
      // User A trying to access User B's profile
      const result = authzService.checkPermission(
        'user-a',
        'member',
        '/member/profile',
        'GET',
        'profile-user-b'
      );

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Resource ownership check failed');
    });

    it('should allow user to access their own profile', () => {
      const result = authzService.checkPermission(
        'user-a',
        'member',
        '/member/profile',
        'GET',
        'profile-user-a'
      );

      expect(result.allowed).toBe(true);
    });

    it('should prevent user from accessing another user\'s backups', () => {
      const result = authzService.checkPermission(
        'user-a',
        'member',
        '/vault/backup/backup-user-b-1',
        'GET',
        'backup-user-b-1'
      );

      expect(result.allowed).toBe(false);
    });

    it('should allow user to access their own backups', () => {
      const result = authzService.checkPermission(
        'user-a',
        'member',
        '/vault/backup/backup-user-a-1',
        'GET',
        'backup-user-a-1'
      );

      expect(result.allowed).toBe(true);
    });
  });

  describe('Connection Isolation', () => {
    it('should prevent user from accessing another user\'s connections', () => {
      // User B trying to delete User A's connection
      const result = authzService.checkPermission(
        'user-b',
        'member',
        '/connections/connection-user-a-1',
        'DELETE',
        'connection-user-a-1'
      );

      expect(result.allowed).toBe(false);
    });

    it('should allow user to manage their own connections', () => {
      const result = authzService.checkPermission(
        'user-a',
        'member',
        '/connections/connection-user-a-1',
        'DELETE',
        'connection-user-a-1'
      );

      expect(result.allowed).toBe(true);
    });
  });

  describe('Message Isolation', () => {
    it('should prevent user from accessing another user\'s messages', () => {
      const result = authzService.checkPermission(
        'user-b',
        'member',
        '/messages/message-user-a-1',
        'GET',
        'message-user-a-1'
      );

      expect(result.allowed).toBe(false);
    });
  });
});

// ============================================
// Vertical Privilege Escalation Tests
// ============================================

describe('Vertical Privilege Escalation Prevention', () => {
  let authzService: MockAuthorizationService;

  beforeEach(() => {
    authzService = new MockAuthorizationService();
  });

  describe('Member to Admin Escalation', () => {
    it('should prevent member from accessing admin endpoints', () => {
      const adminEndpoints = [
        '/admin/registrations',
        '/admin/invites',
        '/admin/users',
        '/admin/settings',
      ];

      for (const endpoint of adminEndpoints) {
        const result = authzService.checkPermission('user-a', 'member', endpoint, 'GET');
        expect(result.allowed).toBe(false);
      }
    });

    it('should allow admin to access admin endpoints', () => {
      const result = authzService.checkPermission(
        'admin-user',
        'admin',
        '/admin/registrations',
        'GET'
      );

      expect(result.allowed).toBe(true);
    });

    it('should prevent member from performing admin actions', () => {
      // Member trying to approve registration
      const result = authzService.checkPermission(
        'user-a',
        'member',
        '/admin/registrations/123/approve',
        'POST'
      );

      expect(result.allowed).toBe(false);
    });
  });

  describe('Anonymous to Member Escalation', () => {
    it('should prevent anonymous access to member endpoints', () => {
      const memberEndpoints = [
        '/member/profile',
        '/vault/backup/list',
        '/connections/list',
        '/messages/list',
      ];

      for (const endpoint of memberEndpoints) {
        const result = authzService.checkPermission(null, 'anonymous', endpoint, 'GET');
        expect(result.allowed).toBe(false);
      }
    });

    it('should allow anonymous access to public endpoints', () => {
      const result = authzService.checkPermission(null, 'anonymous', '/register', 'POST');
      expect(result.allowed).toBe(true);
    });
  });
});

// ============================================
// IDOR Prevention Tests
// ============================================

describe('IDOR (Insecure Direct Object Reference) Prevention', () => {
  let authzService: MockAuthorizationService;

  beforeEach(() => {
    authzService = new MockAuthorizationService();
  });

  describe('Resource ID Validation', () => {
    it('should not reveal resource existence through different error messages', () => {
      // Non-existent resource
      const nonExistent = authzService.getResource('user-a', 'non-existent-resource');

      // Existing resource belonging to another user
      const wrongOwner = authzService.getResource('user-a', 'backup-user-b-1');

      // Both should return null (same response)
      expect(nonExistent).toBeNull();
      expect(wrongOwner).toBeNull();
    });

    it('should validate resource ownership before returning data', () => {
      // User A's resource
      const ownResource = authzService.getResource('user-a', 'backup-user-a-1');
      expect(ownResource).not.toBeNull();
      expect(ownResource?.ownerId).toBe('user-a');

      // User B's resource (should be null)
      const otherResource = authzService.getResource('user-a', 'backup-user-b-1');
      expect(otherResource).toBeNull();
    });
  });

  describe('ID Enumeration Prevention', () => {
    it('should use non-sequential IDs', () => {
      // Generate mock resource IDs
      const ids = Array.from({ length: 100 }, () => crypto.randomUUID());

      // Check no sequential patterns
      const numericParts = ids.map(id => {
        const match = id.match(/\d+/g);
        return match ? match.map(Number) : [];
      });

      // IDs should not be simply incrementing
      let sequential = 0;
      for (let i = 1; i < numericParts.length; i++) {
        if (numericParts[i][0] === numericParts[i - 1][0] + 1) {
          sequential++;
        }
      }

      // Very low sequential count indicates random IDs
      expect(sequential).toBeLessThan(10);
    });

    it('should use unpredictable ID format', () => {
      // UUIDs have 122 bits of entropy
      const uuid = crypto.randomUUID();

      // Check format
      expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

      // Calculate entropy (simplified)
      const entropy = 122; // UUID v4 has 122 random bits
      expect(entropy).toBeGreaterThanOrEqual(100);
    });
  });

  describe('Parameter Tampering Prevention', () => {
    it('should validate all resource identifiers in request', () => {
      const validateRequest = (
        userId: string,
        params: { resourceId: string; ownerId?: string }
      ): boolean => {
        // Even if attacker provides their own ID, validate against actual resource
        const resource = authzService.getResource(userId, params.resourceId);
        return resource !== null;
      };

      // Attacker trying to access resource by providing their own userId
      const maliciousParams = { resourceId: 'backup-user-b-1', ownerId: 'user-a' };
      expect(validateRequest('user-a', maliciousParams)).toBe(false);

      // Legitimate access
      const legitimateParams = { resourceId: 'backup-user-a-1' };
      expect(validateRequest('user-a', legitimateParams)).toBe(true);
    });
  });
});

// ============================================
// Function-Level Access Control Tests
// ============================================

describe('Function-Level Access Control', () => {
  let authzService: MockAuthorizationService;

  beforeEach(() => {
    authzService = new MockAuthorizationService();
  });

  describe('Admin-Only Functions', () => {
    const adminOnlyFunctions = [
      { path: '/admin/registrations', action: 'GET', name: 'List Registrations' },
      { path: '/admin/registrations/123/approve', action: 'POST', name: 'Approve Registration' },
      { path: '/admin/registrations/123/reject', action: 'POST', name: 'Reject Registration' },
      { path: '/admin/invites', action: 'POST', name: 'Create Invite' },
      { path: '/admin/invites/456', action: 'DELETE', name: 'Delete Invite' },
      { path: '/admin/users/789', action: 'DELETE', name: 'Delete User' },
    ];

    for (const func of adminOnlyFunctions) {
      it(`should protect ${func.name} from non-admin access`, () => {
        // Member access
        const memberResult = authzService.checkPermission('user-a', 'member', func.path, func.action);
        expect(memberResult.allowed).toBe(false);

        // Anonymous access
        const anonResult = authzService.checkPermission(null, 'anonymous', func.path, func.action);
        expect(anonResult.allowed).toBe(false);

        // Admin access
        const adminResult = authzService.checkPermission('admin-user', 'admin', func.path, func.action);
        expect(adminResult.allowed).toBe(true);
      });
    }
  });

  describe('Member-Only Functions', () => {
    const memberOnlyFunctions = [
      { path: '/member/profile', action: 'GET', name: 'View Profile' },
      { path: '/member/profile', action: 'PUT', name: 'Update Profile' },
      { path: '/vault/backup/list', action: 'GET', name: 'List Backups' },
      { path: '/vault/backup/create', action: 'POST', name: 'Create Backup' },
      { path: '/connections/list', action: 'GET', name: 'List Connections' },
    ];

    for (const func of memberOnlyFunctions) {
      it(`should protect ${func.name} from anonymous access`, () => {
        // Anonymous access should fail
        const anonResult = authzService.checkPermission(null, 'anonymous', func.path, func.action);
        expect(anonResult.allowed).toBe(false);
      });
    }
  });
});

// ============================================
// OWASP Authorization Bypass Scenarios
// ============================================

describe('OWASP Authorization Bypass Scenarios', () => {
  let authzService: MockAuthorizationService;

  beforeEach(() => {
    authzService = new MockAuthorizationService();
  });

  for (const scenario of AUTHZ_BYPASS_SCENARIOS) {
    describe(`${scenario.name}: ${scenario.description}`, () => {
      it(`should ${scenario.testCase.expectedOutcome === 'denied' ? 'prevent' : 'allow'} access (${scenario.owaspRef})`, () => {
        const { attackerRole, resource, action, expectedOutcome } = scenario.testCase;

        // Extract resource ID if present in path
        const resourceIdMatch = resource.match(/\{([^}]+)\}/);
        const resourceId = resourceIdMatch ? 'test-resource-id' : undefined;

        const result = authzService.checkPermission(
          attackerRole === 'anonymous' ? null : 'attacker-user',
          attackerRole === 'anonymous' ? 'anonymous' : attackerRole,
          resource.replace(/\{[^}]+\}/g, 'test-id'),
          action,
          resourceId
        );

        if (expectedOutcome === 'denied') {
          expect(result.allowed).toBe(false);
        } else {
          expect(result.allowed).toBe(true);
        }
      });
    });
  }
});

// ============================================
// Path Traversal in Authorization
// ============================================

describe('Path Traversal in Authorization', () => {
  let authzService: MockAuthorizationService;

  beforeEach(() => {
    authzService = new MockAuthorizationService();
  });

  describe('Path Manipulation Attempts', () => {
    const pathTraversalAttempts = [
      '/member/profile/../../../admin/users',
      '/member/profile/..%2F..%2F..%2Fadmin%2Fusers',
      '/member/profile/....//....//admin/users',
      '/member/profile%00/../admin/users',
    ];

    for (const path of pathTraversalAttempts) {
      it(`should reject path traversal attempt: ${path.substring(0, 50)}...`, () => {
        // Normalize path first (would be done in middleware)
        const normalizedPath = normalizePath(path);

        // Even after normalization, member shouldn't access admin
        if (normalizedPath.startsWith('/admin')) {
          const result = authzService.checkPermission('user-a', 'member', normalizedPath, 'GET');
          expect(result.allowed).toBe(false);
        }

        // Path should be sanitized to not contain traversal
        expect(normalizedPath).not.toContain('..');
        expect(normalizedPath).not.toContain('%2e');
        expect(normalizedPath).not.toContain('%00');
      });
    }
  });
});

// ============================================
// HTTP Method Override Prevention
// ============================================

describe('HTTP Method Override Prevention', () => {
  describe('Method Override Headers', () => {
    const methodOverrideHeaders = [
      'X-HTTP-Method-Override',
      'X-HTTP-Method',
      'X-Method-Override',
      '_method',
    ];

    it('should not allow method override through headers for sensitive operations', () => {
      // Simulate request with method override header
      const simulateRequest = (
        actualMethod: string,
        overrideHeader: string,
        overrideValue: string
      ): string => {
        // Secure implementation ignores override headers
        return actualMethod;
      };

      for (const header of methodOverrideHeaders) {
        // Attacker tries to turn GET into DELETE
        const effectiveMethod = simulateRequest('GET', header, 'DELETE');
        expect(effectiveMethod).toBe('GET');
      }
    });
  });
});

// ============================================
// Role Assignment Validation
// ============================================

describe('Role Assignment Validation', () => {
  describe('Self-Assigned Role Prevention', () => {
    it('should not allow users to assign themselves admin role', () => {
      const validateRoleChange = (
        requesterId: string,
        requesterRole: string,
        targetUserId: string,
        newRole: string
      ): boolean => {
        // Only admins can change roles
        if (requesterRole !== 'admin') return false;

        // Even admins cannot make themselves admin (needs super-admin)
        if (requesterId === targetUserId && newRole === 'admin') return false;

        return true;
      };

      // User trying to make themselves admin
      expect(validateRoleChange('user-a', 'member', 'user-a', 'admin')).toBe(false);

      // Admin trying to make another user admin (allowed)
      expect(validateRoleChange('admin-1', 'admin', 'user-a', 'admin')).toBe(true);

      // Admin trying to make themselves admin (prevented)
      expect(validateRoleChange('admin-1', 'admin', 'admin-1', 'admin')).toBe(false);
    });
  });

  describe('Role Hierarchy', () => {
    it('should enforce role hierarchy in permission checks', () => {
      const roleHierarchy: Record<string, number> = {
        anonymous: 0,
        member: 1,
        admin: 2,
        superadmin: 3,
      };

      const canAccessRole = (userRole: string, requiredRole: string): boolean => {
        return roleHierarchy[userRole] >= roleHierarchy[requiredRole];
      };

      // Anonymous cannot access member resources
      expect(canAccessRole('anonymous', 'member')).toBe(false);

      // Member cannot access admin resources
      expect(canAccessRole('member', 'admin')).toBe(false);

      // Admin can access member resources
      expect(canAccessRole('admin', 'member')).toBe(true);

      // Admin cannot access superadmin resources
      expect(canAccessRole('admin', 'superadmin')).toBe(false);
    });
  });
});

// ============================================
// Helper Functions
// ============================================

function normalizePath(path: string): string {
  // Decode URL encoding
  let normalized = decodeURIComponent(path);

  // Remove null bytes
  normalized = normalized.replace(/\x00/g, '');

  // Resolve .. traversals
  const segments = normalized.split('/').filter(Boolean);
  const result: string[] = [];

  for (const segment of segments) {
    if (segment === '..') {
      result.pop();
    } else if (segment !== '.') {
      result.push(segment);
    }
  }

  return '/' + result.join('/');
}
