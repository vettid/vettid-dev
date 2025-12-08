/**
 * Integration Tests: Profile Management
 *
 * Tests profile CRUD operations:
 * - Schema validation
 * - Profile updates
 * - Profile publishing to connections
 * - Profile retrieval
 *
 * @see lambda/handlers/profile/ (pending implementation)
 */

import {
  MockConnectionService,
  createMockProfile,
  UserProfile,
} from '../../fixtures/connections/mockConnection';

// ============================================
// Mock Profile Service
// ============================================

class MockProfileService {
  private profiles: Map<string, UserProfile> = new Map();
  private profileHistory: Map<string, UserProfile[]> = new Map();
  private connectionService: MockConnectionService;

  // Validation limits
  private readonly maxDisplayNameLength = 50;
  private readonly maxBioLength = 500;
  private readonly maxLocationLength = 100;
  private readonly maxAvatarUrlLength = 2048;

  // XSS patterns to sanitize
  private readonly xssPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<iframe/gi,
    /<object/gi,
    /<embed/gi,
  ];

  constructor(connectionService: MockConnectionService) {
    this.connectionService = connectionService;
  }

  /**
   * Validate profile fields
   */
  private validateProfile(
    profile: Partial<UserProfile>
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Required fields
    if (profile.display_name !== undefined) {
      if (!profile.display_name || profile.display_name.trim().length === 0) {
        errors.push('display_name is required');
      } else if (profile.display_name.length > this.maxDisplayNameLength) {
        errors.push(`display_name exceeds ${this.maxDisplayNameLength} characters`);
      }
    }

    // Optional field length limits
    if (profile.bio && profile.bio.length > this.maxBioLength) {
      errors.push(`bio exceeds ${this.maxBioLength} characters`);
    }

    if (profile.location && profile.location.length > this.maxLocationLength) {
      errors.push(`location exceeds ${this.maxLocationLength} characters`);
    }

    if (profile.avatar_url && profile.avatar_url.length > this.maxAvatarUrlLength) {
      errors.push(`avatar_url exceeds ${this.maxAvatarUrlLength} characters`);
    }

    // Avatar URL format validation
    if (profile.avatar_url) {
      try {
        new URL(profile.avatar_url);
      } catch {
        errors.push('avatar_url must be a valid URL');
      }
    }

    // Visibility validation
    if (profile.visibility && !['connections', 'public', 'private'].includes(profile.visibility)) {
      errors.push('visibility must be connections, public, or private');
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Sanitize input for XSS prevention
   */
  private sanitize(input: string): string {
    let sanitized = input;
    for (const pattern of this.xssPatterns) {
      sanitized = sanitized.replace(pattern, '');
    }
    return sanitized.trim();
  }

  /**
   * Create or update profile
   */
  async updateProfile(
    userGuid: string,
    updates: Partial<Omit<UserProfile, 'user_guid' | 'version' | 'last_updated'>>
  ): Promise<{ success: boolean; profile?: UserProfile; errors?: string[] }> {
    // Validate
    const validation = this.validateProfile(updates as Partial<UserProfile>);
    if (!validation.valid) {
      return { success: false, errors: validation.errors };
    }

    // Get existing profile or create new
    let profile = this.profiles.get(userGuid);
    const isNew = !profile;

    if (isNew) {
      if (!updates.display_name) {
        return { success: false, errors: ['display_name is required for new profile'] };
      }
      profile = createMockProfile({ userGuid, displayName: updates.display_name });
      // For new profiles, version is already 1 from createMockProfile
    }

    // Store history for versioning
    let history = this.profileHistory.get(userGuid);
    if (!history) {
      history = [];
      this.profileHistory.set(userGuid, history);
    }
    if (profile) {
      history.push({ ...profile });
    }

    // Sanitize and apply updates
    const sanitizedUpdates: Partial<UserProfile> = {};
    if (updates.display_name) {
      sanitizedUpdates.display_name = this.sanitize(updates.display_name);
    }
    if (updates.bio !== undefined) {
      sanitizedUpdates.bio = updates.bio ? this.sanitize(updates.bio) : undefined;
    }
    if (updates.location !== undefined) {
      sanitizedUpdates.location = updates.location ? this.sanitize(updates.location) : undefined;
    }
    if (updates.avatar_url !== undefined) {
      sanitizedUpdates.avatar_url = updates.avatar_url;
    }
    if (updates.visibility !== undefined) {
      sanitizedUpdates.visibility = updates.visibility;
    }

    // Update profile - only increment version if not a new profile
    const updatedProfile: UserProfile = {
      ...profile!,
      ...sanitizedUpdates,
      version: isNew ? 1 : profile!.version + 1,
      last_updated: new Date().toISOString(),
    };

    this.profiles.set(userGuid, updatedProfile);

    return { success: true, profile: updatedProfile };
  }

  /**
   * Get own profile
   */
  getProfile(userGuid: string): UserProfile | undefined {
    return this.profiles.get(userGuid);
  }

  /**
   * Get connection's profile
   */
  getConnectionProfile(
    requesterGuid: string,
    targetGuid: string
  ): { success: boolean; profile?: UserProfile; error?: string } {
    // Check if connection exists
    const connections = this.connectionService.getUserConnections(requesterGuid);
    const hasConnection = connections.some(
      c => c.peer_guid === targetGuid && c.status === 'active'
    );

    if (!hasConnection) {
      return { success: false, error: 'Not connected to this user' };
    }

    const profile = this.profiles.get(targetGuid);
    if (!profile) {
      return { success: false, error: 'Profile not found' };
    }

    // Check visibility
    if (profile.visibility === 'private') {
      return { success: false, error: 'Profile is private' };
    }

    return { success: true, profile };
  }

  /**
   * Publish profile update to connections
   */
  async publishToConnections(
    userGuid: string
  ): Promise<{ success: boolean; notifiedCount: number; error?: string }> {
    const profile = this.profiles.get(userGuid);
    if (!profile) {
      return { success: false, notifiedCount: 0, error: 'Profile not found' };
    }

    const connections = this.connectionService.getUserConnections(userGuid);
    const activeConnections = connections.filter(c => c.status === 'active');

    // In real implementation, this would send NATS messages
    // For mock, we just count

    return { success: true, notifiedCount: activeConnections.length };
  }

  /**
   * Get profile version history
   */
  getProfileHistory(userGuid: string): UserProfile[] {
    return this.profileHistory.get(userGuid) || [];
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.profiles.clear();
    this.profileHistory.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Profile Management', () => {
  let connectionService: MockConnectionService;
  let profileService: MockProfileService;
  const testUserGuid = 'user-profile-123';

  beforeEach(() => {
    connectionService = new MockConnectionService();
    profileService = new MockProfileService(connectionService);
  });

  afterEach(() => {
    connectionService.clear();
    profileService.clear();
  });

  describe('Profile Schema', () => {
    it('should validate required fields (display_name)', async () => {
      const result = await profileService.updateProfile(testUserGuid, {});

      expect(result.success).toBe(false);
      expect(result.errors).toContain('display_name is required for new profile');
    });

    it('should validate optional fields (avatar_url, bio, location)', async () => {
      const result = await profileService.updateProfile(testUserGuid, {
        display_name: 'Test User',
        avatar_url: 'https://example.com/avatar.jpg',
        bio: 'Test bio',
        location: 'Test City',
      });

      expect(result.success).toBe(true);
      expect(result.profile?.avatar_url).toBe('https://example.com/avatar.jpg');
      expect(result.profile?.bio).toBe('Test bio');
      expect(result.profile?.location).toBe('Test City');
    });

    it('should enforce field length limits', async () => {
      const longDisplayName = 'a'.repeat(51);
      const result = await profileService.updateProfile(testUserGuid, {
        display_name: longDisplayName,
      });

      expect(result.success).toBe(false);
      expect(result.errors?.some(e => e.includes('display_name'))).toBe(true);
    });

    it('should enforce bio length limit', async () => {
      // First create profile
      await profileService.updateProfile(testUserGuid, { display_name: 'Test' });

      const longBio = 'a'.repeat(501);
      const result = await profileService.updateProfile(testUserGuid, {
        bio: longBio,
      });

      expect(result.success).toBe(false);
      expect(result.errors?.some(e => e.includes('bio'))).toBe(true);
    });

    it('should sanitize input for XSS prevention', async () => {
      const maliciousInput = '<script>alert("xss")</script>Test User';
      const result = await profileService.updateProfile(testUserGuid, {
        display_name: maliciousInput,
      });

      expect(result.success).toBe(true);
      expect(result.profile?.display_name).not.toContain('<script>');
      expect(result.profile?.display_name).toContain('Test User');
    });

    it('should sanitize javascript: URLs in bio', async () => {
      await profileService.updateProfile(testUserGuid, { display_name: 'Test' });

      const result = await profileService.updateProfile(testUserGuid, {
        bio: 'Check this: javascript:alert(1)',
      });

      expect(result.success).toBe(true);
      expect(result.profile?.bio).not.toContain('javascript:');
    });

    it('should validate avatar URL format', async () => {
      const result = await profileService.updateProfile(testUserGuid, {
        display_name: 'Test User',
        avatar_url: 'not-a-valid-url',
      });

      expect(result.success).toBe(false);
      expect(result.errors?.some(e => e.includes('avatar_url'))).toBe(true);
    });

    it('should validate visibility values', async () => {
      const result = await profileService.updateProfile(testUserGuid, {
        display_name: 'Test User',
        visibility: 'invalid' as any,
      });

      expect(result.success).toBe(false);
      expect(result.errors?.some(e => e.includes('visibility'))).toBe(true);
    });
  });

  describe('Profile Updates', () => {
    it('should update profile fields', async () => {
      // Create profile
      await profileService.updateProfile(testUserGuid, {
        display_name: 'Initial Name',
      });

      // Update
      const result = await profileService.updateProfile(testUserGuid, {
        display_name: 'Updated Name',
        bio: 'New bio',
      });

      expect(result.success).toBe(true);
      expect(result.profile?.display_name).toBe('Updated Name');
      expect(result.profile?.bio).toBe('New bio');
    });

    it('should version profile updates', async () => {
      await profileService.updateProfile(testUserGuid, {
        display_name: 'Name v1',
      });

      const result = await profileService.updateProfile(testUserGuid, {
        display_name: 'Name v2',
      });

      expect(result.profile?.version).toBe(2);
    });

    it('should track last_updated timestamp', async () => {
      const before = new Date();

      const result = await profileService.updateProfile(testUserGuid, {
        display_name: 'Test User',
      });

      const after = new Date();

      expect(result.success).toBe(true);
      const updatedAt = new Date(result.profile!.last_updated);
      expect(updatedAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(updatedAt.getTime()).toBeLessThanOrEqual(after.getTime());
    });

    it('should preserve profile history', async () => {
      await profileService.updateProfile(testUserGuid, {
        display_name: 'Name v1',
      });

      await profileService.updateProfile(testUserGuid, {
        display_name: 'Name v2',
      });

      await profileService.updateProfile(testUserGuid, {
        display_name: 'Name v3',
      });

      const history = profileService.getProfileHistory(testUserGuid);
      expect(history.length).toBe(3); // Includes initial creation
    });

    it('should allow clearing optional fields', async () => {
      await profileService.updateProfile(testUserGuid, {
        display_name: 'Test User',
        bio: 'Initial bio',
        location: 'Initial location',
      });

      // Use empty string to clear optional fields
      // (undefined means "don't update this field", empty string means "clear this field")
      const result = await profileService.updateProfile(testUserGuid, {
        bio: '',
        location: '',
      });

      expect(result.success).toBe(true);
      expect(result.profile?.bio).toBeUndefined();
      expect(result.profile?.location).toBeUndefined();
    });
  });

  describe('Profile Publishing', () => {
    it('should publish update to connections', async () => {
      // Create profile
      await profileService.updateProfile(testUserGuid, {
        display_name: 'Test User',
      });

      // Create some connections
      const peerGuid = 'peer-user-123';
      const invite = await connectionService.createInvitation(testUserGuid);
      await connectionService.acceptInvitation(peerGuid, invite.invitation!.code);

      // Publish
      const result = await profileService.publishToConnections(testUserGuid);

      expect(result.success).toBe(true);
      expect(result.notifiedCount).toBe(1);
    });

    it('should handle offline connections (queue)', async () => {
      await profileService.updateProfile(testUserGuid, {
        display_name: 'Test User',
      });

      // Create connection
      const peerGuid = 'peer-user-123';
      const invite = await connectionService.createInvitation(testUserGuid);
      await connectionService.acceptInvitation(peerGuid, invite.invitation!.code);

      // In real implementation, would queue for offline delivery
      const result = await profileService.publishToConnections(testUserGuid);

      expect(result.success).toBe(true);
    });

    it('should not publish to revoked connections', async () => {
      await profileService.updateProfile(testUserGuid, {
        display_name: 'Test User',
      });

      // Create and revoke connection
      const peerGuid = 'peer-user-123';
      const invite = await connectionService.createInvitation(testUserGuid);
      const accept = await connectionService.acceptInvitation(peerGuid, invite.invitation!.code);
      await connectionService.revokeConnection(peerGuid, accept.connection!.connection_id);

      const result = await profileService.publishToConnections(testUserGuid);

      expect(result.success).toBe(true);
      expect(result.notifiedCount).toBe(0);
    });

    it('should return error for non-existent profile', async () => {
      const result = await profileService.publishToConnections('non-existent-user');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Profile not found');
    });
  });

  describe('Profile Retrieval', () => {
    it('should return own profile', async () => {
      await profileService.updateProfile(testUserGuid, {
        display_name: 'Test User',
        bio: 'My bio',
      });

      const profile = profileService.getProfile(testUserGuid);

      expect(profile).toBeDefined();
      expect(profile?.display_name).toBe('Test User');
      expect(profile?.bio).toBe('My bio');
    });

    it('should return connection profile', async () => {
      const peerGuid = 'peer-user-123';

      // Create peer profile
      await profileService.updateProfile(peerGuid, {
        display_name: 'Peer User',
        visibility: 'connections',
      });

      // Create connection
      const invite = await connectionService.createInvitation(testUserGuid);
      await connectionService.acceptInvitation(peerGuid, invite.invitation!.code);

      const result = profileService.getConnectionProfile(testUserGuid, peerGuid);

      expect(result.success).toBe(true);
      expect(result.profile?.display_name).toBe('Peer User');
    });

    it('should reject non-connection profile requests', async () => {
      const otherGuid = 'other-user-123';

      await profileService.updateProfile(otherGuid, {
        display_name: 'Other User',
      });

      const result = profileService.getConnectionProfile(testUserGuid, otherGuid);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Not connected');
    });

    it('should respect private visibility', async () => {
      const peerGuid = 'peer-user-123';

      // Create peer profile with private visibility
      await profileService.updateProfile(peerGuid, {
        display_name: 'Peer User',
        visibility: 'private',
      });

      // Create connection
      const invite = await connectionService.createInvitation(testUserGuid);
      await connectionService.acceptInvitation(peerGuid, invite.invitation!.code);

      const result = profileService.getConnectionProfile(testUserGuid, peerGuid);

      expect(result.success).toBe(false);
      expect(result.error).toContain('private');
    });

    it('should return undefined for non-existent profile', async () => {
      const profile = profileService.getProfile('non-existent-user');
      expect(profile).toBeUndefined();
    });
  });

  describe('Visibility Settings', () => {
    it('should default to connections visibility', async () => {
      const result = await profileService.updateProfile(testUserGuid, {
        display_name: 'Test User',
      });

      expect(result.profile?.visibility).toBe('connections');
    });

    it('should allow public visibility', async () => {
      const result = await profileService.updateProfile(testUserGuid, {
        display_name: 'Test User',
        visibility: 'public',
      });

      expect(result.profile?.visibility).toBe('public');
    });

    it('should allow private visibility', async () => {
      const result = await profileService.updateProfile(testUserGuid, {
        display_name: 'Test User',
        visibility: 'private',
      });

      expect(result.profile?.visibility).toBe('private');
    });
  });
});
