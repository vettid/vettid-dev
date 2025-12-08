/**
 * Integration Tests: Profile Update Handler
 *
 * Tests the first-party profile update handler:
 * - Update profile fields
 * - Publish profile to MessageSpace
 * - Schema validation
 * - Version tracking
 *
 * @see vault-manager/internal/handlers/builtin/profile.go (pending implementation)
 */

import * as crypto from 'crypto';
import {
  createProfileHandlerPackage,
  createExecutionContext,
} from '../../fixtures/handlers/mockHandler';

// ============================================
// Types
// ============================================

interface Profile {
  user_id: string;
  display_name: string;
  bio?: string;
  avatar_url?: string;
  public_key: string;
  created_at: string;
  updated_at: string;
  version: number;
  published: boolean;
}

interface ProfileUpdateInput {
  display_name?: string;
  bio?: string;
  avatar_url?: string;
}

interface ProfileUpdateResult {
  success: boolean;
  profile?: Profile;
  error?: string;
  version?: number;
  published?: boolean;
}

// ============================================
// Mock Profile Service
// ============================================

class MockProfileService {
  private profiles: Map<string, Profile> = new Map();
  private publishedProfiles: Map<string, Profile> = new Map(); // MessageSpace simulation
  private allowedFields = ['display_name', 'bio', 'avatar_url'];
  private maxDisplayNameLength = 100;
  private maxBioLength = 500;

  /**
   * Create initial profile
   */
  createProfile(userId: string, publicKey: string): Profile {
    const now = new Date().toISOString();
    const profile: Profile = {
      user_id: userId,
      display_name: 'New User',
      public_key: publicKey,
      created_at: now,
      updated_at: now,
      version: 1,
      published: false,
    };
    this.profiles.set(userId, profile);
    return profile;
  }

  /**
   * Get profile
   */
  getProfile(userId: string): Profile | undefined {
    return this.profiles.get(userId);
  }

  /**
   * Update profile
   */
  async updateProfile(
    userId: string,
    updates: ProfileUpdateInput
  ): Promise<ProfileUpdateResult> {
    const profile = this.profiles.get(userId);
    if (!profile) {
      return { success: false, error: 'Profile not found' };
    }

    // Validate updates
    const validationError = this.validateUpdates(updates);
    if (validationError) {
      return { success: false, error: validationError };
    }

    // Check for unauthorized fields
    const unauthorizedFields = Object.keys(updates).filter(
      key => !this.allowedFields.includes(key)
    );
    if (unauthorizedFields.length > 0) {
      return {
        success: false,
        error: `Unauthorized fields: ${unauthorizedFields.join(', ')}`,
      };
    }

    // Apply updates
    if (updates.display_name !== undefined) {
      profile.display_name = updates.display_name;
    }
    if (updates.bio !== undefined) {
      profile.bio = updates.bio;
    }
    if (updates.avatar_url !== undefined) {
      profile.avatar_url = updates.avatar_url;
    }

    // Increment version
    profile.version++;
    profile.updated_at = new Date().toISOString();

    // Publish to MessageSpace
    await this.publishProfile(userId);

    return {
      success: true,
      profile: { ...profile },
      version: profile.version,
      published: profile.published,
    };
  }

  /**
   * Validate profile updates
   */
  private validateUpdates(updates: ProfileUpdateInput): string | null {
    if (updates.display_name !== undefined) {
      if (typeof updates.display_name !== 'string') {
        return 'display_name must be a string';
      }
      if (updates.display_name.length > this.maxDisplayNameLength) {
        return `display_name exceeds maximum length of ${this.maxDisplayNameLength}`;
      }
      if (updates.display_name.trim().length === 0) {
        return 'display_name cannot be empty';
      }
    }

    if (updates.bio !== undefined) {
      if (typeof updates.bio !== 'string') {
        return 'bio must be a string';
      }
      if (updates.bio.length > this.maxBioLength) {
        return `bio exceeds maximum length of ${this.maxBioLength}`;
      }
    }

    if (updates.avatar_url !== undefined) {
      if (typeof updates.avatar_url !== 'string') {
        return 'avatar_url must be a string';
      }
      // Validate URL format
      try {
        new URL(updates.avatar_url);
      } catch {
        return 'avatar_url must be a valid URL';
      }
    }

    return null;
  }

  /**
   * Publish profile to MessageSpace
   */
  private async publishProfile(userId: string): Promise<void> {
    const profile = this.profiles.get(userId);
    if (!profile) return;

    // Simulate publishing to MessageSpace
    this.publishedProfiles.set(userId, { ...profile, published: true });
    profile.published = true;
  }

  /**
   * Get published profile from MessageSpace
   */
  getPublishedProfile(userId: string): Profile | undefined {
    return this.publishedProfiles.get(userId);
  }

  /**
   * Get profile version history count
   */
  getVersionCount(userId: string): number {
    const profile = this.profiles.get(userId);
    return profile?.version || 0;
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.profiles.clear();
    this.publishedProfiles.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Profile Update Handler', () => {
  let profileService: MockProfileService;
  const testUserId = 'user-profile-123';
  const testPublicKey = 'public-key-abc123';

  beforeEach(() => {
    profileService = new MockProfileService();
    profileService.createProfile(testUserId, testPublicKey);
  });

  afterEach(() => {
    profileService.clear();
  });

  it('should update profile fields', async () => {
    const result = await profileService.updateProfile(testUserId, {
      display_name: 'John Doe',
      bio: 'Software developer',
    });

    expect(result.success).toBe(true);
    expect(result.profile?.display_name).toBe('John Doe');
    expect(result.profile?.bio).toBe('Software developer');
  });

  it('should publish profile to MessageSpace', async () => {
    await profileService.updateProfile(testUserId, {
      display_name: 'Published User',
    });

    const published = profileService.getPublishedProfile(testUserId);

    expect(published).toBeDefined();
    expect(published?.display_name).toBe('Published User');
    expect(published?.published).toBe(true);
  });

  it('should validate profile schema', async () => {
    // Valid update
    const validResult = await profileService.updateProfile(testUserId, {
      display_name: 'Valid Name',
      bio: 'A valid bio',
      avatar_url: 'https://example.com/avatar.png',
    });
    expect(validResult.success).toBe(true);

    // Invalid avatar URL
    const invalidUrlResult = await profileService.updateProfile(testUserId, {
      avatar_url: 'not-a-valid-url',
    });
    expect(invalidUrlResult.success).toBe(false);
    expect(invalidUrlResult.error).toContain('valid URL');
  });

  it('should reject unauthorized fields', async () => {
    const result = await profileService.updateProfile(testUserId, {
      display_name: 'Valid',
      public_key: 'attempt-to-change-public-key', // Not allowed
    } as ProfileUpdateInput);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Unauthorized');
    expect(result.error).toContain('public_key');
  });

  it('should version profile updates', async () => {
    const initialProfile = profileService.getProfile(testUserId);
    expect(initialProfile?.version).toBe(1);

    await profileService.updateProfile(testUserId, { display_name: 'Update 1' });
    expect(profileService.getVersionCount(testUserId)).toBe(2);

    await profileService.updateProfile(testUserId, { display_name: 'Update 2' });
    expect(profileService.getVersionCount(testUserId)).toBe(3);

    await profileService.updateProfile(testUserId, { display_name: 'Update 3' });
    expect(profileService.getVersionCount(testUserId)).toBe(4);
  });

  it('should validate display_name length', async () => {
    const longName = 'x'.repeat(150); // Exceeds 100 char limit

    const result = await profileService.updateProfile(testUserId, {
      display_name: longName,
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('maximum length');
  });

  it('should validate bio length', async () => {
    const longBio = 'x'.repeat(600); // Exceeds 500 char limit

    const result = await profileService.updateProfile(testUserId, {
      bio: longBio,
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('maximum length');
  });

  it('should reject empty display_name', async () => {
    const result = await profileService.updateProfile(testUserId, {
      display_name: '   ', // Only whitespace
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('empty');
  });

  it('should allow partial updates', async () => {
    // Set initial values
    await profileService.updateProfile(testUserId, {
      display_name: 'Initial Name',
      bio: 'Initial Bio',
    });

    // Update only display_name
    const result = await profileService.updateProfile(testUserId, {
      display_name: 'New Name',
    });

    expect(result.success).toBe(true);
    expect(result.profile?.display_name).toBe('New Name');
    expect(result.profile?.bio).toBe('Initial Bio'); // Unchanged
  });

  it('should update timestamp on each change', async () => {
    const beforeUpdate = profileService.getProfile(testUserId)?.updated_at;

    await new Promise(resolve => setTimeout(resolve, 10));
    await profileService.updateProfile(testUserId, { display_name: 'Updated' });

    const afterUpdate = profileService.getProfile(testUserId)?.updated_at;

    expect(afterUpdate).not.toBe(beforeUpdate);
  });

  it('should return error for non-existent profile', async () => {
    const result = await profileService.updateProfile('non-existent-user', {
      display_name: 'Test',
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('not found');
  });

  it('should preserve public_key on updates', async () => {
    const originalProfile = profileService.getProfile(testUserId);
    const originalPublicKey = originalProfile?.public_key;

    await profileService.updateProfile(testUserId, {
      display_name: 'New Name',
    });

    const updatedProfile = profileService.getProfile(testUserId);
    expect(updatedProfile?.public_key).toBe(originalPublicKey);
  });

  it('should preserve created_at on updates', async () => {
    const originalProfile = profileService.getProfile(testUserId);
    const originalCreatedAt = originalProfile?.created_at;

    await profileService.updateProfile(testUserId, {
      display_name: 'New Name',
    });

    const updatedProfile = profileService.getProfile(testUserId);
    expect(updatedProfile?.created_at).toBe(originalCreatedAt);
  });

  it('should handle unicode in profile fields', async () => {
    const unicodeName = '田中太郎 🎉';
    const unicodeBio = '日本語でプロフィール 📝 Привет!';

    const result = await profileService.updateProfile(testUserId, {
      display_name: unicodeName,
      bio: unicodeBio,
    });

    expect(result.success).toBe(true);
    expect(result.profile?.display_name).toBe(unicodeName);
    expect(result.profile?.bio).toBe(unicodeBio);
  });

  it('should return new version number in result', async () => {
    const result = await profileService.updateProfile(testUserId, {
      display_name: 'Versioned Update',
    });

    expect(result.version).toBe(2);
  });

  it('should indicate published status in result', async () => {
    const result = await profileService.updateProfile(testUserId, {
      display_name: 'Published',
    });

    expect(result.published).toBe(true);
  });
});
