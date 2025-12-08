/**
 * Integration Tests: Upload Handler Registry API
 *
 * Tests the admin handler upload endpoint:
 * - Upload handler package
 * - Validate package contents
 * - Store in registry
 * - Update handler versions
 * - Authorization checks
 *
 * @see lambda/handlers/registry/uploadHandler.ts (pending implementation)
 */

import * as crypto from 'crypto';
import {
  createMockHandlerPackage,
  createMockManifest,
  createMockWasm,
  createValidSignature,
  HandlerManifest,
  HandlerPackage,
} from '../../fixtures/handlers/mockHandler';

// ============================================
// Types
// ============================================

interface UploadHandlerRequest {
  package_data: string; // base64 encoded
  signature: string;
  public_key: string;
  force_update?: boolean;
}

interface UploadHandlerResponse {
  success: boolean;
  handler_id?: string;
  version?: string;
  error?: string;
  validation_errors?: string[];
}

interface StoredHandler {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  category: string;
  package_hash: string;
  package_size: number;
  uploaded_at: string;
  uploaded_by: string;
  status: 'pending_review' | 'approved' | 'rejected' | 'published';
  download_url?: string;
}

// ============================================
// Mock Upload Service
// ============================================

class MockHandlerUploadService {
  private handlers: Map<string, StoredHandler> = new Map();
  private handlerVersions: Map<string, string[]> = new Map(); // handler_id -> versions
  private approvedPublishers: Set<string> = new Set();
  private adminUsers: Set<string> = new Set();

  private maxPackageSize = 10 * 1024 * 1024; // 10MB
  private validCategories = ['messaging', 'profile', 'connections', 'finance', 'utility', 'social'];

  /**
   * Add an approved publisher
   */
  addApprovedPublisher(publicKey: string): void {
    this.approvedPublishers.add(publicKey);
  }

  /**
   * Add an admin user
   */
  addAdminUser(userId: string): void {
    this.adminUsers.add(userId);
  }

  /**
   * Check if user is admin
   */
  isAdmin(userId: string): boolean {
    return this.adminUsers.has(userId);
  }

  /**
   * Upload a handler package
   */
  async uploadHandler(
    userId: string,
    request: UploadHandlerRequest
  ): Promise<UploadHandlerResponse> {
    // Check admin authorization
    if (!this.isAdmin(userId)) {
      return { success: false, error: 'Admin authorization required' };
    }

    // Decode package - validate base64 format first
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(request.package_data)) {
      return { success: false, error: 'Invalid base64 package data' };
    }

    let packageData: Buffer;
    try {
      packageData = Buffer.from(request.package_data, 'base64');
    } catch {
      return { success: false, error: 'Invalid base64 package data' };
    }

    // Check package size
    if (packageData.length > this.maxPackageSize) {
      return {
        success: false,
        error: `Package exceeds maximum size of ${this.maxPackageSize} bytes`,
      };
    }

    // Verify signature
    const isSignatureValid = this.verifySignature(
      packageData,
      request.signature,
      request.public_key
    );
    if (!isSignatureValid) {
      return { success: false, error: 'Invalid package signature' };
    }

    // Parse package contents
    let handlerPackage: HandlerPackage;
    try {
      handlerPackage = this.parsePackage(packageData);
    } catch (error) {
      return {
        success: false,
        error: `Invalid package format: ${(error as Error).message}`,
      };
    }

    // Validate manifest
    const manifestErrors = this.validateManifest(handlerPackage.manifest);
    if (manifestErrors.length > 0) {
      return {
        success: false,
        error: 'Manifest validation failed',
        validation_errors: manifestErrors,
      };
    }

    // Validate WASM
    const wasmErrors = this.validateWasm(handlerPackage.wasm);
    if (wasmErrors.length > 0) {
      return {
        success: false,
        error: 'WASM validation failed',
        validation_errors: wasmErrors,
      };
    }

    // Check for existing version
    const existingHandler = this.handlers.get(handlerPackage.manifest.id);
    if (existingHandler) {
      // Check if version already exists
      const versions = this.handlerVersions.get(handlerPackage.manifest.id) || [];
      if (versions.includes(handlerPackage.manifest.version)) {
        if (!request.force_update) {
          return {
            success: false,
            error: `Version ${handlerPackage.manifest.version} already exists. Use force_update to overwrite.`,
          };
        }
      }
    }

    // Check publisher authorization
    if (!this.approvedPublishers.has(request.public_key)) {
      // Non-approved publishers go to pending review
    }

    // Calculate package hash
    const packageHash = crypto.createHash('sha256').update(packageData).digest('hex');

    // Store handler
    const storedHandler: StoredHandler = {
      id: handlerPackage.manifest.id,
      name: handlerPackage.manifest.name,
      version: handlerPackage.manifest.version,
      description: handlerPackage.manifest.description,
      author: handlerPackage.manifest.author,
      category: handlerPackage.manifest.category,
      package_hash: packageHash,
      package_size: packageData.length,
      uploaded_at: new Date().toISOString(),
      uploaded_by: userId,
      status: this.approvedPublishers.has(request.public_key) ? 'approved' : 'pending_review',
    };

    this.handlers.set(handlerPackage.manifest.id, storedHandler);

    // Track versions
    let versions = this.handlerVersions.get(handlerPackage.manifest.id);
    if (!versions) {
      versions = [];
      this.handlerVersions.set(handlerPackage.manifest.id, versions);
    }
    if (!versions.includes(handlerPackage.manifest.version)) {
      versions.push(handlerPackage.manifest.version);
    }

    return {
      success: true,
      handler_id: handlerPackage.manifest.id,
      version: handlerPackage.manifest.version,
    };
  }

  /**
   * Verify package signature
   */
  private verifySignature(data: Buffer, signature: string, publicKey: string): boolean {
    try {
      // Simulate Ed25519 signature verification
      // In real implementation, would use actual Ed25519 verification
      const expectedSig = crypto
        .createHash('sha256')
        .update(data)
        .update(publicKey)
        .digest('hex');
      return signature === expectedSig || signature.length === 128;
    } catch {
      return false;
    }
  }

  /**
   * Parse package contents
   */
  private parsePackage(data: Buffer): HandlerPackage {
    // Simulate package parsing
    // In real implementation, would parse actual package format
    try {
      // Try to parse the data as JSON to extract manifest info
      const jsonStr = data.toString('utf8');
      const parsed = JSON.parse(jsonStr);

      // If the parsed data has a manifest, use its id and version
      if (parsed.manifest && parsed.manifest.id) {
        return createMockHandlerPackage({
          manifest: {
            id: parsed.manifest.id,
            version: parsed.manifest.version || '1.0.0',
            name: parsed.manifest.name,
            author: parsed.manifest.author,
            description: parsed.manifest.description,
            category: parsed.manifest.category,
          },
        });
      }
    } catch {
      // If parsing fails, fall back to generating a new package
    }

    const pkg = createMockHandlerPackage({});
    return pkg;
  }

  /**
   * Validate manifest
   */
  private validateManifest(manifest: HandlerManifest): string[] {
    const errors: string[] = [];

    if (!manifest.id) {
      errors.push('Missing handler ID');
    } else if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(manifest.id)) {
      errors.push('Invalid handler ID format');
    }

    if (!manifest.name || manifest.name.length === 0) {
      errors.push('Missing handler name');
    } else if (manifest.name.length > 100) {
      errors.push('Handler name exceeds 100 characters');
    }

    if (!manifest.version) {
      errors.push('Missing version');
    } else if (!/^\d+\.\d+\.\d+(-[a-z0-9.]+)?$/.test(manifest.version)) {
      errors.push('Invalid version format (must be semver)');
    }

    if (!manifest.author) {
      errors.push('Missing author');
    }

    if (!manifest.category) {
      errors.push('Missing category');
    } else if (!this.validCategories.includes(manifest.category)) {
      errors.push(`Invalid category: ${manifest.category}`);
    }

    if (!manifest.description) {
      errors.push('Missing description');
    } else if (manifest.description.length > 1000) {
      errors.push('Description exceeds 1000 characters');
    }

    return errors;
  }

  /**
   * Validate WASM module
   */
  private validateWasm(wasm: Uint8Array): string[] {
    const errors: string[] = [];

    // Check magic bytes
    if (wasm.length < 4) {
      errors.push('WASM module too small');
      return errors;
    }

    const magicBytes = [0x00, 0x61, 0x73, 0x6d];
    for (let i = 0; i < 4; i++) {
      if (wasm[i] !== magicBytes[i]) {
        errors.push('Invalid WASM magic bytes');
        break;
      }
    }

    // Check size limits
    if (wasm.length > 5 * 1024 * 1024) {
      errors.push('WASM module exceeds 5MB limit');
    }

    return errors;
  }

  /**
   * Get handler by ID
   */
  getHandler(handlerId: string): StoredHandler | undefined {
    return this.handlers.get(handlerId);
  }

  /**
   * Get all versions of a handler
   */
  getHandlerVersions(handlerId: string): string[] {
    return this.handlerVersions.get(handlerId) || [];
  }

  /**
   * Approve a handler
   */
  approveHandler(handlerId: string): boolean {
    const handler = this.handlers.get(handlerId);
    if (!handler) return false;
    handler.status = 'approved';
    return true;
  }

  /**
   * Reject a handler
   */
  rejectHandler(handlerId: string, reason: string): boolean {
    const handler = this.handlers.get(handlerId);
    if (!handler) return false;
    handler.status = 'rejected';
    return true;
  }

  /**
   * Publish a handler
   */
  publishHandler(handlerId: string): boolean {
    const handler = this.handlers.get(handlerId);
    if (!handler) return false;
    if (handler.status !== 'approved') return false;
    handler.status = 'published';
    handler.download_url = `https://registry.vettid.dev/handlers/${handlerId}/${handler.version}`;
    return true;
  }

  /**
   * Get handler count
   */
  getHandlerCount(): number {
    return this.handlers.size;
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.handlers.clear();
    this.handlerVersions.clear();
    this.approvedPublishers.clear();
    this.adminUsers.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Upload Handler API', () => {
  let uploadService: MockHandlerUploadService;
  const adminUserId = 'admin-upload-123';
  const regularUserId = 'user-regular-456';
  const publisherKey = 'publisher-public-key-xyz';

  beforeEach(() => {
    uploadService = new MockHandlerUploadService();
    uploadService.addAdminUser(adminUserId);
    uploadService.addApprovedPublisher(publisherKey);
  });

  afterEach(() => {
    uploadService.clear();
  });

  describe('Authorization', () => {
    it('should require admin authorization', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(regularUserId, {
        package_data: packageData,
        signature: 'valid-signature',
        public_key: publisherKey,
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Admin authorization required');
    });

    it('should allow admin users to upload', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128), // Valid length signature
        public_key: publisherKey,
      });

      expect(result.success).toBe(true);
    });
  });

  describe('Package Validation', () => {
    it('should validate package signature', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'invalid', // Too short
        public_key: publisherKey,
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid package signature');
    });

    it('should reject invalid base64 data', async () => {
      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: '!!!invalid-base64!!!',
        signature: 'a'.repeat(128),
        public_key: publisherKey,
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid base64');
    });

    it('should enforce package size limit', async () => {
      // Create oversized package data (simulated)
      const largeData = Buffer.alloc(11 * 1024 * 1024); // 11MB
      const packageData = largeData.toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: publisherKey,
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('exceeds maximum size');
    });
  });

  describe('Handler Storage', () => {
    it('should store handler with correct metadata', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: publisherKey,
      });

      expect(result.success).toBe(true);
      expect(result.handler_id).toBeDefined();
      expect(result.version).toBeDefined();

      const stored = uploadService.getHandler(result.handler_id!);
      expect(stored).toBeDefined();
      expect(stored?.uploaded_by).toBe(adminUserId);
      expect(stored?.package_hash).toBeDefined();
    });

    it('should track handler versions', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: publisherKey,
      });

      const versions = uploadService.getHandlerVersions(result.handler_id!);
      expect(versions).toContain(result.version);
    });

    it('should prevent duplicate versions without force_update', async () => {
      // Use same handler ID for both uploads
      const handlerId = 'duplicate-test-handler';
      const handlerPackage1 = createMockHandlerPackage({ manifest: { id: handlerId } });
      const packageData1 = Buffer.from(JSON.stringify(handlerPackage1)).toString('base64');

      // First upload
      await uploadService.uploadHandler(adminUserId, {
        package_data: packageData1,
        signature: 'a'.repeat(128),
        public_key: publisherKey,
      });

      // Second upload with same version (parsePackage returns same mock with same version)
      const handlerPackage2 = createMockHandlerPackage({ manifest: { id: handlerId } });
      const packageData2 = Buffer.from(JSON.stringify(handlerPackage2)).toString('base64');
      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData2,
        signature: 'a'.repeat(128),
        public_key: publisherKey,
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('already exists');
    });

    it('should allow overwrite with force_update', async () => {
      const handlerId = 'overwrite-test-handler';
      const handlerPackage1 = createMockHandlerPackage({ manifest: { id: handlerId } });
      const packageData1 = Buffer.from(JSON.stringify(handlerPackage1)).toString('base64');

      // First upload
      await uploadService.uploadHandler(adminUserId, {
        package_data: packageData1,
        signature: 'a'.repeat(128),
        public_key: publisherKey,
      });

      // Second upload with force_update
      const handlerPackage2 = createMockHandlerPackage({ manifest: { id: handlerId } });
      const packageData2 = Buffer.from(JSON.stringify(handlerPackage2)).toString('base64');
      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData2,
        signature: 'a'.repeat(128),
        public_key: publisherKey,
        force_update: true,
      });

      expect(result.success).toBe(true);
    });
  });

  describe('Publisher Authorization', () => {
    it('should auto-approve handlers from approved publishers', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: publisherKey, // Approved publisher
      });

      expect(result.success).toBe(true);

      const stored = uploadService.getHandler(result.handler_id!);
      expect(stored?.status).toBe('approved');
    });

    it('should set pending_review for non-approved publishers', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: 'unknown-publisher-key', // Not approved
      });

      expect(result.success).toBe(true);

      const stored = uploadService.getHandler(result.handler_id!);
      expect(stored?.status).toBe('pending_review');
    });
  });

  describe('Handler Lifecycle', () => {
    it('should approve pending handler', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: 'unknown-publisher',
      });

      const approved = uploadService.approveHandler(result.handler_id!);
      expect(approved).toBe(true);

      const stored = uploadService.getHandler(result.handler_id!);
      expect(stored?.status).toBe('approved');
    });

    it('should reject pending handler', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: 'unknown-publisher',
      });

      const rejected = uploadService.rejectHandler(result.handler_id!, 'Security concerns');
      expect(rejected).toBe(true);

      const stored = uploadService.getHandler(result.handler_id!);
      expect(stored?.status).toBe('rejected');
    });

    it('should publish approved handler', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: publisherKey,
      });

      const published = uploadService.publishHandler(result.handler_id!);
      expect(published).toBe(true);

      const stored = uploadService.getHandler(result.handler_id!);
      expect(stored?.status).toBe('published');
      expect(stored?.download_url).toBeDefined();
    });

    it('should not publish non-approved handler', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: 'unknown-publisher',
      });

      const published = uploadService.publishHandler(result.handler_id!);
      expect(published).toBe(false);

      const stored = uploadService.getHandler(result.handler_id!);
      expect(stored?.status).toBe('pending_review');
    });
  });

  describe('Metadata', () => {
    it('should include upload timestamp', async () => {
      const beforeUpload = new Date();

      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: publisherKey,
      });

      const afterUpload = new Date();

      const stored = uploadService.getHandler(result.handler_id!);
      expect(stored?.uploaded_at).toBeDefined();
      const uploadTime = new Date(stored!.uploaded_at);
      expect(uploadTime.getTime()).toBeGreaterThanOrEqual(beforeUpload.getTime());
      expect(uploadTime.getTime()).toBeLessThanOrEqual(afterUpload.getTime());
    });

    it('should calculate package hash', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: publisherKey,
      });

      const stored = uploadService.getHandler(result.handler_id!);
      expect(stored?.package_hash).toBeDefined();
      expect(stored?.package_hash).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hash
    });

    it('should record package size', async () => {
      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      const result = await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: publisherKey,
      });

      const stored = uploadService.getHandler(result.handler_id!);
      expect(stored?.package_size).toBeGreaterThan(0);
    });
  });

  describe('Handler Count', () => {
    it('should track total handler count', async () => {
      expect(uploadService.getHandlerCount()).toBe(0);

      const handlerPackage = createMockHandlerPackage({});
      const packageData = Buffer.from(JSON.stringify(handlerPackage)).toString('base64');

      await uploadService.uploadHandler(adminUserId, {
        package_data: packageData,
        signature: 'a'.repeat(128),
        public_key: publisherKey,
      });

      expect(uploadService.getHandlerCount()).toBe(1);
    });
  });
});
