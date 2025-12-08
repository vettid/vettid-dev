/**
 * E2E Tests: Handler Lifecycle
 *
 * Tests the complete handler lifecycle from upload to execution:
 * 1. Upload handler package to registry
 * 2. Verify and validate handler
 * 3. Install handler in vault
 * 4. Execute handler with permissions
 * 5. Manage handler updates
 * 6. Uninstall handler
 *
 * @see vault-manager/internal/handlers/ (pending implementation)
 * @see lambda/handlers/registry/ (pending implementation)
 */

import * as crypto from 'crypto';
import {
  createMockHandlerPackage,
  createMockManifest,
  createMockWasm,
  createValidSignature,
  HandlerManifest,
  HandlerPackage,
} from '../fixtures/handlers/mockHandler';

// ============================================
// Types
// ============================================

interface VaultInstance {
  vault_id: string;
  user_id: string;
  status: 'active' | 'suspended' | 'deleted';
  installed_handlers: InstalledHandler[];
}

interface InstalledHandler {
  handler_id: string;
  version: string;
  installed_at: string;
  enabled: boolean;
  permissions: HandlerPermissions;
}

interface HandlerPermissions {
  network_access: boolean;
  storage_access: boolean;
  messaging_access: boolean;
  allowed_domains?: string[];
}

interface RegistryHandler {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  category: string;
  status: 'pending' | 'approved' | 'published' | 'rejected' | 'deprecated';
  package_hash: string;
  created_at: string;
  updated_at: string;
  download_count: number;
}

interface ExecutionRequest {
  handler_id: string;
  action: string;
  input: Record<string, unknown>;
}

interface ExecutionResult {
  success: boolean;
  output?: Record<string, unknown>;
  error?: string;
  logs?: string[];
  metrics?: {
    execution_time_ms: number;
    memory_used_bytes: number;
  };
}

// ============================================
// Mock E2E Service
// ============================================

class MockHandlerLifecycleService {
  private registry: Map<string, RegistryHandler> = new Map();
  private vaults: Map<string, VaultInstance> = new Map();
  private handlerPackages: Map<string, HandlerPackage> = new Map();
  private executionHistory: Map<string, ExecutionResult[]> = new Map();

  // ========== Registry Operations ==========

  /**
   * Upload handler to registry
   */
  async uploadHandler(
    manifest: HandlerManifest,
    wasm: Uint8Array,
    signature: string
  ): Promise<{ success: boolean; handler_id?: string; error?: string }> {
    // Validate signature
    if (!this.verifySignature(wasm, signature)) {
      return { success: false, error: 'Invalid signature' };
    }

    // Validate manifest
    const manifestErrors = this.validateManifest(manifest);
    if (manifestErrors.length > 0) {
      return { success: false, error: manifestErrors.join(', ') };
    }

    // Validate WASM
    const wasmErrors = this.validateWasm(wasm);
    if (wasmErrors.length > 0) {
      return { success: false, error: wasmErrors.join(', ') };
    }

    // Calculate package hash
    const packageHash = crypto.createHash('sha256').update(wasm).digest('hex');

    // Store in registry
    const handler: RegistryHandler = {
      id: manifest.id,
      name: manifest.name,
      version: manifest.version,
      description: manifest.description,
      author: manifest.author,
      category: manifest.category,
      status: 'pending',
      package_hash: packageHash,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      download_count: 0,
    };

    this.registry.set(manifest.id, handler);
    const wasmBuffer = Buffer.from(wasm);
    const signatureBuffer = Buffer.from(signature);
    this.handlerPackages.set(manifest.id, {
      manifest,
      wasm: wasmBuffer,
      signature: signatureBuffer,
      signaturePublicKey: Buffer.from('mock-public-key'),
      hash: Buffer.from(packageHash, 'hex'),
    });

    return { success: true, handler_id: manifest.id };
  }

  /**
   * Approve handler in registry
   */
  approveHandler(handlerId: string): boolean {
    const handler = this.registry.get(handlerId);
    if (!handler || handler.status !== 'pending') return false;
    handler.status = 'approved';
    handler.updated_at = new Date().toISOString();
    return true;
  }

  /**
   * Publish handler to registry
   */
  publishHandler(handlerId: string): boolean {
    const handler = this.registry.get(handlerId);
    if (!handler || handler.status !== 'approved') return false;
    handler.status = 'published';
    handler.updated_at = new Date().toISOString();
    return true;
  }

  /**
   * Deprecate handler
   */
  deprecateHandler(handlerId: string): boolean {
    const handler = this.registry.get(handlerId);
    if (!handler || handler.status !== 'published') return false;
    handler.status = 'deprecated';
    handler.updated_at = new Date().toISOString();
    return true;
  }

  /**
   * Get handler from registry
   */
  getRegistryHandler(handlerId: string): RegistryHandler | undefined {
    return this.registry.get(handlerId);
  }

  // ========== Vault Operations ==========

  /**
   * Create vault instance
   */
  createVault(userId: string): VaultInstance {
    const vault: VaultInstance = {
      vault_id: crypto.randomUUID(),
      user_id: userId,
      status: 'active',
      installed_handlers: [],
    };
    this.vaults.set(vault.vault_id, vault);
    return vault;
  }

  /**
   * Get vault by ID
   */
  getVault(vaultId: string): VaultInstance | undefined {
    return this.vaults.get(vaultId);
  }

  /**
   * Install handler in vault
   */
  async installHandler(
    vaultId: string,
    handlerId: string,
    permissions: HandlerPermissions
  ): Promise<{ success: boolean; error?: string }> {
    const vault = this.vaults.get(vaultId);
    if (!vault) {
      return { success: false, error: 'Vault not found' };
    }

    if (vault.status !== 'active') {
      return { success: false, error: 'Vault is not active' };
    }

    const handler = this.registry.get(handlerId);
    if (!handler) {
      return { success: false, error: 'Handler not found in registry' };
    }

    if (handler.status !== 'published') {
      return { success: false, error: 'Handler is not published' };
    }

    // Check if already installed
    const existing = vault.installed_handlers.find(h => h.handler_id === handlerId);
    if (existing) {
      return { success: false, error: 'Handler already installed' };
    }

    // Install handler
    vault.installed_handlers.push({
      handler_id: handlerId,
      version: handler.version,
      installed_at: new Date().toISOString(),
      enabled: true,
      permissions,
    });

    // Increment download count
    handler.download_count++;

    return { success: true };
  }

  /**
   * Uninstall handler from vault
   */
  uninstallHandler(vaultId: string, handlerId: string): boolean {
    const vault = this.vaults.get(vaultId);
    if (!vault) return false;

    const index = vault.installed_handlers.findIndex(h => h.handler_id === handlerId);
    if (index === -1) return false;

    vault.installed_handlers.splice(index, 1);
    return true;
  }

  /**
   * Update handler in vault
   */
  async updateHandler(
    vaultId: string,
    handlerId: string
  ): Promise<{ success: boolean; old_version?: string; new_version?: string; error?: string }> {
    const vault = this.vaults.get(vaultId);
    if (!vault) {
      return { success: false, error: 'Vault not found' };
    }

    const installed = vault.installed_handlers.find(h => h.handler_id === handlerId);
    if (!installed) {
      return { success: false, error: 'Handler not installed' };
    }

    const handler = this.registry.get(handlerId);
    if (!handler) {
      return { success: false, error: 'Handler not found in registry' };
    }

    const oldVersion = installed.version;
    if (oldVersion === handler.version) {
      return { success: false, error: 'Already at latest version' };
    }

    installed.version = handler.version;
    return { success: true, old_version: oldVersion, new_version: handler.version };
  }

  /**
   * Enable/disable handler in vault
   */
  setHandlerEnabled(vaultId: string, handlerId: string, enabled: boolean): boolean {
    const vault = this.vaults.get(vaultId);
    if (!vault) return false;

    const installed = vault.installed_handlers.find(h => h.handler_id === handlerId);
    if (!installed) return false;

    installed.enabled = enabled;
    return true;
  }

  /**
   * Update handler permissions
   */
  updateHandlerPermissions(
    vaultId: string,
    handlerId: string,
    permissions: Partial<HandlerPermissions>
  ): boolean {
    const vault = this.vaults.get(vaultId);
    if (!vault) return false;

    const installed = vault.installed_handlers.find(h => h.handler_id === handlerId);
    if (!installed) return false;

    installed.permissions = { ...installed.permissions, ...permissions };
    return true;
  }

  // ========== Execution Operations ==========

  /**
   * Execute handler action
   */
  async executeHandler(
    vaultId: string,
    request: ExecutionRequest
  ): Promise<ExecutionResult> {
    const vault = this.vaults.get(vaultId);
    if (!vault) {
      return { success: false, error: 'Vault not found' };
    }

    if (vault.status !== 'active') {
      return { success: false, error: 'Vault is not active' };
    }

    const installed = vault.installed_handlers.find(h => h.handler_id === request.handler_id);
    if (!installed) {
      return { success: false, error: 'Handler not installed' };
    }

    if (!installed.enabled) {
      return { success: false, error: 'Handler is disabled' };
    }

    // Simulate execution
    const startTime = Date.now();
    const result: ExecutionResult = {
      success: true,
      output: {
        action: request.action,
        processed_input: request.input,
        handler_version: installed.version,
      },
      logs: [
        `[INFO] Handler ${request.handler_id} started`,
        `[INFO] Action: ${request.action}`,
        `[INFO] Handler completed successfully`,
      ],
      metrics: {
        execution_time_ms: Date.now() - startTime + Math.random() * 50,
        memory_used_bytes: Math.floor(1024 * 1024 * (0.5 + Math.random())),
      },
    };

    // Store execution history
    let history = this.executionHistory.get(vaultId);
    if (!history) {
      history = [];
      this.executionHistory.set(vaultId, history);
    }
    history.push(result);

    return result;
  }

  /**
   * Get execution history
   */
  getExecutionHistory(vaultId: string): ExecutionResult[] {
    return this.executionHistory.get(vaultId) || [];
  }

  // ========== Validation Helpers ==========

  private verifySignature(wasm: Uint8Array, signature: string): boolean {
    return signature.length >= 64;
  }

  private validateManifest(manifest: HandlerManifest): string[] {
    const errors: string[] = [];
    if (!manifest.id) errors.push('Missing handler ID');
    if (!manifest.name) errors.push('Missing handler name');
    if (!manifest.version) errors.push('Missing version');
    return errors;
  }

  private validateWasm(wasm: Uint8Array): string[] {
    const errors: string[] = [];
    if (wasm.length < 8) errors.push('WASM too small');
    // Check magic bytes
    const magicBytes = [0x00, 0x61, 0x73, 0x6d];
    for (let i = 0; i < 4 && i < wasm.length; i++) {
      if (wasm[i] !== magicBytes[i]) {
        errors.push('Invalid WASM magic bytes');
        break;
      }
    }
    return errors;
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.registry.clear();
    this.vaults.clear();
    this.handlerPackages.clear();
    this.executionHistory.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Handler Lifecycle E2E', () => {
  let service: MockHandlerLifecycleService;
  const testUserId = 'user-lifecycle-123';

  beforeEach(() => {
    service = new MockHandlerLifecycleService();
  });

  afterEach(() => {
    service.clear();
  });

  describe('Complete Lifecycle', () => {
    it('should complete full handler lifecycle: upload -> install -> execute -> uninstall', async () => {
      // 1. Create vault
      const vault = service.createVault(testUserId);
      expect(vault.vault_id).toBeDefined();

      // 2. Upload handler
      const manifest = createMockManifest({
        id: 'lifecycle.test-handler',
        name: 'Lifecycle Test Handler',
      });
      const wasm = createMockWasm();
      const signature = 'a'.repeat(64);

      const uploadResult = await service.uploadHandler(manifest, wasm, signature);
      expect(uploadResult.success).toBe(true);
      expect(uploadResult.handler_id).toBe('lifecycle.test-handler');

      // 3. Approve handler
      const approved = service.approveHandler(uploadResult.handler_id!);
      expect(approved).toBe(true);

      // 4. Publish handler
      const published = service.publishHandler(uploadResult.handler_id!);
      expect(published).toBe(true);

      // 5. Install in vault
      const installResult = await service.installHandler(
        vault.vault_id,
        uploadResult.handler_id!,
        { network_access: false, storage_access: true, messaging_access: false }
      );
      expect(installResult.success).toBe(true);

      // 6. Execute handler
      const execResult = await service.executeHandler(vault.vault_id, {
        handler_id: uploadResult.handler_id!,
        action: 'process',
        input: { data: 'test' },
      });
      expect(execResult.success).toBe(true);
      expect(execResult.output).toBeDefined();

      // 7. Uninstall handler
      const uninstalled = service.uninstallHandler(vault.vault_id, uploadResult.handler_id!);
      expect(uninstalled).toBe(true);

      // Verify uninstalled
      const updatedVault = service.getVault(vault.vault_id);
      expect(updatedVault?.installed_handlers).toHaveLength(0);
    });
  });

  describe('Upload Phase', () => {
    it('should upload handler to registry', async () => {
      const manifest = createMockManifest({
        id: 'upload.test',
        name: 'Upload Test',
      });
      const wasm = createMockWasm();

      const result = await service.uploadHandler(manifest, wasm, 'a'.repeat(64));

      expect(result.success).toBe(true);

      const handler = service.getRegistryHandler(result.handler_id!);
      expect(handler).toBeDefined();
      expect(handler?.status).toBe('pending');
    });

    it('should reject invalid signature', async () => {
      const manifest = createMockManifest();
      const wasm = createMockWasm();

      const result = await service.uploadHandler(manifest, wasm, 'short');

      expect(result.success).toBe(false);
      expect(result.error).toContain('signature');
    });

    it('should reject invalid WASM', async () => {
      const manifest = createMockManifest();
      const invalidWasm = new Uint8Array([1, 2, 3, 4]); // Invalid magic bytes

      const result = await service.uploadHandler(manifest, invalidWasm, 'a'.repeat(64));

      expect(result.success).toBe(false);
      expect(result.error).toContain('WASM');
    });
  });

  describe('Approval Phase', () => {
    it('should approve pending handler', async () => {
      const manifest = createMockManifest({ id: 'approval.test' });
      await service.uploadHandler(manifest, createMockWasm(), 'a'.repeat(64));

      const approved = service.approveHandler('approval.test');
      expect(approved).toBe(true);

      const handler = service.getRegistryHandler('approval.test');
      expect(handler?.status).toBe('approved');
    });

    it('should not approve non-pending handler', async () => {
      const manifest = createMockManifest({ id: 'approval.test2' });
      await service.uploadHandler(manifest, createMockWasm(), 'a'.repeat(64));
      service.approveHandler('approval.test2');
      service.publishHandler('approval.test2');

      // Try to approve already published handler
      const approved = service.approveHandler('approval.test2');
      expect(approved).toBe(false);
    });
  });

  describe('Installation Phase', () => {
    let vaultId: string;
    const handlerId = 'install.test';

    beforeEach(async () => {
      const vault = service.createVault(testUserId);
      vaultId = vault.vault_id;

      const manifest = createMockManifest({ id: handlerId, name: 'Install Test' });
      await service.uploadHandler(manifest, createMockWasm(), 'a'.repeat(64));
      service.approveHandler(handlerId);
      service.publishHandler(handlerId);
    });

    it('should install published handler', async () => {
      const result = await service.installHandler(vaultId, handlerId, {
        network_access: false,
        storage_access: true,
        messaging_access: false,
      });

      expect(result.success).toBe(true);

      const vault = service.getVault(vaultId);
      expect(vault?.installed_handlers).toHaveLength(1);
      expect(vault?.installed_handlers[0].handler_id).toBe(handlerId);
    });

    it('should not install unpublished handler', async () => {
      const unpublishedManifest = createMockManifest({ id: 'unpublished.handler' });
      await service.uploadHandler(unpublishedManifest, createMockWasm(), 'a'.repeat(64));

      const result = await service.installHandler(vaultId, 'unpublished.handler', {
        network_access: false,
        storage_access: false,
        messaging_access: false,
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('not published');
    });

    it('should not install duplicate handler', async () => {
      await service.installHandler(vaultId, handlerId, {
        network_access: false,
        storage_access: false,
        messaging_access: false,
      });

      const result = await service.installHandler(vaultId, handlerId, {
        network_access: false,
        storage_access: false,
        messaging_access: false,
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('already installed');
    });

    it('should increment download count on install', async () => {
      const beforeInstall = service.getRegistryHandler(handlerId)?.download_count || 0;

      await service.installHandler(vaultId, handlerId, {
        network_access: false,
        storage_access: false,
        messaging_access: false,
      });

      const afterInstall = service.getRegistryHandler(handlerId)?.download_count || 0;
      expect(afterInstall).toBe(beforeInstall + 1);
    });
  });

  describe('Execution Phase', () => {
    let vaultId: string;
    const handlerId = 'exec.test';

    beforeEach(async () => {
      const vault = service.createVault(testUserId);
      vaultId = vault.vault_id;

      const manifest = createMockManifest({ id: handlerId, name: 'Exec Test' });
      await service.uploadHandler(manifest, createMockWasm(), 'a'.repeat(64));
      service.approveHandler(handlerId);
      service.publishHandler(handlerId);
      await service.installHandler(vaultId, handlerId, {
        network_access: true,
        storage_access: true,
        messaging_access: false,
      });
    });

    it('should execute installed handler', async () => {
      const result = await service.executeHandler(vaultId, {
        handler_id: handlerId,
        action: 'test-action',
        input: { key: 'value' },
      });

      expect(result.success).toBe(true);
      expect(result.output).toBeDefined();
      expect(result.logs).toContain(`[INFO] Handler ${handlerId} started`);
      expect(result.metrics?.execution_time_ms).toBeGreaterThanOrEqual(0);
    });

    it('should not execute uninstalled handler', async () => {
      const result = await service.executeHandler(vaultId, {
        handler_id: 'nonexistent.handler',
        action: 'test',
        input: {},
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('not installed');
    });

    it('should not execute disabled handler', async () => {
      service.setHandlerEnabled(vaultId, handlerId, false);

      const result = await service.executeHandler(vaultId, {
        handler_id: handlerId,
        action: 'test',
        input: {},
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('disabled');
    });

    it('should track execution history', async () => {
      await service.executeHandler(vaultId, {
        handler_id: handlerId,
        action: 'action1',
        input: {},
      });
      await service.executeHandler(vaultId, {
        handler_id: handlerId,
        action: 'action2',
        input: {},
      });

      const history = service.getExecutionHistory(vaultId);
      expect(history).toHaveLength(2);
    });
  });

  describe('Update Phase', () => {
    let vaultId: string;
    const handlerId = 'update.test';

    beforeEach(async () => {
      const vault = service.createVault(testUserId);
      vaultId = vault.vault_id;

      const manifest = createMockManifest({
        id: handlerId,
        name: 'Update Test',
        version: '1.0.0',
      });
      await service.uploadHandler(manifest, createMockWasm(), 'a'.repeat(64));
      service.approveHandler(handlerId);
      service.publishHandler(handlerId);
      await service.installHandler(vaultId, handlerId, {
        network_access: false,
        storage_access: false,
        messaging_access: false,
      });
    });

    it('should detect when already at latest version', async () => {
      const result = await service.updateHandler(vaultId, handlerId);

      expect(result.success).toBe(false);
      expect(result.error).toContain('latest version');
    });
  });

  describe('Permission Management', () => {
    let vaultId: string;
    const handlerId = 'perms.test';

    beforeEach(async () => {
      const vault = service.createVault(testUserId);
      vaultId = vault.vault_id;

      const manifest = createMockManifest({ id: handlerId, name: 'Perms Test' });
      await service.uploadHandler(manifest, createMockWasm(), 'a'.repeat(64));
      service.approveHandler(handlerId);
      service.publishHandler(handlerId);
      await service.installHandler(vaultId, handlerId, {
        network_access: false,
        storage_access: false,
        messaging_access: false,
      });
    });

    it('should update handler permissions', () => {
      const updated = service.updateHandlerPermissions(vaultId, handlerId, {
        network_access: true,
        allowed_domains: ['api.example.com'],
      });

      expect(updated).toBe(true);

      const vault = service.getVault(vaultId);
      const handler = vault?.installed_handlers.find(h => h.handler_id === handlerId);
      expect(handler?.permissions.network_access).toBe(true);
      expect(handler?.permissions.allowed_domains).toContain('api.example.com');
    });

    it('should enable/disable handler', () => {
      // Disable
      let result = service.setHandlerEnabled(vaultId, handlerId, false);
      expect(result).toBe(true);

      let vault = service.getVault(vaultId);
      let handler = vault?.installed_handlers.find(h => h.handler_id === handlerId);
      expect(handler?.enabled).toBe(false);

      // Re-enable
      result = service.setHandlerEnabled(vaultId, handlerId, true);
      expect(result).toBe(true);

      vault = service.getVault(vaultId);
      handler = vault?.installed_handlers.find(h => h.handler_id === handlerId);
      expect(handler?.enabled).toBe(true);
    });
  });

  describe('Deprecation', () => {
    it('should deprecate published handler', async () => {
      const manifest = createMockManifest({ id: 'deprecate.test' });
      await service.uploadHandler(manifest, createMockWasm(), 'a'.repeat(64));
      service.approveHandler('deprecate.test');
      service.publishHandler('deprecate.test');

      const deprecated = service.deprecateHandler('deprecate.test');
      expect(deprecated).toBe(true);

      const handler = service.getRegistryHandler('deprecate.test');
      expect(handler?.status).toBe('deprecated');
    });

    it('should not deprecate unpublished handler', async () => {
      const manifest = createMockManifest({ id: 'deprecate.unpublished' });
      await service.uploadHandler(manifest, createMockWasm(), 'a'.repeat(64));
      service.approveHandler('deprecate.unpublished');
      // Not published

      const deprecated = service.deprecateHandler('deprecate.unpublished');
      expect(deprecated).toBe(false);
    });
  });

  describe('Vault State', () => {
    it('should not allow operations on suspended vault', async () => {
      const vault = service.createVault(testUserId);
      vault.status = 'suspended';

      const manifest = createMockManifest({ id: 'suspended.test' });
      await service.uploadHandler(manifest, createMockWasm(), 'a'.repeat(64));
      service.approveHandler('suspended.test');
      service.publishHandler('suspended.test');

      const installResult = await service.installHandler(vault.vault_id, 'suspended.test', {
        network_access: false,
        storage_access: false,
        messaging_access: false,
      });

      expect(installResult.success).toBe(false);
      expect(installResult.error).toContain('not active');
    });

    it('should not execute on suspended vault', async () => {
      const vault = service.createVault(testUserId);

      const manifest = createMockManifest({ id: 'suspended.exec' });
      await service.uploadHandler(manifest, createMockWasm(), 'a'.repeat(64));
      service.approveHandler('suspended.exec');
      service.publishHandler('suspended.exec');
      await service.installHandler(vault.vault_id, 'suspended.exec', {
        network_access: false,
        storage_access: false,
        messaging_access: false,
      });

      // Suspend vault
      vault.status = 'suspended';

      const result = await service.executeHandler(vault.vault_id, {
        handler_id: 'suspended.exec',
        action: 'test',
        input: {},
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('not active');
    });
  });
});
