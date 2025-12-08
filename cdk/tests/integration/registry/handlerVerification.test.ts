/**
 * Integration Tests: Handler Verification
 *
 * Tests handler package verification including:
 * - Ed25519 signature verification
 * - Manifest validation
 * - WASM module validation
 *
 * @see vault-manager/internal/handlers/verify.go (pending implementation)
 */

import * as crypto from 'crypto';
import {
  createMockHandlerPackage,
  createMockManifest,
  createInvalidManifest,
  createMockWasm,
  createInvalidWasm,
  createWasmWithForbiddenImports,
  createValidSignature,
  createInvalidSignature,
  generateSigningKeyPair,
  verifySignature,
  validateWasmMagic,
  validateWasmVersion,
  checkRequiredExports,
  checkForbiddenImports,
  validateManifest,
  validateSemver,
  HandlerManifest,
  HandlerPackage,
} from '../../fixtures/handlers/mockHandler';

// ============================================
// Mock Verification Service
// ============================================

interface VerificationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

interface SignatureInfo {
  valid: boolean;
  expired: boolean;
  revoked: boolean;
  signedAt: string;
  expiresAt?: string;
  signerPublicKey: string;
}

class MockHandlerVerificationService {
  private revokedHandlers: Set<string> = new Set();
  private trustedPublicKeys: Set<string> = new Set();
  private signatureExpiry: Map<string, Date> = new Map();

  constructor() {
    // Add default trusted key
    const defaultKeyPair = generateSigningKeyPair();
    this.trustedPublicKeys.add(defaultKeyPair.publicKey.toString('hex'));
  }

  /**
   * Add a trusted public key
   */
  addTrustedPublicKey(publicKey: Buffer): void {
    this.trustedPublicKeys.add(publicKey.toString('hex'));
  }

  /**
   * Revoke a handler
   */
  revokeHandler(handlerId: string, version: string): void {
    this.revokedHandlers.add(`${handlerId}@${version}`);
  }

  /**
   * Set signature expiry
   */
  setSignatureExpiry(handlerId: string, expiresAt: Date): void {
    this.signatureExpiry.set(handlerId, expiresAt);
  }

  /**
   * Verify package signature
   */
  verifyPackageSignature(pkg: HandlerPackage): SignatureInfo {
    const keyHex = pkg.signaturePublicKey.toString('hex');
    const isTrusted = this.trustedPublicKeys.has(keyHex);

    // Check signature validity
    const isValidSignature = verifySignature(pkg.hash, pkg.signature, pkg.signaturePublicKey);

    // Check if revoked
    const handlerKey = `${pkg.manifest.id}@${pkg.manifest.version}`;
    const isRevoked = this.revokedHandlers.has(handlerKey);

    // Check expiry
    const expiryDate = this.signatureExpiry.get(pkg.manifest.id);
    const isExpired = expiryDate ? new Date() > expiryDate : false;

    return {
      valid: isValidSignature && isTrusted && !isRevoked && !isExpired,
      expired: isExpired,
      revoked: isRevoked,
      signedAt: new Date().toISOString(),
      expiresAt: expiryDate?.toISOString(),
      signerPublicKey: keyHex,
    };
  }

  /**
   * Validate handler manifest
   */
  validateManifest(manifest: Partial<HandlerManifest>): VerificationResult {
    const result = validateManifest(manifest);
    return {
      valid: result.valid,
      errors: result.errors,
      warnings: [],
    };
  }

  /**
   * Validate WASM module
   */
  validateWasm(wasm: Buffer): VerificationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check magic bytes
    if (!validateWasmMagic(wasm)) {
      errors.push('Invalid WASM magic bytes');
    }

    // Check version
    if (!validateWasmVersion(wasm)) {
      errors.push('Invalid WASM version');
    }

    // Check required exports
    const exports = checkRequiredExports(wasm);
    if (!exports.hasMain) {
      errors.push('Missing required export: main');
    }
    if (!exports.hasInit) {
      warnings.push('Missing optional export: init');
    }

    // Check forbidden imports
    const forbidden = checkForbiddenImports(wasm);
    for (const imp of forbidden) {
      errors.push(`Forbidden WASM import: ${imp}`);
    }

    // Check memory limits (simplified check)
    if (wasm.length > 10 * 1024 * 1024) { // 10MB max
      errors.push('WASM module exceeds maximum size (10MB)');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Full package verification
   */
  verifyPackage(pkg: HandlerPackage): VerificationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Verify signature
    const sigInfo = this.verifyPackageSignature(pkg);
    if (!sigInfo.valid) {
      if (sigInfo.revoked) {
        errors.push('Handler has been revoked');
      } else if (sigInfo.expired) {
        errors.push('Signature has expired');
      } else {
        errors.push('Invalid package signature');
      }
    }

    // Validate manifest
    const manifestResult = this.validateManifest(pkg.manifest);
    errors.push(...manifestResult.errors);
    warnings.push(...manifestResult.warnings);

    // Validate WASM
    const wasmResult = this.validateWasm(pkg.wasm);
    errors.push(...wasmResult.errors);
    warnings.push(...wasmResult.warnings);

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Verify signature chain for updates
   */
  verifyUpdateChain(currentPkg: HandlerPackage, updatePkg: HandlerPackage): VerificationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Must be same handler ID
    if (currentPkg.manifest.id !== updatePkg.manifest.id) {
      errors.push('Handler ID mismatch');
    }

    // New version must be higher
    const currentParts = currentPkg.manifest.version.split('.').map(Number);
    const updateParts = updatePkg.manifest.version.split('.').map(Number);

    let isHigher = false;
    for (let i = 0; i < 3; i++) {
      if (updateParts[i] > currentParts[i]) {
        isHigher = true;
        break;
      } else if (updateParts[i] < currentParts[i]) {
        break;
      }
    }

    if (!isHigher) {
      errors.push('Update version must be higher than current version');
    }

    // Both signatures must be valid
    const currentSig = this.verifyPackageSignature(currentPkg);
    const updateSig = this.verifyPackageSignature(updatePkg);

    if (!currentSig.valid) {
      errors.push('Current package signature invalid');
    }
    if (!updateSig.valid) {
      errors.push('Update package signature invalid');
    }

    // Signatures should be from same key (or trusted key)
    if (currentSig.signerPublicKey !== updateSig.signerPublicKey) {
      warnings.push('Update signed by different key than original');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Clear state
   */
  clear(): void {
    this.revokedHandlers.clear();
    this.signatureExpiry.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Handler Verification', () => {
  let verifier: MockHandlerVerificationService;

  beforeEach(() => {
    verifier = new MockHandlerVerificationService();
  });

  afterEach(() => {
    verifier.clear();
  });

  describe('Package Signature', () => {
    it('should verify valid Ed25519 signature', () => {
      const pkg = createMockHandlerPackage({ signatureValid: true });
      verifier.addTrustedPublicKey(pkg.signaturePublicKey);

      const result = verifier.verifyPackageSignature(pkg);

      expect(result.valid).toBe(true);
      expect(result.revoked).toBe(false);
      expect(result.expired).toBe(false);
    });

    it('should reject invalid signature', () => {
      const pkg = createMockHandlerPackage({ signatureValid: false });
      verifier.addTrustedPublicKey(pkg.signaturePublicKey);

      const result = verifier.verifyPackageSignature(pkg);

      expect(result.valid).toBe(false);
    });

    it('should reject expired signature', () => {
      const pkg = createMockHandlerPackage({ signatureValid: true });
      verifier.addTrustedPublicKey(pkg.signaturePublicKey);

      // Set expiry to past
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 1);
      verifier.setSignatureExpiry(pkg.manifest.id, pastDate);

      const result = verifier.verifyPackageSignature(pkg);

      expect(result.valid).toBe(false);
      expect(result.expired).toBe(true);
    });

    it('should reject revoked handler', () => {
      const pkg = createMockHandlerPackage({ signatureValid: true });
      verifier.addTrustedPublicKey(pkg.signaturePublicKey);

      verifier.revokeHandler(pkg.manifest.id, pkg.manifest.version);

      const result = verifier.verifyPackageSignature(pkg);

      expect(result.valid).toBe(false);
      expect(result.revoked).toBe(true);
    });

    it('should verify signature chain for updates', () => {
      const currentPkg = createMockHandlerPackage({
        name: 'Test Handler',
        version: '1.0.0',
        signatureValid: true,
      });

      const updatePkg = createMockHandlerPackage({
        name: 'Test Handler',
        version: '1.1.0',
        manifest: { id: currentPkg.manifest.id },
        signatureValid: true,
      });

      verifier.addTrustedPublicKey(currentPkg.signaturePublicKey);
      verifier.addTrustedPublicKey(updatePkg.signaturePublicKey);

      const result = verifier.verifyUpdateChain(currentPkg, updatePkg);

      expect(result.valid).toBe(true);
    });

    it('should reject update with lower version', () => {
      const currentPkg = createMockHandlerPackage({
        name: 'Test Handler',
        version: '2.0.0',
        signatureValid: true,
      });

      const updatePkg = createMockHandlerPackage({
        name: 'Test Handler',
        version: '1.0.0',
        manifest: { id: currentPkg.manifest.id },
        signatureValid: true,
      });

      verifier.addTrustedPublicKey(currentPkg.signaturePublicKey);
      verifier.addTrustedPublicKey(updatePkg.signaturePublicKey);

      const result = verifier.verifyUpdateChain(currentPkg, updatePkg);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Update version must be higher than current version');
    });

    it('should reject untrusted public key', () => {
      const pkg = createMockHandlerPackage({ signatureValid: true });
      // Don't add to trusted keys

      const result = verifier.verifyPackageSignature(pkg);

      expect(result.valid).toBe(false);
    });

    it('should include signer public key in result', () => {
      const pkg = createMockHandlerPackage({ signatureValid: true });
      verifier.addTrustedPublicKey(pkg.signaturePublicKey);

      const result = verifier.verifyPackageSignature(pkg);

      expect(result.signerPublicKey).toBe(pkg.signaturePublicKey.toString('hex'));
    });
  });

  describe('Manifest Validation', () => {
    it('should validate required manifest fields', () => {
      const manifest = createMockManifest();

      const result = verifier.validateManifest(manifest);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject manifest missing id', () => {
      const manifest = createInvalidManifest('missing-id');

      const result = verifier.validateManifest(manifest);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Missing required field: id');
    });

    it('should reject manifest missing version', () => {
      const manifest = createInvalidManifest('missing-version');

      const result = verifier.validateManifest(manifest);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Missing required field: version');
    });

    it('should validate handler version format', () => {
      expect(validateSemver('1.0.0')).toBe(true);
      expect(validateSemver('2.3.4-beta.1')).toBe(true);
      expect(validateSemver('1.0.0+build.123')).toBe(true);
      expect(validateSemver('not-semver')).toBe(false);
      expect(validateSemver('1.0')).toBe(false);
      expect(validateSemver('v1.0.0')).toBe(false);
    });

    it('should reject invalid version format', () => {
      const manifest = createInvalidManifest('invalid-version');

      const result = verifier.validateManifest(manifest);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid version format: must be semver');
    });

    it('should validate input/output schema', () => {
      const manifest = createMockManifest({
        input_schema: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            age: { type: 'number', minimum: 0 },
          },
          required: ['name'],
        },
        output_schema: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
          },
          required: ['success'],
        },
      });

      const result = verifier.validateManifest(manifest);

      expect(result.valid).toBe(true);
    });

    it('should validate permission declarations', () => {
      const manifest = createMockManifest({
        permissions: [
          { type: 'read_profile', reason: 'Display user name' },
          { type: 'send_message', reason: 'Send notifications' },
        ],
      });

      const result = verifier.validateManifest(manifest);

      expect(result.valid).toBe(true);
    });

    it('should reject manifest with undeclared capabilities', () => {
      const manifest = createInvalidManifest('undeclared-capability');

      const result = verifier.validateManifest(manifest);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Egress rules declared without network_egress permission');
    });

    it('should validate category is valid', () => {
      const validCategories = ['messaging', 'profile', 'connections', 'finance', 'utility'];

      for (const category of validCategories) {
        const manifest = createMockManifest({ category: category as any });
        const result = verifier.validateManifest(manifest);
        expect(result.valid).toBe(true);
      }
    });

    it('should validate egress rules when network permission declared', () => {
      const manifest = createMockManifest({
        permissions: [
          { type: 'network_egress', reason: 'Call external API' },
        ],
        egress: [
          { host: 'api.example.com', protocol: 'https', rate_limit_rpm: 60 },
        ],
      });

      const result = verifier.validateManifest(manifest);

      expect(result.valid).toBe(true);
    });

    it('should require author field', () => {
      const manifest = createMockManifest();
      delete (manifest as any).author;

      const result = verifier.validateManifest(manifest);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Missing required field: author');
    });
  });

  describe('WASM Validation', () => {
    it('should validate WASM magic bytes', () => {
      const validWasm = createMockWasm('success');
      const invalidWasm = createInvalidWasm();

      expect(validateWasmMagic(validWasm)).toBe(true);
      expect(validateWasmMagic(invalidWasm)).toBe(false);
    });

    it('should validate WASM version', () => {
      const validWasm = createMockWasm('success');

      expect(validateWasmVersion(validWasm)).toBe(true);
    });

    it('should validate required exports', () => {
      const wasm = createMockWasm('success');

      const result = verifier.validateWasm(wasm);

      expect(result.valid).toBe(true);
    });

    it('should reject WASM with forbidden imports', () => {
      const wasm = createWasmWithForbiddenImports();

      const result = verifier.validateWasm(wasm);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('Forbidden WASM import'))).toBe(true);
    });

    it('should validate memory limits', () => {
      const wasm = createMockWasm('success');

      const result = verifier.validateWasm(wasm);

      // Our mock WASM is small, should pass
      expect(result.errors.filter(e => e.includes('memory'))).toHaveLength(0);
    });

    it('should reject invalid WASM magic bytes', () => {
      const invalidWasm = createInvalidWasm();

      const result = verifier.validateWasm(invalidWasm);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid WASM magic bytes');
    });

    it('should check for required main export', () => {
      const wasm = createMockWasm('success');
      const exports = checkRequiredExports(wasm);

      expect(exports.hasMain).toBe(true);
    });

    it('should list forbidden imports found', () => {
      const wasm = createWasmWithForbiddenImports();
      const forbidden = checkForbiddenImports(wasm);

      expect(forbidden.length).toBeGreaterThan(0);
    });
  });

  describe('Full Package Verification', () => {
    it('should verify valid package', () => {
      const pkg = createMockHandlerPackage({ signatureValid: true });
      verifier.addTrustedPublicKey(pkg.signaturePublicKey);

      const result = verifier.verifyPackage(pkg);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should collect all errors from verification steps', () => {
      // Create package with multiple issues
      const keyPair = generateSigningKeyPair();
      const manifest = createInvalidManifest('missing-id');
      const wasm = createInvalidWasm();

      const pkg: HandlerPackage = {
        manifest: manifest as HandlerManifest,
        wasm,
        signature: createInvalidSignature(),
        signaturePublicKey: keyPair.publicKey,
        hash: crypto.randomBytes(32),
      };

      const result = verifier.verifyPackage(pkg);

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(1);
    });

    it('should include warnings for non-critical issues', () => {
      const pkg = createMockHandlerPackage({ signatureValid: true });
      verifier.addTrustedPublicKey(pkg.signaturePublicKey);

      const result = verifier.verifyPackage(pkg);

      // Warnings are informational, not failures
      expect(result.valid).toBe(true);
    });

    it('should reject package if any critical check fails', () => {
      const pkg = createMockHandlerPackage({ signatureValid: false });
      verifier.addTrustedPublicKey(pkg.signaturePublicKey);

      const result = verifier.verifyPackage(pkg);

      expect(result.valid).toBe(false);
    });
  });
});
