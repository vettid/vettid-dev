/**
 * Mock Handler Package Fixtures
 *
 * Provides utilities for creating mock handler packages for testing:
 * - Handler manifest creation
 * - WASM module simulation
 * - Package signing
 * - Various handler behaviors
 */

import * as crypto from 'crypto';

// ============================================
// Types
// ============================================

export interface HandlerManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  category: 'messaging' | 'profile' | 'connections' | 'finance' | 'utility';
  min_app_version: string;
  min_vault_version: string;
  permissions: HandlerPermission[];
  egress: EgressRule[];
  input_schema: JsonSchema;
  output_schema: JsonSchema;
  state_schema?: JsonSchema;
  created_at: string;
  updated_at: string;
}

export interface HandlerPermission {
  type: 'read_contacts' | 'write_contacts' | 'read_profile' | 'write_profile' |
        'send_message' | 'receive_message' | 'network_egress' | 'persistent_state';
  reason: string;
}

export interface EgressRule {
  host: string;
  port?: number;
  protocol: 'https' | 'wss';
  rate_limit_rpm?: number;
  bandwidth_kbps?: number;
}

export interface JsonSchema {
  type: string;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: string[];
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
}

export interface HandlerPackage {
  manifest: HandlerManifest;
  wasm: Buffer;
  signature: Buffer;
  signaturePublicKey: Buffer;
  hash: Buffer;
}

export interface HandlerExecutionContext {
  vault_id: string;
  user_id: string;
  handler_id: string;
  execution_id: string;
  timestamp: string;
}

export interface HandlerExecutionResult {
  success: boolean;
  output?: Record<string, unknown>;
  error?: string;
  logs: string[];
  duration_ms: number;
  memory_used_bytes: number;
}

export type WasmBehavior = 'success' | 'error' | 'timeout' | 'memory-exceed' | 'crash' | 'forbidden-import';

// ============================================
// Mock WASM Module
// ============================================

/**
 * WASM magic bytes: \0asm (0x00 0x61 0x73 0x6D)
 */
const WASM_MAGIC = Buffer.from([0x00, 0x61, 0x73, 0x6D]);

/**
 * WASM version 1: 0x01 0x00 0x00 0x00
 */
const WASM_VERSION = Buffer.from([0x01, 0x00, 0x00, 0x00]);

/**
 * Create a mock WASM module
 */
export function createMockWasm(behavior: WasmBehavior = 'success'): Buffer {
  // Create minimal valid WASM structure
  const header = Buffer.concat([WASM_MAGIC, WASM_VERSION]);

  // Different behaviors are represented by different module content
  // In real implementation, these would be actual WASM bytecode
  const behaviorMarker = Buffer.from(behavior);

  // Add section headers (minimal type section, function section, export section)
  const typeSection = Buffer.from([
    0x01, // Type section ID
    0x04, // Section size
    0x01, // One type
    0x60, // Function type
    0x00, // No params
    0x00, // No returns
  ]);

  const functionSection = Buffer.from([
    0x03, // Function section ID
    0x02, // Section size
    0x01, // One function
    0x00, // Type index 0
  ]);

  const exportSection = Buffer.from([
    0x07, // Export section ID
    0x08, // Section size
    0x01, // One export
    0x04, // Name length
    0x6d, 0x61, 0x69, 0x6e, // "main"
    0x00, // Export kind: function
    0x00, // Function index
  ]);

  const codeSection = Buffer.from([
    0x0a, // Code section ID
    0x04, // Section size
    0x01, // One function body
    0x02, // Body size
    0x00, // Local count
    0x0b, // end opcode
  ]);

  return Buffer.concat([
    header,
    typeSection,
    functionSection,
    exportSection,
    codeSection,
    behaviorMarker,
  ]);
}

/**
 * Create an invalid WASM module (missing magic bytes)
 */
export function createInvalidWasm(): Buffer {
  return Buffer.from('not a wasm module');
}

/**
 * Create WASM with forbidden imports
 */
export function createWasmWithForbiddenImports(): Buffer {
  const header = Buffer.concat([WASM_MAGIC, WASM_VERSION]);

  // Import section with forbidden "env.system" import
  const importSection = Buffer.from([
    0x02, // Import section ID
    0x0f, // Section size
    0x01, // One import
    0x03, // Module name length
    0x65, 0x6e, 0x76, // "env"
    0x06, // Field name length
    0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, // "system"
    0x00, // Import kind: function
    0x00, // Type index
  ]);

  return Buffer.concat([header, importSection]);
}

// ============================================
// Mock Manifest Creation
// ============================================

/**
 * Create a valid handler manifest with defaults
 */
export function createMockManifest(overrides?: Partial<HandlerManifest>): HandlerManifest {
  const now = new Date().toISOString();
  const id = overrides?.id || `handler-${crypto.randomUUID().slice(0, 8)}`;

  return {
    id,
    name: overrides?.name || 'Test Handler',
    version: overrides?.version || '1.0.0',
    description: overrides?.description || 'A test handler for unit testing',
    author: overrides?.author || 'VettID Test Suite',
    category: overrides?.category || 'utility',
    min_app_version: overrides?.min_app_version || '1.0.0',
    min_vault_version: overrides?.min_vault_version || '1.0.0',
    permissions: overrides?.permissions || [],
    egress: overrides?.egress || [],
    input_schema: overrides?.input_schema || {
      type: 'object',
      properties: {
        action: { type: 'string' },
        data: { type: 'object' },
      },
      required: ['action'],
    },
    output_schema: overrides?.output_schema || {
      type: 'object',
      properties: {
        success: { type: 'boolean' },
        result: { type: 'object' },
      },
      required: ['success'],
    },
    state_schema: overrides?.state_schema,
    created_at: overrides?.created_at || now,
    updated_at: overrides?.updated_at || now,
  };
}

/**
 * Create manifest with invalid fields
 */
export function createInvalidManifest(issue: 'missing-id' | 'missing-version' | 'invalid-version' |
  'missing-permissions' | 'undeclared-capability' | 'invalid-schema'): Partial<HandlerManifest> {
  const valid = createMockManifest();

  switch (issue) {
    case 'missing-id':
      const { id: _id, ...noId } = valid;
      return noId;

    case 'missing-version':
      const { version: _version, ...noVersion } = valid;
      return noVersion;

    case 'invalid-version':
      return { ...valid, version: 'not-semver' };

    case 'missing-permissions':
      return {
        ...valid,
        permissions: undefined as unknown as HandlerPermission[],
      };

    case 'undeclared-capability':
      // Has network egress in behavior but not declared in permissions
      return {
        ...valid,
        egress: [{ host: 'api.example.com', protocol: 'https' }],
        permissions: [], // Missing network_egress permission
      };

    case 'invalid-schema':
      return {
        ...valid,
        input_schema: { type: 'invalid-type' },
      };
  }
}

// ============================================
// Signature Creation
// ============================================

/**
 * Generate Ed25519 key pair for signing
 */
export function generateSigningKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

  return {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }) as Buffer,
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer,
  };
}

/**
 * Create a valid signature for a package hash
 */
export function createValidSignature(packageHash: Buffer, privateKeyDer: Buffer): Buffer {
  const privateKey = crypto.createPrivateKey({
    key: privateKeyDer,
    format: 'der',
    type: 'pkcs8',
  });

  return crypto.sign(null, packageHash, privateKey);
}

/**
 * Create an invalid signature
 */
export function createInvalidSignature(): Buffer {
  return crypto.randomBytes(64);
}

/**
 * Verify a signature
 */
export function verifySignature(packageHash: Buffer, signature: Buffer, publicKeyDer: Buffer): boolean {
  try {
    const publicKey = crypto.createPublicKey({
      key: publicKeyDer,
      format: 'der',
      type: 'spki',
    });

    return crypto.verify(null, packageHash, publicKey, signature);
  } catch {
    return false;
  }
}

// ============================================
// Package Creation
// ============================================

/**
 * Create a complete mock handler package
 */
export function createMockHandlerPackage(options: {
  name?: string;
  version?: string;
  manifest?: Partial<HandlerManifest>;
  wasmBehavior?: WasmBehavior;
  signatureValid?: boolean;
}): HandlerPackage {
  const manifest = createMockManifest({
    name: options.name,
    version: options.version,
    ...options.manifest,
  });

  const wasm = createMockWasm(options.wasmBehavior || 'success');

  // Create package content hash
  const packageContent = Buffer.concat([
    Buffer.from(JSON.stringify(manifest)),
    wasm,
  ]);
  const hash = crypto.createHash('sha256').update(packageContent).digest();

  // Generate signature
  const keyPair = generateSigningKeyPair();
  let signature: Buffer;

  if (options.signatureValid === false) {
    signature = createInvalidSignature();
  } else {
    signature = createValidSignature(hash, keyPair.privateKey);
  }

  return {
    manifest,
    wasm,
    signature,
    signaturePublicKey: keyPair.publicKey,
    hash,
  };
}

// ============================================
// Execution Simulation
// ============================================

/**
 * Simulate handler execution
 */
export async function simulateHandlerExecution(
  handlerPackage: HandlerPackage,
  input: Record<string, unknown>,
  context: HandlerExecutionContext,
  behavior?: WasmBehavior
): Promise<HandlerExecutionResult> {
  const startTime = Date.now();
  const logs: string[] = [];

  // Determine behavior from WASM content or override
  const wasmBehavior = behavior ||
    (handlerPackage.wasm.includes(Buffer.from('timeout')) ? 'timeout' :
     handlerPackage.wasm.includes(Buffer.from('memory-exceed')) ? 'memory-exceed' :
     handlerPackage.wasm.includes(Buffer.from('forbidden-import')) ? 'forbidden-import' :
     handlerPackage.wasm.includes(Buffer.from('error')) ? 'error' :
     handlerPackage.wasm.includes(Buffer.from('crash')) ? 'crash' :
     'success');

  logs.push(`[${new Date().toISOString()}] Handler execution started`);
  logs.push(`[${new Date().toISOString()}] Input: ${JSON.stringify(input)}`);

  switch (wasmBehavior) {
    case 'success':
      await simulateDelay(10);
      logs.push(`[${new Date().toISOString()}] Processing completed successfully`);
      return {
        success: true,
        output: { success: true, result: { processed: true, handler_id: handlerPackage.manifest.id } },
        logs,
        duration_ms: Date.now() - startTime,
        memory_used_bytes: 1024 * 1024, // 1MB
      };

    case 'error':
      await simulateDelay(5);
      logs.push(`[${new Date().toISOString()}] ERROR: Handler execution failed`);
      return {
        success: false,
        error: 'Handler returned error: Invalid input data',
        logs,
        duration_ms: Date.now() - startTime,
        memory_used_bytes: 512 * 1024,
      };

    case 'timeout':
      // Simulate long-running handler (but don't actually wait)
      logs.push(`[${new Date().toISOString()}] Handler taking too long...`);
      return {
        success: false,
        error: 'Handler execution timed out after 30000ms',
        logs,
        duration_ms: 30000,
        memory_used_bytes: 2 * 1024 * 1024,
      };

    case 'memory-exceed':
      logs.push(`[${new Date().toISOString()}] Memory allocation request: 256MB`);
      return {
        success: false,
        error: 'Handler exceeded memory limit (64MB)',
        logs,
        duration_ms: Date.now() - startTime,
        memory_used_bytes: 64 * 1024 * 1024,
      };

    case 'crash':
      logs.push(`[${new Date().toISOString()}] FATAL: Unrecoverable error`);
      return {
        success: false,
        error: 'Handler crashed unexpectedly',
        logs,
        duration_ms: Date.now() - startTime,
        memory_used_bytes: 0,
      };

    case 'forbidden-import':
      return {
        success: false,
        error: 'Handler uses forbidden WASM import: env.system',
        logs,
        duration_ms: Date.now() - startTime,
        memory_used_bytes: 0,
      };

    default:
      return {
        success: false,
        error: `Unknown behavior: ${wasmBehavior}`,
        logs,
        duration_ms: Date.now() - startTime,
        memory_used_bytes: 0,
      };
  }
}

/**
 * Create an execution context
 */
export function createExecutionContext(overrides?: Partial<HandlerExecutionContext>): HandlerExecutionContext {
  return {
    vault_id: overrides?.vault_id || `vault-${crypto.randomUUID().slice(0, 8)}`,
    user_id: overrides?.user_id || `user-${crypto.randomUUID().slice(0, 8)}`,
    handler_id: overrides?.handler_id || `handler-${crypto.randomUUID().slice(0, 8)}`,
    execution_id: overrides?.execution_id || crypto.randomUUID(),
    timestamp: overrides?.timestamp || new Date().toISOString(),
  };
}

// ============================================
// First-Party Handler Mocks
// ============================================

/**
 * Create mock messaging handler package
 */
export function createMessagingHandlerPackage(): HandlerPackage {
  return createMockHandlerPackage({
    name: 'Messaging Send Text',
    manifest: {
      id: 'vettid.messaging.send-text',
      name: 'Messaging Send Text',
      category: 'messaging',
      permissions: [
        { type: 'send_message', reason: 'Send text messages to connections' },
        { type: 'read_contacts', reason: 'Verify recipient is a connection' },
      ],
      input_schema: {
        type: 'object',
        properties: {
          recipient_id: { type: 'string' },
          message: { type: 'string', maxLength: 10000 },
        },
        required: ['recipient_id', 'message'],
      },
      output_schema: {
        type: 'object',
        properties: {
          message_id: { type: 'string' },
          delivered: { type: 'boolean' },
          queued: { type: 'boolean' },
        },
        required: ['message_id'],
      },
    },
  });
}

/**
 * Create mock profile handler package
 */
export function createProfileHandlerPackage(): HandlerPackage {
  return createMockHandlerPackage({
    name: 'Profile Update',
    manifest: {
      id: 'vettid.profile.update',
      name: 'Profile Update',
      category: 'profile',
      permissions: [
        { type: 'read_profile', reason: 'Read current profile' },
        { type: 'write_profile', reason: 'Update profile fields' },
      ],
      input_schema: {
        type: 'object',
        properties: {
          display_name: { type: 'string', maxLength: 100 },
          bio: { type: 'string', maxLength: 500 },
          avatar_url: { type: 'string' },
        },
      },
      output_schema: {
        type: 'object',
        properties: {
          success: { type: 'boolean' },
          profile_version: { type: 'number' },
        },
        required: ['success'],
      },
    },
  });
}

/**
 * Create mock connection invite handler package
 */
export function createConnectionInviteHandlerPackage(): HandlerPackage {
  return createMockHandlerPackage({
    name: 'Connection Invite',
    manifest: {
      id: 'vettid.connections.invite',
      name: 'Connection Invite',
      category: 'connections',
      permissions: [
        { type: 'write_contacts', reason: 'Create pending invitation' },
        { type: 'read_profile', reason: 'Include public key in invite' },
      ],
      input_schema: {
        type: 'object',
        properties: {
          expires_in_hours: { type: 'number', minimum: 1, maximum: 168 },
          max_uses: { type: 'number', minimum: 1, maximum: 10 },
          note: { type: 'string', maxLength: 200 },
        },
      },
      output_schema: {
        type: 'object',
        properties: {
          invite_code: { type: 'string' },
          expires_at: { type: 'string' },
          public_key: { type: 'string' },
        },
        required: ['invite_code', 'expires_at', 'public_key'],
      },
    },
  });
}

// ============================================
// Utility Functions
// ============================================

function simulateDelay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Validate WASM magic bytes
 */
export function validateWasmMagic(wasm: Buffer): boolean {
  if (wasm.length < 8) return false;
  return wasm.slice(0, 4).equals(WASM_MAGIC);
}

/**
 * Validate WASM version
 */
export function validateWasmVersion(wasm: Buffer): boolean {
  if (wasm.length < 8) return false;
  return wasm.slice(4, 8).equals(WASM_VERSION);
}

/**
 * Check for required WASM exports
 */
export function checkRequiredExports(wasm: Buffer): { hasMain: boolean; hasInit: boolean } {
  // In real implementation, would parse WASM export section
  // For mock, check if our mock export section is present
  const hasExportSection = wasm.includes(Buffer.from([0x07])); // Export section ID

  return {
    hasMain: hasExportSection,
    hasInit: false, // Optional export
  };
}

/**
 * Check for forbidden WASM imports
 */
export function checkForbiddenImports(wasm: Buffer): string[] {
  const forbidden: string[] = [];

  // Check for import section (0x02)
  if (wasm.includes(Buffer.from([0x02]))) {
    // In real implementation, would parse import section
    // For mock, check for known forbidden imports
    if (wasm.includes(Buffer.from('system'))) {
      forbidden.push('env.system');
    }
    if (wasm.includes(Buffer.from('spawn'))) {
      forbidden.push('env.spawn');
    }
    if (wasm.includes(Buffer.from('exec'))) {
      forbidden.push('env.exec');
    }
  }

  return forbidden;
}

/**
 * Validate semver version format
 */
export function validateSemver(version: string): boolean {
  const semverRegex = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$/;
  return semverRegex.test(version);
}

/**
 * Validate manifest against schema
 */
export function validateManifest(manifest: Partial<HandlerManifest>): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!manifest.id) errors.push('Missing required field: id');
  if (!manifest.name) errors.push('Missing required field: name');
  if (!manifest.version) errors.push('Missing required field: version');
  if (manifest.version && !validateSemver(manifest.version)) {
    errors.push('Invalid version format: must be semver');
  }
  if (!manifest.author) errors.push('Missing required field: author');
  if (!manifest.category) errors.push('Missing required field: category');
  if (!manifest.permissions) errors.push('Missing required field: permissions');
  if (!manifest.input_schema) errors.push('Missing required field: input_schema');
  if (!manifest.output_schema) errors.push('Missing required field: output_schema');

  // Check for undeclared capabilities
  if (manifest.egress && manifest.egress.length > 0) {
    const hasNetworkPermission = manifest.permissions?.some(p => p.type === 'network_egress');
    if (!hasNetworkPermission) {
      errors.push('Egress rules declared without network_egress permission');
    }
  }

  return { valid: errors.length === 0, errors };
}
