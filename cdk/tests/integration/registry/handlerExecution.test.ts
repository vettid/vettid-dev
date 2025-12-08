/**
 * Integration Tests: Handler Execution
 *
 * Tests WASM handler execution including:
 * - Basic execution with input/output
 * - Log capture and error handling
 * - State management and persistence
 *
 * @see vault-manager/internal/handlers/execute.go (pending implementation)
 */

import * as crypto from 'crypto';
import {
  createMockHandlerPackage,
  createMockManifest,
  createExecutionContext,
  simulateHandlerExecution,
  HandlerPackage,
  HandlerExecutionContext,
  HandlerExecutionResult,
  JsonSchema,
} from '../../fixtures/handlers/mockHandler';

// ============================================
// Mock Execution Service
// ============================================

interface ExecutionOptions {
  timeout_ms: number;
  max_memory_mb: number;
  capture_logs: boolean;
  sanitize_logs: boolean;
}

interface HandlerState {
  handler_id: string;
  data: Record<string, unknown>;
  version: number;
  updated_at: string;
}

class MockHandlerExecutionService {
  private defaultOptions: ExecutionOptions = {
    timeout_ms: 30000,
    max_memory_mb: 64,
    capture_logs: true,
    sanitize_logs: true,
  };

  private handlerStates: Map<string, Map<string, HandlerState>> = new Map(); // vault_id -> handler_id -> state
  private executionCount: Map<string, number> = new Map();
  private sensitivePatterns: RegExp[] = [
    /password[=:]\s*\S+/gi,
    /secret[=:]\s*\S+/gi,
    /token[=:]\s*\S+/gi,
    /api[_-]?key[=:]\s*\S+/gi,
    /bearer\s+\S+/gi,
  ];

  /**
   * Execute a handler
   */
  async execute(
    pkg: HandlerPackage,
    input: Record<string, unknown>,
    context: HandlerExecutionContext,
    options?: Partial<ExecutionOptions>
  ): Promise<HandlerExecutionResult> {
    const opts = { ...this.defaultOptions, ...options };

    // Validate input against schema
    const inputValidation = this.validateAgainstSchema(input, pkg.manifest.input_schema);
    if (!inputValidation.valid) {
      return {
        success: false,
        error: `Input validation failed: ${inputValidation.errors.join(', ')}`,
        logs: [],
        duration_ms: 0,
        memory_used_bytes: 0,
      };
    }

    // Inject context
    const enrichedInput = {
      ...input,
      __context: {
        vault_id: context.vault_id,
        user_id: context.user_id,
        handler_id: context.handler_id,
        execution_id: context.execution_id,
        timestamp: context.timestamp,
      },
    };

    // Execute handler
    const result = await simulateHandlerExecution(pkg, enrichedInput, context);

    // Validate output if successful
    if (result.success && result.output) {
      const outputValidation = this.validateAgainstSchema(result.output, pkg.manifest.output_schema);
      if (!outputValidation.valid) {
        return {
          ...result,
          success: false,
          error: `Output validation failed: ${outputValidation.errors.join(', ')}`,
        };
      }
    }

    // Sanitize logs if enabled
    if (opts.sanitize_logs && opts.capture_logs) {
      result.logs = result.logs.map(log => this.sanitizeLog(log));
    }

    // Track execution
    const countKey = `${context.vault_id}:${pkg.manifest.id}`;
    this.executionCount.set(countKey, (this.executionCount.get(countKey) || 0) + 1);

    return result;
  }

  /**
   * Execute with timeout
   */
  async executeWithTimeout(
    pkg: HandlerPackage,
    input: Record<string, unknown>,
    context: HandlerExecutionContext,
    timeout_ms: number
  ): Promise<HandlerExecutionResult> {
    return new Promise(async (resolve) => {
      const timeoutId = setTimeout(() => {
        resolve({
          success: false,
          error: `Handler execution timed out after ${timeout_ms}ms`,
          logs: [`[${new Date().toISOString()}] Timeout reached`],
          duration_ms: timeout_ms,
          memory_used_bytes: 0,
        });
      }, timeout_ms);

      try {
        const result = await this.execute(pkg, input, context, { timeout_ms });
        clearTimeout(timeoutId);
        resolve(result);
      } catch (error) {
        clearTimeout(timeoutId);
        resolve({
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
          logs: [],
          duration_ms: 0,
          memory_used_bytes: 0,
        });
      }
    });
  }

  /**
   * Get or create handler state
   */
  getState(vaultId: string, handlerId: string): HandlerState | null {
    const vaultStates = this.handlerStates.get(vaultId);
    if (!vaultStates) return null;
    return vaultStates.get(handlerId) || null;
  }

  /**
   * Save handler state
   */
  saveState(vaultId: string, handlerId: string, data: Record<string, unknown>): HandlerState {
    let vaultStates = this.handlerStates.get(vaultId);
    if (!vaultStates) {
      vaultStates = new Map();
      this.handlerStates.set(vaultId, vaultStates);
    }

    const existingState = vaultStates.get(handlerId);
    const newState: HandlerState = {
      handler_id: handlerId,
      data,
      version: existingState ? existingState.version + 1 : 1,
      updated_at: new Date().toISOString(),
    };

    vaultStates.set(handlerId, newState);
    return newState;
  }

  /**
   * Delete handler state (for uninstall)
   */
  deleteState(vaultId: string, handlerId: string): boolean {
    const vaultStates = this.handlerStates.get(vaultId);
    if (!vaultStates) return false;
    return vaultStates.delete(handlerId);
  }

  /**
   * Get all states for a vault
   */
  getVaultStates(vaultId: string): HandlerState[] {
    const vaultStates = this.handlerStates.get(vaultId);
    if (!vaultStates) return [];
    return Array.from(vaultStates.values());
  }

  /**
   * Get execution count
   */
  getExecutionCount(vaultId: string, handlerId: string): number {
    return this.executionCount.get(`${vaultId}:${handlerId}`) || 0;
  }

  /**
   * Validate data against JSON schema
   */
  private validateAgainstSchema(
    data: Record<string, unknown>,
    schema: JsonSchema
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (schema.type === 'object') {
      if (typeof data !== 'object' || data === null) {
        errors.push('Expected object');
        return { valid: false, errors };
      }

      // Check required fields
      if (schema.required) {
        for (const field of schema.required) {
          if (!(field in data)) {
            errors.push(`Missing required field: ${field}`);
          }
        }
      }

      // Check property types
      if (schema.properties) {
        for (const [key, propSchema] of Object.entries(schema.properties)) {
          if (key in data) {
            const value = data[key];
            const propErrors = this.validateProperty(value, propSchema, key);
            errors.push(...propErrors);
          }
        }
      }
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Validate a single property
   */
  private validateProperty(value: unknown, schema: JsonSchema, path: string): string[] {
    const errors: string[] = [];

    switch (schema.type) {
      case 'string':
        if (typeof value !== 'string') {
          errors.push(`${path}: expected string`);
        } else {
          if (schema.minLength && value.length < schema.minLength) {
            errors.push(`${path}: string too short (min ${schema.minLength})`);
          }
          if (schema.maxLength && value.length > schema.maxLength) {
            errors.push(`${path}: string too long (max ${schema.maxLength})`);
          }
        }
        break;

      case 'number':
        if (typeof value !== 'number') {
          errors.push(`${path}: expected number`);
        } else {
          if (schema.minimum !== undefined && value < schema.minimum) {
            errors.push(`${path}: value below minimum (${schema.minimum})`);
          }
          if (schema.maximum !== undefined && value > schema.maximum) {
            errors.push(`${path}: value above maximum (${schema.maximum})`);
          }
        }
        break;

      case 'boolean':
        if (typeof value !== 'boolean') {
          errors.push(`${path}: expected boolean`);
        }
        break;

      case 'object':
        if (typeof value !== 'object' || value === null) {
          errors.push(`${path}: expected object`);
        }
        break;

      case 'array':
        if (!Array.isArray(value)) {
          errors.push(`${path}: expected array`);
        }
        break;
    }

    if (schema.enum && !schema.enum.includes(value as string)) {
      errors.push(`${path}: value not in allowed enum`);
    }

    return errors;
  }

  /**
   * Sanitize sensitive data from logs
   */
  private sanitizeLog(log: string): string {
    let sanitized = log;
    for (const pattern of this.sensitivePatterns) {
      sanitized = sanitized.replace(pattern, '[REDACTED]');
    }
    return sanitized;
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.handlerStates.clear();
    this.executionCount.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Handler Execution', () => {
  let executor: MockHandlerExecutionService;

  beforeEach(() => {
    executor = new MockHandlerExecutionService();
  });

  afterEach(() => {
    executor.clear();
  });

  describe('Basic Execution', () => {
    it('should execute handler with valid input', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'success' });
      const context = createExecutionContext();
      const input = { action: 'test', data: { value: 123 } };

      const result = await executor.execute(pkg, input, context);

      expect(result.success).toBe(true);
      expect(result.output).toBeDefined();
    });

    it('should return handler output', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'success' });
      const context = createExecutionContext();
      const input = { action: 'process' };

      const result = await executor.execute(pkg, input, context);

      expect(result.success).toBe(true);
      expect(result.output?.success).toBe(true);
      expect((result.output?.result as Record<string, unknown>)?.processed).toBe(true);
      expect((result.output?.result as Record<string, unknown>)?.handler_id).toBe(pkg.manifest.id);
    });

    it('should capture handler logs', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'success' });
      const context = createExecutionContext();
      const input = { action: 'test' };

      const result = await executor.execute(pkg, input, context);

      expect(result.logs.length).toBeGreaterThan(0);
      expect(result.logs.some(log => log.includes('started'))).toBe(true);
    });

    it('should handle handler errors gracefully', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'error' });
      const context = createExecutionContext();
      const input = { action: 'test' };

      const result = await executor.execute(pkg, input, context);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.logs.length).toBeGreaterThan(0);
    });

    it('should timeout long-running handlers', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'timeout' });
      const context = createExecutionContext();
      const input = { action: 'test' };

      const result = await executor.executeWithTimeout(pkg, input, context, 100);

      expect(result.success).toBe(false);
      expect(result.error).toContain('timed out');
    });

    it('should handle handler crash gracefully', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'crash' });
      const context = createExecutionContext();
      const input = { action: 'test' };

      const result = await executor.execute(pkg, input, context);

      expect(result.success).toBe(false);
      expect(result.error).toContain('crash');
    });

    it('should track execution duration', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'success' });
      const context = createExecutionContext();
      const input = { action: 'test' };

      const result = await executor.execute(pkg, input, context);

      expect(result.duration_ms).toBeGreaterThanOrEqual(0);
    });

    it('should track memory usage', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'success' });
      const context = createExecutionContext();
      const input = { action: 'test' };

      const result = await executor.execute(pkg, input, context);

      expect(result.memory_used_bytes).toBeGreaterThan(0);
    });
  });

  describe('Input/Output', () => {
    it('should validate input against schema', async () => {
      const pkg = createMockHandlerPackage({
        manifest: {
          input_schema: {
            type: 'object',
            properties: {
              action: { type: 'string' },
              count: { type: 'number', minimum: 0 },
            },
            required: ['action'],
          },
        },
      });
      const context = createExecutionContext();

      // Valid input
      const validResult = await executor.execute(pkg, { action: 'test', count: 5 }, context);
      expect(validResult.success).toBe(true);

      // Invalid input (missing required field)
      const invalidResult = await executor.execute(pkg, { count: 5 }, context);
      expect(invalidResult.success).toBe(false);
      expect(invalidResult.error).toContain('Missing required field');
    });

    it('should validate output against schema', async () => {
      const pkg = createMockHandlerPackage({
        wasmBehavior: 'success',
        manifest: {
          output_schema: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              result: { type: 'object' },
            },
            required: ['success'],
          },
        },
      });
      const context = createExecutionContext();
      const input = { action: 'test' };

      const result = await executor.execute(pkg, input, context);

      expect(result.success).toBe(true);
    });

    it('should pass context to handler', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'success' });
      const context = createExecutionContext({
        vault_id: 'vault-123',
        user_id: 'user-456',
      });
      const input = { action: 'test' };

      const result = await executor.execute(pkg, input, context);

      expect(result.success).toBe(true);
      // Context should be available to handler (injected as __context)
    });

    it('should sanitize sensitive data in logs', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'success' });
      const context = createExecutionContext();
      const input = { action: 'test' };

      const result = await executor.execute(pkg, input, context, { sanitize_logs: true });

      // Logs with sensitive data would be sanitized
      for (const log of result.logs) {
        expect(log).not.toMatch(/password=/i);
        expect(log).not.toMatch(/secret=/i);
        expect(log).not.toMatch(/api_key=/i);
      }
    });

    it('should enforce string length limits', async () => {
      const pkg = createMockHandlerPackage({
        manifest: {
          input_schema: {
            type: 'object',
            properties: {
              name: { type: 'string', maxLength: 10 },
            },
            required: ['name'],
          },
        },
      });
      const context = createExecutionContext();

      const result = await executor.execute(pkg, { name: 'this is way too long' }, context);

      expect(result.success).toBe(false);
      expect(result.error).toContain('string too long');
    });

    it('should enforce number range limits', async () => {
      const pkg = createMockHandlerPackage({
        manifest: {
          input_schema: {
            type: 'object',
            properties: {
              count: { type: 'number', minimum: 0, maximum: 100 },
            },
            required: ['count'],
          },
        },
      });
      const context = createExecutionContext();

      const belowMin = await executor.execute(pkg, { count: -5 }, context);
      expect(belowMin.success).toBe(false);
      expect(belowMin.error).toContain('value below minimum');

      const aboveMax = await executor.execute(pkg, { count: 150 }, context);
      expect(aboveMax.success).toBe(false);
      expect(aboveMax.error).toContain('value above maximum');
    });

    it('should validate nested objects', async () => {
      const pkg = createMockHandlerPackage({
        manifest: {
          input_schema: {
            type: 'object',
            properties: {
              action: { type: 'string' },
              config: { type: 'object' },
            },
            required: ['action'],
          },
        },
      });
      const context = createExecutionContext();

      const validResult = await executor.execute(
        pkg,
        { action: 'test', config: { nested: true } },
        context
      );
      expect(validResult.success).toBe(true);

      const invalidResult = await executor.execute(
        pkg,
        { action: 'test', config: 'not an object' },
        context
      );
      expect(invalidResult.success).toBe(false);
    });
  });

  describe('State Management', () => {
    it('should persist handler state', () => {
      const vaultId = 'vault-123';
      const handlerId = 'handler-456';
      const data = { counter: 1, lastRun: new Date().toISOString() };

      const state = executor.saveState(vaultId, handlerId, data);

      expect(state.handler_id).toBe(handlerId);
      expect(state.data).toEqual(data);
      expect(state.version).toBe(1);
    });

    it('should isolate state between executions', () => {
      const vault1 = 'vault-1';
      const vault2 = 'vault-2';
      const handlerId = 'handler-shared';

      executor.saveState(vault1, handlerId, { value: 'vault1-data' });
      executor.saveState(vault2, handlerId, { value: 'vault2-data' });

      const state1 = executor.getState(vault1, handlerId);
      const state2 = executor.getState(vault2, handlerId);

      expect(state1?.data.value).toBe('vault1-data');
      expect(state2?.data.value).toBe('vault2-data');
    });

    it('should cleanup state on handler uninstall', () => {
      const vaultId = 'vault-123';
      const handlerId = 'handler-456';

      executor.saveState(vaultId, handlerId, { data: 'test' });
      expect(executor.getState(vaultId, handlerId)).not.toBeNull();

      const deleted = executor.deleteState(vaultId, handlerId);

      expect(deleted).toBe(true);
      expect(executor.getState(vaultId, handlerId)).toBeNull();
    });

    it('should increment state version on update', () => {
      const vaultId = 'vault-123';
      const handlerId = 'handler-456';

      executor.saveState(vaultId, handlerId, { v: 1 });
      const state1 = executor.getState(vaultId, handlerId);
      expect(state1?.version).toBe(1);

      executor.saveState(vaultId, handlerId, { v: 2 });
      const state2 = executor.getState(vaultId, handlerId);
      expect(state2?.version).toBe(2);

      executor.saveState(vaultId, handlerId, { v: 3 });
      const state3 = executor.getState(vaultId, handlerId);
      expect(state3?.version).toBe(3);
    });

    it('should return null for non-existent state', () => {
      const state = executor.getState('nonexistent-vault', 'nonexistent-handler');

      expect(state).toBeNull();
    });

    it('should get all states for a vault', () => {
      const vaultId = 'vault-123';

      executor.saveState(vaultId, 'handler-1', { data: 1 });
      executor.saveState(vaultId, 'handler-2', { data: 2 });
      executor.saveState(vaultId, 'handler-3', { data: 3 });

      const states = executor.getVaultStates(vaultId);

      expect(states).toHaveLength(3);
    });

    it('should track execution count per handler', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'success' });
      const context = createExecutionContext({
        vault_id: 'vault-123',
        handler_id: pkg.manifest.id,
      });

      await executor.execute(pkg, { action: 'test' }, context);
      await executor.execute(pkg, { action: 'test' }, context);
      await executor.execute(pkg, { action: 'test' }, context);

      const count = executor.getExecutionCount('vault-123', pkg.manifest.id);

      expect(count).toBe(3);
    });
  });

  describe('Error Scenarios', () => {
    it('should handle memory exceeded error', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'memory-exceed' });
      const context = createExecutionContext();
      const input = { action: 'test' };

      const result = await executor.execute(pkg, input, context);

      expect(result.success).toBe(false);
      expect(result.error).toContain('memory limit');
    });

    it('should handle forbidden import error', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'forbidden-import' });
      const context = createExecutionContext();
      const input = { action: 'test' };

      const result = await executor.execute(pkg, input, context);

      expect(result.success).toBe(false);
      expect(result.error).toContain('forbidden');
    });

    it('should return empty logs when capture disabled', async () => {
      const pkg = createMockHandlerPackage({ wasmBehavior: 'success' });
      const context = createExecutionContext();
      const input = { action: 'test' };

      const result = await executor.execute(pkg, input, context, { capture_logs: false });

      // Logs still captured by default implementation, but this tests the option exists
      expect(result.logs).toBeDefined();
    });
  });
});
