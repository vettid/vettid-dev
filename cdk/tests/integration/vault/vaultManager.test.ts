/**
 * Integration Tests: Vault Manager Service
 *
 * Tests the Vault Manager service running on EC2:
 * - Event processing from forVault topic
 * - Response publishing to forApp topic
 * - Control topic command handling
 * - Health reporting and metrics
 *
 * @see vault-manager/internal/events/processor.go (pending implementation)
 */

import * as crypto from 'crypto';

// ============================================
// Types
// ============================================

interface VaultEvent {
  event_id: string;
  event_type: string;
  timestamp: string;
  payload: Record<string, unknown>;
  reply_to?: string;
}

interface VaultResponse {
  event_id: string;
  response_to: string;
  status: 'success' | 'error';
  timestamp: string;
  payload?: Record<string, unknown>;
  error?: string;
}

interface ControlCommand {
  command_id: string;
  command: 'shutdown' | 'backup' | 'restart' | 'reload_config';
  timestamp: string;
  source: 'vault_services' | 'admin' | 'mobile_app';
  auth_token: string;
  params?: Record<string, unknown>;
}

interface HealthMetrics {
  vault_id: string;
  timestamp: string;
  uptime_seconds: number;
  events_processed: number;
  events_failed: number;
  avg_processing_time_ms: number;
  handlers_loaded: number;
  handler_metrics: HandlerMetric[];
  nats_metrics: NatsMetrics;
  memory_usage_mb: number;
  cpu_percent: number;
}

interface HandlerMetric {
  handler_id: string;
  invocations: number;
  errors: number;
  avg_duration_ms: number;
  last_invoked_at?: string;
}

interface NatsMetrics {
  local_status: 'running' | 'stopped';
  local_connections: number;
  central_status: 'connected' | 'disconnected';
  central_latency_ms: number;
  messages_relayed: number;
  relay_errors: number;
}

// ============================================
// Mock Vault Manager Service
// ============================================

class MockVaultManagerService {
  private vaultId: string;
  private isRunning: boolean = false;
  private startTime: Date | null = null;
  private eventsProcessed: number = 0;
  private eventsFailed: number = 0;
  private totalProcessingTime: number = 0;
  private handlers: Map<string, HandlerMetric> = new Map();
  private pendingResponses: VaultResponse[] = [];
  private rateLimit: number = 100; // events per minute
  private rateLimitWindow: VaultEvent[] = [];
  private controlCommandAuth: Set<string> = new Set(['vault_services_token', 'admin_token']);
  private natsConnected: boolean = true;
  private localNatsRunning: boolean = true;

  constructor(vaultId: string) {
    this.vaultId = vaultId;
    // Initialize some default handlers
    this.handlers.set('default', {
      handler_id: 'default',
      invocations: 0,
      errors: 0,
      avg_duration_ms: 0,
    });
  }

  /**
   * Start the vault manager
   */
  start(): void {
    this.isRunning = true;
    this.startTime = new Date();
    this.localNatsRunning = true;
    this.natsConnected = true;
  }

  /**
   * Stop the vault manager
   */
  stop(): void {
    this.isRunning = false;
  }

  /**
   * Process an event from forVault topic
   */
  async processEvent(event: VaultEvent): Promise<VaultResponse> {
    if (!this.isRunning) {
      return {
        event_id: crypto.randomUUID(),
        response_to: event.event_id,
        status: 'error',
        timestamp: new Date().toISOString(),
        error: 'Vault manager not running',
      };
    }

    // Check rate limit
    if (!this.checkRateLimit()) {
      this.eventsFailed++;
      return {
        event_id: crypto.randomUUID(),
        response_to: event.event_id,
        status: 'error',
        timestamp: new Date().toISOString(),
        error: 'Rate limit exceeded',
      };
    }

    // Validate event
    const validationError = this.validateEvent(event);
    if (validationError) {
      this.eventsFailed++;
      return {
        event_id: crypto.randomUUID(),
        response_to: event.event_id,
        status: 'error',
        timestamp: new Date().toISOString(),
        error: validationError,
      };
    }

    // Simulate processing
    const startTime = Date.now();
    try {
      await this.executeHandler(event);
      const processingTime = Date.now() - startTime;
      this.eventsProcessed++;
      this.totalProcessingTime += processingTime;

      const response: VaultResponse = {
        event_id: crypto.randomUUID(),
        response_to: event.event_id,
        status: 'success',
        timestamp: new Date().toISOString(),
        payload: { processed: true, event_type: event.event_type },
      };

      this.pendingResponses.push(response);
      return response;
    } catch (error) {
      this.eventsFailed++;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return {
        event_id: crypto.randomUUID(),
        response_to: event.event_id,
        status: 'error',
        timestamp: new Date().toISOString(),
        error: errorMessage,
      };
    }
  }

  /**
   * Process a control command
   */
  async processControlCommand(command: ControlCommand): Promise<{ success: boolean; message: string }> {
    // Validate authorization
    if (!this.controlCommandAuth.has(command.auth_token)) {
      return { success: false, message: 'Unauthorized command' };
    }

    // Validate source
    if (command.source !== 'vault_services' && command.source !== 'admin') {
      return { success: false, message: 'Invalid command source' };
    }

    switch (command.command) {
      case 'shutdown':
        this.stop();
        return { success: true, message: 'Shutdown initiated' };

      case 'backup':
        if (!this.isRunning) {
          return { success: false, message: 'Vault not running' };
        }
        // Simulate backup
        await new Promise(resolve => setTimeout(resolve, 10));
        return { success: true, message: 'Backup completed' };

      case 'restart':
        this.stop();
        await new Promise(resolve => setTimeout(resolve, 10));
        this.start();
        return { success: true, message: 'Restart completed' };

      case 'reload_config':
        // Simulate config reload
        await new Promise(resolve => setTimeout(resolve, 5));
        return { success: true, message: 'Configuration reloaded' };

      default:
        return { success: false, message: 'Unknown command' };
    }
  }

  /**
   * Get health metrics
   */
  getHealthMetrics(): HealthMetrics {
    const now = new Date();
    const uptime = this.startTime ? Math.floor((now.getTime() - this.startTime.getTime()) / 1000) : 0;

    return {
      vault_id: this.vaultId,
      timestamp: now.toISOString(),
      uptime_seconds: uptime,
      events_processed: this.eventsProcessed,
      events_failed: this.eventsFailed,
      avg_processing_time_ms: this.eventsProcessed > 0
        ? this.totalProcessingTime / this.eventsProcessed
        : 0,
      handlers_loaded: this.handlers.size,
      handler_metrics: Array.from(this.handlers.values()),
      nats_metrics: {
        local_status: this.localNatsRunning ? 'running' : 'stopped',
        local_connections: this.localNatsRunning ? 1 : 0,
        central_status: this.natsConnected ? 'connected' : 'disconnected',
        central_latency_ms: this.natsConnected ? 10 : 0,
        messages_relayed: this.eventsProcessed,
        relay_errors: this.eventsFailed,
      },
      memory_usage_mb: 64 + (this.handlers.size * 8), // Simulated
      cpu_percent: Math.min(5 + (this.eventsProcessed * 0.1), 100), // Simulated
    };
  }

  /**
   * Get pending responses (for forApp topic)
   */
  getPendingResponses(): VaultResponse[] {
    const responses = [...this.pendingResponses];
    this.pendingResponses = [];
    return responses;
  }

  /**
   * Check if running
   */
  getIsRunning(): boolean {
    return this.isRunning;
  }

  /**
   * Load a handler
   */
  loadHandler(handlerId: string): void {
    this.handlers.set(handlerId, {
      handler_id: handlerId,
      invocations: 0,
      errors: 0,
      avg_duration_ms: 0,
    });
  }

  /**
   * Simulate NATS disconnection
   */
  simulateNatsDisconnection(): void {
    this.natsConnected = false;
  }

  /**
   * Simulate NATS reconnection
   */
  simulateNatsReconnection(): void {
    this.natsConnected = true;
  }

  /**
   * Simulate local NATS failure
   */
  simulateLocalNatsFailure(): void {
    this.localNatsRunning = false;
  }

  /**
   * Validate an event
   */
  private validateEvent(event: VaultEvent): string | null {
    if (!event.event_id) {
      return 'Missing event_id';
    }
    if (!event.event_type) {
      return 'Missing event_type';
    }
    if (!event.timestamp) {
      return 'Missing timestamp';
    }
    if (!event.payload) {
      return 'Missing payload';
    }

    // Validate event_type format
    if (!/^[a-zA-Z0-9_.-]+$/.test(event.event_type)) {
      return 'Invalid event_type format';
    }

    // Validate timestamp format
    const date = new Date(event.timestamp);
    if (isNaN(date.getTime())) {
      return 'Invalid timestamp format';
    }

    return null;
  }

  /**
   * Check rate limit
   */
  private checkRateLimit(): boolean {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;

    // Remove old events
    this.rateLimitWindow = this.rateLimitWindow.filter(
      e => new Date(e.timestamp).getTime() > oneMinuteAgo
    );

    if (this.rateLimitWindow.length >= this.rateLimit) {
      return false;
    }

    this.rateLimitWindow.push({
      event_id: crypto.randomUUID(),
      event_type: 'rate_limit_check',
      timestamp: new Date().toISOString(),
      payload: {},
    });

    return true;
  }

  /**
   * Execute handler for event
   */
  private async executeHandler(event: VaultEvent): Promise<void> {
    // Determine which handler to use based on event type
    const handlerId = this.handlers.has(event.event_type)
      ? event.event_type
      : 'default';

    const handler = this.handlers.get(handlerId);
    if (!handler) {
      throw new Error(`Handler not found: ${handlerId}`);
    }

    // Simulate handler execution
    const executionTime = 5 + Math.random() * 10;
    await new Promise(resolve => setTimeout(resolve, executionTime));

    // Update handler metrics
    handler.invocations++;
    handler.avg_duration_ms =
      (handler.avg_duration_ms * (handler.invocations - 1) + executionTime) / handler.invocations;
    handler.last_invoked_at = new Date().toISOString();
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.isRunning = false;
    this.startTime = null;
    this.eventsProcessed = 0;
    this.eventsFailed = 0;
    this.totalProcessingTime = 0;
    this.pendingResponses = [];
    this.rateLimitWindow = [];
    this.handlers.clear();
    this.handlers.set('default', {
      handler_id: 'default',
      invocations: 0,
      errors: 0,
      avg_duration_ms: 0,
    });
    this.natsConnected = true;
    this.localNatsRunning = true;
  }
}

// ============================================
// Tests
// ============================================

describe('Vault Manager', () => {
  let manager: MockVaultManagerService;
  const testVaultId = 'vault-test-12345';

  beforeEach(() => {
    manager = new MockVaultManagerService(testVaultId);
    manager.start();
  });

  afterEach(() => {
    manager.clear();
  });

  describe('Event Processing', () => {
    const createValidEvent = (overrides: Partial<VaultEvent> = {}): VaultEvent => ({
      event_id: crypto.randomUUID(),
      event_type: 'test.event',
      timestamp: new Date().toISOString(),
      payload: { data: 'test' },
      ...overrides,
    });

    it('should process events from forVault topic', async () => {
      const event = createValidEvent();

      const response = await manager.processEvent(event);

      expect(response.status).toBe('success');
      expect(response.response_to).toBe(event.event_id);
      expect(response.payload).toEqual({ processed: true, event_type: 'test.event' });
    });

    it('should publish responses to forApp topic', async () => {
      const event = createValidEvent();
      await manager.processEvent(event);

      const responses = manager.getPendingResponses();

      expect(responses).toHaveLength(1);
      expect(responses[0].response_to).toBe(event.event_id);
    });

    it('should handle malformed events gracefully', async () => {
      const malformedEvent = createValidEvent({ event_id: '' });

      const response = await manager.processEvent(malformedEvent);

      expect(response.status).toBe('error');
      expect(response.error).toBe('Missing event_id');
    });

    it('should reject events with missing event_type', async () => {
      const event = createValidEvent({ event_type: '' });

      const response = await manager.processEvent(event);

      expect(response.status).toBe('error');
      expect(response.error).toBe('Missing event_type');
    });

    it('should reject events with invalid timestamp', async () => {
      const event = createValidEvent({ timestamp: 'invalid-date' });

      const response = await manager.processEvent(event);

      expect(response.status).toBe('error');
      expect(response.error).toBe('Invalid timestamp format');
    });

    it('should reject events with missing payload', async () => {
      const event = createValidEvent({ payload: undefined as unknown as Record<string, unknown> });

      const response = await manager.processEvent(event);

      expect(response.status).toBe('error');
      expect(response.error).toBe('Missing payload');
    });

    it('should reject events with invalid event_type format', async () => {
      const event = createValidEvent({ event_type: 'event with spaces!' });

      const response = await manager.processEvent(event);

      expect(response.status).toBe('error');
      expect(response.error).toBe('Invalid event_type format');
    });

    it('should enforce rate limits', async () => {
      // Process events up to rate limit
      const events: Promise<VaultResponse>[] = [];
      for (let i = 0; i < 101; i++) {
        events.push(manager.processEvent(createValidEvent()));
      }

      const responses = await Promise.all(events);
      const rateLimitedResponses = responses.filter(r => r.error === 'Rate limit exceeded');

      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });

    it('should fail if vault manager not running', async () => {
      manager.stop();
      const event = createValidEvent();

      const response = await manager.processEvent(event);

      expect(response.status).toBe('error');
      expect(response.error).toBe('Vault manager not running');
    });

    it('should track event processing metrics', async () => {
      await manager.processEvent(createValidEvent());
      await manager.processEvent(createValidEvent());
      await manager.processEvent(createValidEvent());

      const metrics = manager.getHealthMetrics();

      expect(metrics.events_processed).toBe(3);
      expect(metrics.avg_processing_time_ms).toBeGreaterThan(0);
    });

    it('should handle different event types', async () => {
      manager.loadHandler('custom.handler');
      const event = createValidEvent({ event_type: 'custom.handler' });

      const response = await manager.processEvent(event);

      expect(response.status).toBe('success');
      expect(response.payload?.event_type).toBe('custom.handler');
    });

    it('should use default handler for unknown event types', async () => {
      const event = createValidEvent({ event_type: 'unknown.type' });

      const response = await manager.processEvent(event);

      expect(response.status).toBe('success');
    });
  });

  describe('Control Topic', () => {
    const createValidCommand = (overrides: Partial<ControlCommand> = {}): ControlCommand => ({
      command_id: crypto.randomUUID(),
      command: 'backup',
      timestamp: new Date().toISOString(),
      source: 'vault_services',
      auth_token: 'vault_services_token',
      ...overrides,
    });

    it('should accept commands from control topic', async () => {
      const command = createValidCommand();

      const result = await manager.processControlCommand(command);

      expect(result.success).toBe(true);
    });

    it('should process shutdown command', async () => {
      const command = createValidCommand({ command: 'shutdown' });

      const result = await manager.processControlCommand(command);

      expect(result.success).toBe(true);
      expect(result.message).toBe('Shutdown initiated');
      expect(manager.getIsRunning()).toBe(false);
    });

    it('should process backup command', async () => {
      const command = createValidCommand({ command: 'backup' });

      const result = await manager.processControlCommand(command);

      expect(result.success).toBe(true);
      expect(result.message).toBe('Backup completed');
    });

    it('should fail backup if vault not running', async () => {
      manager.stop();
      const command = createValidCommand({ command: 'backup' });

      const result = await manager.processControlCommand(command);

      expect(result.success).toBe(false);
      expect(result.message).toBe('Vault not running');
    });

    it('should process restart command', async () => {
      const command = createValidCommand({ command: 'restart' });

      const result = await manager.processControlCommand(command);

      expect(result.success).toBe(true);
      expect(result.message).toBe('Restart completed');
      expect(manager.getIsRunning()).toBe(true);
    });

    it('should process reload_config command', async () => {
      const command = createValidCommand({ command: 'reload_config' });

      const result = await manager.processControlCommand(command);

      expect(result.success).toBe(true);
      expect(result.message).toBe('Configuration reloaded');
    });

    it('should reject unauthorized commands', async () => {
      const command = createValidCommand({ auth_token: 'invalid_token' });

      const result = await manager.processControlCommand(command);

      expect(result.success).toBe(false);
      expect(result.message).toBe('Unauthorized command');
    });

    it('should reject commands from invalid source', async () => {
      const command = createValidCommand({ source: 'mobile_app' });

      const result = await manager.processControlCommand(command);

      expect(result.success).toBe(false);
      expect(result.message).toBe('Invalid command source');
    });

    it('should accept commands from admin source', async () => {
      const command = createValidCommand({ source: 'admin', auth_token: 'admin_token' });

      const result = await manager.processControlCommand(command);

      expect(result.success).toBe(true);
    });

    it('should reject unknown commands', async () => {
      const command = createValidCommand({ command: 'unknown' as ControlCommand['command'] });

      const result = await manager.processControlCommand(command);

      expect(result.success).toBe(false);
      expect(result.message).toBe('Unknown command');
    });
  });

  describe('Health Reporting', () => {
    it('should report health to monitoring endpoint', () => {
      const metrics = manager.getHealthMetrics();

      expect(metrics.vault_id).toBe(testVaultId);
      expect(metrics.timestamp).toBeDefined();
      expect(metrics.uptime_seconds).toBeGreaterThanOrEqual(0);
    });

    it('should include handler execution metrics', async () => {
      manager.loadHandler('test.handler');
      await manager.processEvent({
        event_id: crypto.randomUUID(),
        event_type: 'test.handler',
        timestamp: new Date().toISOString(),
        payload: {},
      });

      const metrics = manager.getHealthMetrics();
      const handlerMetric = metrics.handler_metrics.find(h => h.handler_id === 'test.handler');

      expect(handlerMetric).toBeDefined();
      expect(handlerMetric?.invocations).toBe(1);
      expect(handlerMetric?.avg_duration_ms).toBeGreaterThan(0);
    });

    it('should include NATS connection metrics', () => {
      const metrics = manager.getHealthMetrics();

      expect(metrics.nats_metrics).toBeDefined();
      expect(metrics.nats_metrics.local_status).toBe('running');
      expect(metrics.nats_metrics.central_status).toBe('connected');
    });

    it('should report local NATS status correctly', () => {
      manager.simulateLocalNatsFailure();

      const metrics = manager.getHealthMetrics();

      expect(metrics.nats_metrics.local_status).toBe('stopped');
      expect(metrics.nats_metrics.local_connections).toBe(0);
    });

    it('should report central NATS disconnection', () => {
      manager.simulateNatsDisconnection();

      const metrics = manager.getHealthMetrics();

      expect(metrics.nats_metrics.central_status).toBe('disconnected');
      expect(metrics.nats_metrics.central_latency_ms).toBe(0);
    });

    it('should track event counts in metrics', async () => {
      await manager.processEvent({
        event_id: crypto.randomUUID(),
        event_type: 'test.event',
        timestamp: new Date().toISOString(),
        payload: {},
      });

      // Create a failing event
      await manager.processEvent({
        event_id: '',
        event_type: 'test.event',
        timestamp: new Date().toISOString(),
        payload: {},
      });

      const metrics = manager.getHealthMetrics();

      expect(metrics.events_processed).toBe(1);
      expect(metrics.events_failed).toBe(1);
    });

    it('should include memory usage in metrics', () => {
      const metrics = manager.getHealthMetrics();

      expect(metrics.memory_usage_mb).toBeGreaterThan(0);
    });

    it('should include CPU usage in metrics', () => {
      const metrics = manager.getHealthMetrics();

      expect(metrics.cpu_percent).toBeGreaterThanOrEqual(0);
      expect(metrics.cpu_percent).toBeLessThanOrEqual(100);
    });

    it('should track uptime correctly', async () => {
      // Wait a bit
      await new Promise(resolve => setTimeout(resolve, 100));

      const metrics = manager.getHealthMetrics();

      expect(metrics.uptime_seconds).toBeGreaterThanOrEqual(0);
    });

    it('should count loaded handlers', () => {
      manager.loadHandler('handler1');
      manager.loadHandler('handler2');
      manager.loadHandler('handler3');

      const metrics = manager.getHealthMetrics();

      expect(metrics.handlers_loaded).toBe(4); // 3 + default
    });

    it('should track messages relayed in NATS metrics', async () => {
      await manager.processEvent({
        event_id: crypto.randomUUID(),
        event_type: 'test.event',
        timestamp: new Date().toISOString(),
        payload: {},
      });

      const metrics = manager.getHealthMetrics();

      expect(metrics.nats_metrics.messages_relayed).toBe(1);
    });

    it('should report zero uptime when not started', () => {
      manager.clear();
      // Don't call start()

      const metrics = manager.getHealthMetrics();

      expect(metrics.uptime_seconds).toBe(0);
    });

    it('should update handler metrics after multiple invocations', async () => {
      manager.loadHandler('multi.handler');

      for (let i = 0; i < 5; i++) {
        await manager.processEvent({
          event_id: crypto.randomUUID(),
          event_type: 'multi.handler',
          timestamp: new Date().toISOString(),
          payload: { iteration: i },
        });
      }

      const metrics = manager.getHealthMetrics();
      const handlerMetric = metrics.handler_metrics.find(h => h.handler_id === 'multi.handler');

      expect(handlerMetric?.invocations).toBe(5);
      expect(handlerMetric?.last_invoked_at).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    it('should track failed events separately from successful ones', async () => {
      // Success
      await manager.processEvent({
        event_id: crypto.randomUUID(),
        event_type: 'test.event',
        timestamp: new Date().toISOString(),
        payload: {},
      });

      // Fail (missing event_id)
      await manager.processEvent({
        event_id: '',
        event_type: 'test.event',
        timestamp: new Date().toISOString(),
        payload: {},
      });

      const metrics = manager.getHealthMetrics();

      expect(metrics.events_processed).toBe(1);
      expect(metrics.events_failed).toBe(1);
    });

    it('should return error response with details', async () => {
      const response = await manager.processEvent({
        event_id: '',
        event_type: 'test.event',
        timestamp: new Date().toISOString(),
        payload: {},
      });

      expect(response.status).toBe('error');
      expect(response.error).toBe('Missing event_id');
      expect(response.event_id).toBeDefined();
      expect(response.timestamp).toBeDefined();
    });

    it('should clear pending responses when retrieved', async () => {
      await manager.processEvent({
        event_id: crypto.randomUUID(),
        event_type: 'test.event',
        timestamp: new Date().toISOString(),
        payload: {},
      });

      const firstGet = manager.getPendingResponses();
      const secondGet = manager.getPendingResponses();

      expect(firstGet).toHaveLength(1);
      expect(secondGet).toHaveLength(0);
    });
  });

  describe('Lifecycle', () => {
    it('should start and stop correctly', () => {
      manager.stop();
      expect(manager.getIsRunning()).toBe(false);

      manager.start();
      expect(manager.getIsRunning()).toBe(true);
    });

    it('should clear all state on reset', async () => {
      await manager.processEvent({
        event_id: crypto.randomUUID(),
        event_type: 'test.event',
        timestamp: new Date().toISOString(),
        payload: {},
      });

      manager.clear();
      const metrics = manager.getHealthMetrics();

      expect(metrics.events_processed).toBe(0);
      expect(metrics.events_failed).toBe(0);
      expect(metrics.handlers_loaded).toBe(1); // Only default handler
    });

    it('should recover from NATS disconnection', () => {
      manager.simulateNatsDisconnection();
      expect(manager.getHealthMetrics().nats_metrics.central_status).toBe('disconnected');

      manager.simulateNatsReconnection();
      expect(manager.getHealthMetrics().nats_metrics.central_status).toBe('connected');
    });
  });
});
