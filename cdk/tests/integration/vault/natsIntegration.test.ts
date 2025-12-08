/**
 * Integration Tests: Vault NATS Integration
 *
 * Tests NATS message routing between local and central NATS:
 * - Message relay from central to local
 * - Message relay from local to central
 * - Disconnection handling
 * - Automatic reconnection
 * - Message buffering during reconnection
 *
 * @see vault-manager/internal/nats/relay.go (pending implementation)
 */

import * as crypto from 'crypto';

// ============================================
// Types
// ============================================

interface NatsMessage {
  subject: string;
  payload: string;
  timestamp: string;
  replyTo?: string;
}

interface NatsConnectionState {
  connected: boolean;
  latencyMs: number;
  reconnecting: boolean;
  reconnectAttempts: number;
}

// ============================================
// Mock NATS Relay Service
// ============================================

class MockNatsRelayService {
  private localMessages: NatsMessage[] = [];
  private centralMessages: NatsMessage[] = [];
  private bufferedMessages: NatsMessage[] = [];
  private connectionState: NatsConnectionState = {
    connected: true,
    latencyMs: 10,
    reconnecting: false,
    reconnectAttempts: 0,
  };
  private localSubscriptions: Map<string, ((msg: NatsMessage) => void)[]> = new Map();
  private centralSubscriptions: Map<string, ((msg: NatsMessage) => void)[]> = new Map();
  private maxBufferSize = 100;
  private maxReconnectAttempts = 5;

  /**
   * Publish to local NATS
   */
  async publishLocal(subject: string, payload: string): Promise<boolean> {
    const message: NatsMessage = {
      subject,
      payload,
      timestamp: new Date().toISOString(),
    };

    this.localMessages.push(message);

    // Notify local subscribers
    this.notifySubscribers(this.localSubscriptions, subject, message);

    return true;
  }

  /**
   * Publish to central NATS
   */
  async publishCentral(subject: string, payload: string): Promise<boolean> {
    if (!this.connectionState.connected) {
      // Buffer message if disconnected
      if (this.bufferedMessages.length < this.maxBufferSize) {
        this.bufferedMessages.push({
          subject,
          payload,
          timestamp: new Date().toISOString(),
        });
        return true; // Buffered successfully
      }
      return false; // Buffer full
    }

    const message: NatsMessage = {
      subject,
      payload,
      timestamp: new Date().toISOString(),
    };

    this.centralMessages.push(message);

    // Notify central subscribers
    this.notifySubscribers(this.centralSubscriptions, subject, message);

    return true;
  }

  /**
   * Subscribe to local NATS subject
   */
  subscribeLocal(subject: string, callback: (msg: NatsMessage) => void): void {
    const subs = this.localSubscriptions.get(subject) || [];
    subs.push(callback);
    this.localSubscriptions.set(subject, subs);
  }

  /**
   * Subscribe to central NATS subject
   */
  subscribeCentral(subject: string, callback: (msg: NatsMessage) => void): void {
    const subs = this.centralSubscriptions.get(subject) || [];
    subs.push(callback);
    this.centralSubscriptions.set(subject, subs);
  }

  /**
   * Relay message from central to local
   */
  async relayFromCentralToLocal(subject: string, payload: string): Promise<boolean> {
    // Simulate receiving from central
    const message: NatsMessage = {
      subject,
      payload,
      timestamp: new Date().toISOString(),
    };

    // Forward to local subscribers
    this.notifySubscribers(this.localSubscriptions, subject, message);
    this.localMessages.push(message);

    return true;
  }

  /**
   * Relay message from local to central
   */
  async relayFromLocalToCentral(subject: string, payload: string): Promise<boolean> {
    return this.publishCentral(subject, payload);
  }

  /**
   * Simulate central NATS disconnection
   */
  simulateDisconnection(): void {
    this.connectionState.connected = false;
    this.connectionState.reconnecting = true;
    // Note: reconnectAttempts is NOT reset here - it persists across disconnection cycles
  }

  /**
   * Simulate reconnection
   */
  async simulateReconnection(): Promise<boolean> {
    if (this.connectionState.reconnectAttempts >= this.maxReconnectAttempts) {
      return false;
    }

    this.connectionState.reconnectAttempts++;

    // Simulate delay
    await new Promise(resolve => setTimeout(resolve, 10));

    this.connectionState.connected = true;
    this.connectionState.reconnecting = false;

    // Flush buffered messages
    for (const msg of this.bufferedMessages) {
      this.centralMessages.push(msg);
      this.notifySubscribers(this.centralSubscriptions, msg.subject, msg);
    }
    this.bufferedMessages = [];

    return true;
  }

  /**
   * Get connection state
   */
  getConnectionState(): NatsConnectionState {
    return { ...this.connectionState };
  }

  /**
   * Get buffered message count
   */
  getBufferedMessageCount(): number {
    return this.bufferedMessages.length;
  }

  /**
   * Get local messages
   */
  getLocalMessages(): NatsMessage[] {
    return [...this.localMessages];
  }

  /**
   * Get central messages
   */
  getCentralMessages(): NatsMessage[] {
    return [...this.centralMessages];
  }

  /**
   * Check if subject matches pattern
   */
  private matchesSubject(subject: string, pattern: string): boolean {
    if (subject === pattern) return true;

    const patternParts = pattern.split('.');
    const subjectParts = subject.split('.');

    for (let i = 0; i < patternParts.length; i++) {
      if (patternParts[i] === '>') return true;
      if (patternParts[i] === '*') continue;
      if (i >= subjectParts.length || patternParts[i] !== subjectParts[i]) {
        return false;
      }
    }

    return patternParts.length === subjectParts.length;
  }

  /**
   * Notify subscribers
   */
  private notifySubscribers(
    subscriptions: Map<string, ((msg: NatsMessage) => void)[]>,
    subject: string,
    message: NatsMessage
  ): void {
    for (const [pattern, callbacks] of subscriptions.entries()) {
      if (this.matchesSubject(subject, pattern)) {
        for (const callback of callbacks) {
          callback(message);
        }
      }
    }
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.localMessages = [];
    this.centralMessages = [];
    this.bufferedMessages = [];
    this.localSubscriptions.clear();
    this.centralSubscriptions.clear();
    this.connectionState = {
      connected: true,
      latencyMs: 10,
      reconnecting: false,
      reconnectAttempts: 0,
    };
  }
}

// ============================================
// Tests
// ============================================

describe('Vault NATS Integration', () => {
  let relay: MockNatsRelayService;

  beforeEach(() => {
    relay = new MockNatsRelayService();
  });

  describe('Message Relay: Central to Local', () => {
    it('should relay messages from central to local NATS', async () => {
      const receivedMessages: NatsMessage[] = [];

      relay.subscribeLocal('OwnerSpace.user1.forVault.>', (msg) => {
        receivedMessages.push(msg);
      });

      await relay.relayFromCentralToLocal(
        'OwnerSpace.user1.forVault.command',
        JSON.stringify({ action: 'sync' })
      );

      expect(receivedMessages).toHaveLength(1);
      expect(receivedMessages[0].subject).toBe('OwnerSpace.user1.forVault.command');
    });

    it('should maintain message order', async () => {
      const receivedMessages: NatsMessage[] = [];

      relay.subscribeLocal('events.>', (msg) => {
        receivedMessages.push(msg);
      });

      await relay.relayFromCentralToLocal('events.1', 'first');
      await relay.relayFromCentralToLocal('events.2', 'second');
      await relay.relayFromCentralToLocal('events.3', 'third');

      expect(receivedMessages.map(m => m.payload)).toEqual(['first', 'second', 'third']);
    });

    it('should include timestamp on relayed messages', async () => {
      const receivedMessages: NatsMessage[] = [];

      relay.subscribeLocal('test.>', (msg) => {
        receivedMessages.push(msg);
      });

      await relay.relayFromCentralToLocal('test.msg', 'payload');

      expect(receivedMessages[0].timestamp).toBeDefined();
      expect(new Date(receivedMessages[0].timestamp)).toBeInstanceOf(Date);
    });
  });

  describe('Message Relay: Local to Central', () => {
    it('should relay messages from local to central NATS', async () => {
      const receivedMessages: NatsMessage[] = [];

      relay.subscribeCentral('OwnerSpace.user1.forApp.>', (msg) => {
        receivedMessages.push(msg);
      });

      await relay.relayFromLocalToCentral(
        'OwnerSpace.user1.forApp.response',
        JSON.stringify({ status: 'ok' })
      );

      expect(receivedMessages).toHaveLength(1);
      expect(receivedMessages[0].subject).toBe('OwnerSpace.user1.forApp.response');
    });

    it('should handle large payloads', async () => {
      const largePayload = JSON.stringify({
        data: 'x'.repeat(10000),
      });

      const result = await relay.relayFromLocalToCentral('test.large', largePayload);
      expect(result).toBe(true);

      const messages = relay.getCentralMessages();
      expect(messages[0].payload).toBe(largePayload);
    });
  });

  describe('Central NATS Disconnection', () => {
    it('should handle central NATS disconnection', async () => {
      relay.simulateDisconnection();

      const state = relay.getConnectionState();
      expect(state.connected).toBe(false);
      expect(state.reconnecting).toBe(true);
    });

    it('should buffer messages during disconnection', async () => {
      relay.simulateDisconnection();

      await relay.publishCentral('test.msg1', 'buffered1');
      await relay.publishCentral('test.msg2', 'buffered2');

      expect(relay.getBufferedMessageCount()).toBe(2);
      expect(relay.getCentralMessages()).toHaveLength(0); // Not sent yet
    });

    it('should respect buffer size limit', async () => {
      relay.simulateDisconnection();

      // Try to buffer more than limit
      for (let i = 0; i < 150; i++) {
        await relay.publishCentral(`test.msg${i}`, `payload${i}`);
      }

      // Buffer should be at max
      expect(relay.getBufferedMessageCount()).toBe(100);
    });
  });

  describe('Automatic Reconnection', () => {
    it('should reconnect automatically after network issues', async () => {
      relay.simulateDisconnection();

      const reconnected = await relay.simulateReconnection();

      expect(reconnected).toBe(true);
      expect(relay.getConnectionState().connected).toBe(true);
    });

    it('should flush buffered messages after reconnection', async () => {
      const receivedMessages: NatsMessage[] = [];

      relay.subscribeCentral('test.>', (msg) => {
        receivedMessages.push(msg);
      });

      relay.simulateDisconnection();

      // Buffer some messages
      await relay.publishCentral('test.msg1', 'buffered1');
      await relay.publishCentral('test.msg2', 'buffered2');

      expect(relay.getBufferedMessageCount()).toBe(2);

      // Reconnect
      await relay.simulateReconnection();

      // Buffered messages should be delivered
      expect(receivedMessages).toHaveLength(2);
      expect(relay.getBufferedMessageCount()).toBe(0);
    });

    it('should track reconnection attempts', async () => {
      relay.simulateDisconnection();

      await relay.simulateReconnection();

      const state = relay.getConnectionState();
      expect(state.reconnectAttempts).toBe(1);
    });

    it('should stop reconnecting after max attempts', async () => {
      relay.simulateDisconnection();

      // Exhaust reconnection attempts (maxReconnectAttempts = 5)
      for (let i = 0; i < 5; i++) {
        await relay.simulateReconnection();
      }

      // 6th attempt should fail
      const result = await relay.simulateReconnection();

      expect(result).toBe(false);
    });
  });

  describe('Message Buffering During Reconnection', () => {
    it('should buffer messages during reconnection', async () => {
      relay.simulateDisconnection();

      const result = await relay.publishCentral('test.buffered', 'data');

      expect(result).toBe(true);
      expect(relay.getBufferedMessageCount()).toBe(1);
    });

    it('should preserve message order in buffer', async () => {
      const receivedMessages: NatsMessage[] = [];

      relay.subscribeCentral('test.>', (msg) => {
        receivedMessages.push(msg);
      });

      relay.simulateDisconnection();

      await relay.publishCentral('test.1', 'first');
      await relay.publishCentral('test.2', 'second');
      await relay.publishCentral('test.3', 'third');

      await relay.simulateReconnection();

      expect(receivedMessages.map(m => m.payload)).toEqual(['first', 'second', 'third']);
    });

    it('should clear buffer after successful flush', async () => {
      relay.simulateDisconnection();

      await relay.publishCentral('test.msg', 'data');
      expect(relay.getBufferedMessageCount()).toBe(1);

      await relay.simulateReconnection();
      expect(relay.getBufferedMessageCount()).toBe(0);
    });
  });

  describe('Subscription Pattern Matching', () => {
    it('should match > wildcard for all remaining segments', async () => {
      const receivedMessages: NatsMessage[] = [];

      relay.subscribeLocal('OwnerSpace.user1.>', (msg) => {
        receivedMessages.push(msg);
      });

      await relay.publishLocal('OwnerSpace.user1.forVault.cmd', 'msg1');
      await relay.publishLocal('OwnerSpace.user1.forApp.response', 'msg2');
      await relay.publishLocal('OwnerSpace.user1.control', 'msg3');

      expect(receivedMessages).toHaveLength(3);
    });

    it('should match * wildcard for single segment', async () => {
      const receivedMessages: NatsMessage[] = [];

      relay.subscribeLocal('events.*.created', (msg) => {
        receivedMessages.push(msg);
      });

      await relay.publishLocal('events.user.created', 'msg1');
      await relay.publishLocal('events.order.created', 'msg2');
      await relay.publishLocal('events.user.updated', 'msg3'); // Should not match

      expect(receivedMessages).toHaveLength(2);
    });

    it('should match exact subjects', async () => {
      const receivedMessages: NatsMessage[] = [];

      relay.subscribeLocal('specific.subject.only', (msg) => {
        receivedMessages.push(msg);
      });

      await relay.publishLocal('specific.subject.only', 'msg1');
      await relay.publishLocal('specific.subject', 'msg2'); // Should not match
      await relay.publishLocal('specific.subject.only.more', 'msg3'); // Should not match

      expect(receivedMessages).toHaveLength(1);
    });
  });

  describe('Connection State', () => {
    it('should report connected state', () => {
      const state = relay.getConnectionState();

      expect(state.connected).toBe(true);
      expect(state.latencyMs).toBeGreaterThanOrEqual(0);
      expect(state.reconnecting).toBe(false);
    });

    it('should report disconnected state', () => {
      relay.simulateDisconnection();

      const state = relay.getConnectionState();

      expect(state.connected).toBe(false);
      expect(state.reconnecting).toBe(true);
    });

    it('should report reconnecting state', () => {
      relay.simulateDisconnection();

      const state = relay.getConnectionState();

      expect(state.reconnecting).toBe(true);
      expect(state.reconnectAttempts).toBe(0);
    });
  });
});
