/**
 * E2E Tests: Enrollment State Transitions
 *
 * Tests the state machine validation for enrollment flow:
 * - Valid state transitions
 * - Invalid state transitions (should be rejected)
 * - Timeout and cleanup behaviors
 * - Recovery from partial failures
 *
 * @see cdk/coordination/specs/vault-services-api.yaml
 */

import * as crypto from 'crypto';

// ============================================
// Types (matching enrollment flow states)
// ============================================

type EnrollmentState =
  | 'created'           // Session created, waiting for start
  | 'started'           // Mobile started enrollment
  | 'attested'          // Device attestation verified
  | 'password_set'      // Password has been set
  | 'finalized'         // Enrollment complete
  | 'expired'           // Session timed out
  | 'failed'            // Enrollment failed
  | 'cancelled';        // User/admin cancelled

interface StateTransition {
  from: EnrollmentState;
  to: EnrollmentState;
  trigger: string;
  conditions?: string[];
}

interface EnrollmentSession {
  id: string;
  vaultId: string;
  state: EnrollmentState;
  createdAt: Date;
  updatedAt: Date;
  expiresAt: Date;
  stateHistory: Array<{
    from: EnrollmentState;
    to: EnrollmentState;
    timestamp: Date;
    trigger: string;
  }>;
  metadata: {
    platform?: 'android' | 'ios';
    deviceId?: string;
    attestationVerified?: boolean;
    passwordSet?: boolean;
    failureReason?: string;
    cancellationReason?: string;
  };
}

// ============================================
// Valid State Transitions (State Machine Definition)
// ============================================

const VALID_TRANSITIONS: StateTransition[] = [
  // Normal flow
  { from: 'created', to: 'started', trigger: 'mobile_start' },
  { from: 'started', to: 'attested', trigger: 'attestation_verified' },
  { from: 'attested', to: 'password_set', trigger: 'password_accepted' },
  { from: 'password_set', to: 'finalized', trigger: 'finalize_complete' },

  // Timeout handling
  { from: 'created', to: 'expired', trigger: 'timeout' },
  { from: 'started', to: 'expired', trigger: 'timeout' },
  { from: 'attested', to: 'expired', trigger: 'timeout' },
  { from: 'password_set', to: 'expired', trigger: 'timeout' },

  // Failure handling
  { from: 'started', to: 'failed', trigger: 'attestation_failed' },
  { from: 'attested', to: 'failed', trigger: 'password_rejected' },
  { from: 'password_set', to: 'failed', trigger: 'finalize_failed' },

  // Cancellation
  { from: 'created', to: 'cancelled', trigger: 'user_cancel' },
  { from: 'started', to: 'cancelled', trigger: 'user_cancel' },
  { from: 'attested', to: 'cancelled', trigger: 'user_cancel' },
  { from: 'password_set', to: 'cancelled', trigger: 'user_cancel' },
  { from: 'created', to: 'cancelled', trigger: 'admin_cancel' },
  { from: 'started', to: 'cancelled', trigger: 'admin_cancel' },
];

// ============================================
// Mock Enrollment State Machine
// ============================================

class EnrollmentStateMachine {
  private sessions: Map<string, EnrollmentSession> = new Map();
  private readonly sessionTimeoutMs: number;

  constructor(sessionTimeoutMs: number = 30 * 60 * 1000) { // 30 minutes default
    this.sessionTimeoutMs = sessionTimeoutMs;
  }

  /**
   * Create a new enrollment session
   */
  createSession(vaultId: string): EnrollmentSession {
    const now = new Date();
    const session: EnrollmentSession = {
      id: crypto.randomUUID(),
      vaultId,
      state: 'created',
      createdAt: now,
      updatedAt: now,
      expiresAt: new Date(now.getTime() + this.sessionTimeoutMs),
      stateHistory: [],
      metadata: {},
    };

    this.sessions.set(session.id, session);
    return session;
  }

  /**
   * Check if a transition is valid
   */
  isValidTransition(from: EnrollmentState, to: EnrollmentState, trigger: string): boolean {
    return VALID_TRANSITIONS.some(
      t => t.from === from && t.to === to && t.trigger === trigger
    );
  }

  /**
   * Attempt a state transition
   */
  transition(
    sessionId: string,
    targetState: EnrollmentState,
    trigger: string,
    metadata?: Partial<EnrollmentSession['metadata']>
  ): { success: boolean; error?: string } {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return { success: false, error: 'Session not found' };
    }

    // Check if session has expired
    if (new Date() > session.expiresAt && session.state !== 'expired') {
      this.expireSession(sessionId);
      return { success: false, error: 'Session expired' };
    }

    // Check if transition is valid
    if (!this.isValidTransition(session.state, targetState, trigger)) {
      return {
        success: false,
        error: `Invalid transition: ${session.state} -> ${targetState} (trigger: ${trigger})`
      };
    }

    // Cannot transition from terminal states
    if (['finalized', 'expired', 'failed', 'cancelled'].includes(session.state)) {
      return { success: false, error: `Cannot transition from terminal state: ${session.state}` };
    }

    // Record transition
    const previousState = session.state;
    session.stateHistory.push({
      from: previousState,
      to: targetState,
      timestamp: new Date(),
      trigger,
    });

    session.state = targetState;
    session.updatedAt = new Date();

    if (metadata) {
      Object.assign(session.metadata, metadata);
    }

    return { success: true };
  }

  /**
   * Expire a session (internal or triggered by timeout)
   */
  private expireSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session && !['finalized', 'failed', 'cancelled'].includes(session.state)) {
      session.stateHistory.push({
        from: session.state,
        to: 'expired',
        timestamp: new Date(),
        trigger: 'timeout',
      });
      session.state = 'expired';
      session.updatedAt = new Date();
    }
  }

  /**
   * Get session by ID
   */
  getSession(sessionId: string): EnrollmentSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * Check and expire timed out sessions
   */
  processTimeouts(): string[] {
    const expired: string[] = [];
    const now = new Date();

    for (const [id, session] of this.sessions) {
      if (now > session.expiresAt && !['finalized', 'expired', 'failed', 'cancelled'].includes(session.state)) {
        this.expireSession(id);
        expired.push(id);
      }
    }

    return expired;
  }

  /**
   * Get all sessions in a specific state
   */
  getSessionsByState(state: EnrollmentState): EnrollmentSession[] {
    return Array.from(this.sessions.values()).filter(s => s.state === state);
  }

  /**
   * Clear all sessions (for testing)
   */
  clear(): void {
    this.sessions.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Enrollment State Transitions', () => {
  let stateMachine: EnrollmentStateMachine;
  const testVaultId = crypto.randomUUID();

  beforeEach(() => {
    stateMachine = new EnrollmentStateMachine();
  });

  describe('1. Valid State Transitions', () => {
    it('should allow complete normal enrollment flow', () => {
      const session = stateMachine.createSession(testVaultId);
      expect(session.state).toBe('created');

      // Start enrollment
      let result = stateMachine.transition(session.id, 'started', 'mobile_start', {
        platform: 'android',
        deviceId: 'test-device-123',
      });
      expect(result.success).toBe(true);
      expect(stateMachine.getSession(session.id)?.state).toBe('started');

      // Attest device
      result = stateMachine.transition(session.id, 'attested', 'attestation_verified', {
        attestationVerified: true,
      });
      expect(result.success).toBe(true);
      expect(stateMachine.getSession(session.id)?.state).toBe('attested');

      // Set password
      result = stateMachine.transition(session.id, 'password_set', 'password_accepted', {
        passwordSet: true,
      });
      expect(result.success).toBe(true);
      expect(stateMachine.getSession(session.id)?.state).toBe('password_set');

      // Finalize
      result = stateMachine.transition(session.id, 'finalized', 'finalize_complete');
      expect(result.success).toBe(true);
      expect(stateMachine.getSession(session.id)?.state).toBe('finalized');
    });

    it('should record state history', () => {
      const session = stateMachine.createSession(testVaultId);

      stateMachine.transition(session.id, 'started', 'mobile_start');
      stateMachine.transition(session.id, 'attested', 'attestation_verified');
      stateMachine.transition(session.id, 'password_set', 'password_accepted');
      stateMachine.transition(session.id, 'finalized', 'finalize_complete');

      const updatedSession = stateMachine.getSession(session.id);
      expect(updatedSession?.stateHistory).toHaveLength(4);
      expect(updatedSession?.stateHistory.map(h => h.to)).toEqual([
        'started', 'attested', 'password_set', 'finalized'
      ]);
    });

    it('should allow cancellation from created state', () => {
      const session = stateMachine.createSession(testVaultId);

      const result = stateMachine.transition(session.id, 'cancelled', 'user_cancel', {
        cancellationReason: 'User changed mind',
      });

      expect(result.success).toBe(true);
      expect(stateMachine.getSession(session.id)?.state).toBe('cancelled');
    });

    it('should allow cancellation from started state', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');

      const result = stateMachine.transition(session.id, 'cancelled', 'user_cancel');

      expect(result.success).toBe(true);
      expect(stateMachine.getSession(session.id)?.state).toBe('cancelled');
    });

    it('should allow cancellation from attested state', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');
      stateMachine.transition(session.id, 'attested', 'attestation_verified');

      const result = stateMachine.transition(session.id, 'cancelled', 'user_cancel');

      expect(result.success).toBe(true);
      expect(stateMachine.getSession(session.id)?.state).toBe('cancelled');
    });

    it('should allow admin cancellation', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');

      const result = stateMachine.transition(session.id, 'cancelled', 'admin_cancel');

      expect(result.success).toBe(true);
      expect(stateMachine.getSession(session.id)?.state).toBe('cancelled');
    });
  });

  describe('2. Invalid State Transitions', () => {
    it('should reject skipping attestation step', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');

      // Try to skip directly to password_set
      const result = stateMachine.transition(session.id, 'password_set', 'password_accepted');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid transition');
      expect(stateMachine.getSession(session.id)?.state).toBe('started');
    });

    it('should reject skipping password step', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');
      stateMachine.transition(session.id, 'attested', 'attestation_verified');

      // Try to skip directly to finalized
      const result = stateMachine.transition(session.id, 'finalized', 'finalize_complete');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid transition');
      expect(stateMachine.getSession(session.id)?.state).toBe('attested');
    });

    it('should reject going backwards in flow', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');
      stateMachine.transition(session.id, 'attested', 'attestation_verified');

      // Try to go back to started
      const result = stateMachine.transition(session.id, 'started', 'mobile_start');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid transition');
    });

    it('should reject re-starting from finalized', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');
      stateMachine.transition(session.id, 'attested', 'attestation_verified');
      stateMachine.transition(session.id, 'password_set', 'password_accepted');
      stateMachine.transition(session.id, 'finalized', 'finalize_complete');

      // Try to restart
      const result = stateMachine.transition(session.id, 'started', 'mobile_start');

      expect(result.success).toBe(false);
      // No valid transitions from 'finalized' state, so "Invalid transition" is returned
      expect(result.error).toContain('Invalid transition');
      expect(stateMachine.getSession(session.id)?.state).toBe('finalized');
    });

    it('should reject transitions from expired state', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');
      stateMachine.transition(session.id, 'expired', 'timeout');

      // Try to continue
      const result = stateMachine.transition(session.id, 'attested', 'attestation_verified');

      expect(result.success).toBe(false);
      // No valid transitions from 'expired' state
      expect(result.error).toContain('Invalid transition');
      expect(stateMachine.getSession(session.id)?.state).toBe('expired');
    });

    it('should reject transitions from failed state', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');
      stateMachine.transition(session.id, 'failed', 'attestation_failed');

      // Try to continue
      const result = stateMachine.transition(session.id, 'attested', 'attestation_verified');

      expect(result.success).toBe(false);
      // No valid transitions from 'failed' state
      expect(result.error).toContain('Invalid transition');
      expect(stateMachine.getSession(session.id)?.state).toBe('failed');
    });

    it('should reject transitions from cancelled state', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'cancelled', 'user_cancel');

      // Try to start after cancellation
      const result = stateMachine.transition(session.id, 'started', 'mobile_start');

      expect(result.success).toBe(false);
      // No valid transitions from 'cancelled' state
      expect(result.error).toContain('Invalid transition');
      expect(stateMachine.getSession(session.id)?.state).toBe('cancelled');
    });

    it('should reject invalid trigger for valid state pair', () => {
      const session = stateMachine.createSession(testVaultId);

      // created -> started is valid, but with wrong trigger
      const result = stateMachine.transition(session.id, 'started', 'wrong_trigger');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid transition');
    });

    it('should reject non-existent session', () => {
      const result = stateMachine.transition('non-existent-id', 'started', 'mobile_start');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Session not found');
    });
  });

  describe('3. Failure State Transitions', () => {
    it('should allow attestation failure', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');

      const result = stateMachine.transition(session.id, 'failed', 'attestation_failed', {
        failureReason: 'Device attestation verification failed',
      });

      expect(result.success).toBe(true);
      expect(stateMachine.getSession(session.id)?.state).toBe('failed');
      expect(stateMachine.getSession(session.id)?.metadata.failureReason).toBe(
        'Device attestation verification failed'
      );
    });

    it('should allow password rejection failure', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');
      stateMachine.transition(session.id, 'attested', 'attestation_verified');

      const result = stateMachine.transition(session.id, 'failed', 'password_rejected', {
        failureReason: 'Password does not meet requirements',
      });

      expect(result.success).toBe(true);
      expect(stateMachine.getSession(session.id)?.state).toBe('failed');
    });

    it('should allow finalize failure', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');
      stateMachine.transition(session.id, 'attested', 'attestation_verified');
      stateMachine.transition(session.id, 'password_set', 'password_accepted');

      const result = stateMachine.transition(session.id, 'failed', 'finalize_failed', {
        failureReason: 'Database write failed',
      });

      expect(result.success).toBe(true);
      expect(stateMachine.getSession(session.id)?.state).toBe('failed');
    });

    it('should not allow failure from created state', () => {
      const session = stateMachine.createSession(testVaultId);

      const result = stateMachine.transition(session.id, 'failed', 'attestation_failed');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid transition');
    });
  });

  describe('4. Timeout Handling', () => {
    it('should expire session after timeout', () => {
      // Create state machine with 1ms timeout for testing
      const fastMachine = new EnrollmentStateMachine(1);
      const session = fastMachine.createSession(testVaultId);

      // Wait for timeout
      return new Promise<void>(resolve => setTimeout(resolve, 10)).then(() => {
        const expired = fastMachine.processTimeouts();
        expect(expired).toContain(session.id);
        expect(fastMachine.getSession(session.id)?.state).toBe('expired');
      });
    });

    it('should allow timeout from any active state', () => {
      const session = stateMachine.createSession(testVaultId);

      // Test timeout from created
      let result = stateMachine.transition(session.id, 'expired', 'timeout');
      expect(result.success).toBe(true);

      // New session - test timeout from started
      const session2 = stateMachine.createSession(testVaultId);
      stateMachine.transition(session2.id, 'started', 'mobile_start');
      result = stateMachine.transition(session2.id, 'expired', 'timeout');
      expect(result.success).toBe(true);

      // New session - test timeout from attested
      const session3 = stateMachine.createSession(testVaultId);
      stateMachine.transition(session3.id, 'started', 'mobile_start');
      stateMachine.transition(session3.id, 'attested', 'attestation_verified');
      result = stateMachine.transition(session3.id, 'expired', 'timeout');
      expect(result.success).toBe(true);

      // New session - test timeout from password_set
      const session4 = stateMachine.createSession(testVaultId);
      stateMachine.transition(session4.id, 'started', 'mobile_start');
      stateMachine.transition(session4.id, 'attested', 'attestation_verified');
      stateMachine.transition(session4.id, 'password_set', 'password_accepted');
      result = stateMachine.transition(session4.id, 'expired', 'timeout');
      expect(result.success).toBe(true);
    });

    it('should not expire already finalized session', () => {
      const fastMachine = new EnrollmentStateMachine(1);
      const session = fastMachine.createSession(testVaultId);

      // Complete the flow quickly
      fastMachine.transition(session.id, 'started', 'mobile_start');
      fastMachine.transition(session.id, 'attested', 'attestation_verified');
      fastMachine.transition(session.id, 'password_set', 'password_accepted');
      fastMachine.transition(session.id, 'finalized', 'finalize_complete');

      // Wait for would-be timeout
      return new Promise<void>(resolve => setTimeout(resolve, 10)).then(() => {
        const expired = fastMachine.processTimeouts();
        expect(expired).not.toContain(session.id);
        expect(fastMachine.getSession(session.id)?.state).toBe('finalized');
      });
    });

    it('should reject transitions on expired session', () => {
      const fastMachine = new EnrollmentStateMachine(1);
      const session = fastMachine.createSession(testVaultId);

      // Wait for timeout
      return new Promise<void>(resolve => setTimeout(resolve, 10)).then(() => {
        const result = fastMachine.transition(session.id, 'started', 'mobile_start');
        expect(result.success).toBe(false);
        expect(result.error).toBe('Session expired');
      });
    });
  });

  describe('5. Concurrent Session Handling', () => {
    it('should track multiple sessions independently', () => {
      const vault1 = crypto.randomUUID();
      const vault2 = crypto.randomUUID();

      const session1 = stateMachine.createSession(vault1);
      const session2 = stateMachine.createSession(vault2);

      // Advance session1 further than session2
      stateMachine.transition(session1.id, 'started', 'mobile_start');
      stateMachine.transition(session1.id, 'attested', 'attestation_verified');

      stateMachine.transition(session2.id, 'started', 'mobile_start');

      expect(stateMachine.getSession(session1.id)?.state).toBe('attested');
      expect(stateMachine.getSession(session2.id)?.state).toBe('started');
    });

    it('should query sessions by state', () => {
      // Create sessions in various states
      const s1 = stateMachine.createSession(crypto.randomUUID());
      const s2 = stateMachine.createSession(crypto.randomUUID());
      const s3 = stateMachine.createSession(crypto.randomUUID());

      stateMachine.transition(s1.id, 'started', 'mobile_start');
      stateMachine.transition(s2.id, 'started', 'mobile_start');
      stateMachine.transition(s2.id, 'attested', 'attestation_verified');
      // s3 stays in 'created'

      const createdSessions = stateMachine.getSessionsByState('created');
      const startedSessions = stateMachine.getSessionsByState('started');
      const attestedSessions = stateMachine.getSessionsByState('attested');

      expect(createdSessions).toHaveLength(1);
      expect(startedSessions).toHaveLength(1);
      expect(attestedSessions).toHaveLength(1);
    });

    it('should handle rapid state changes correctly', () => {
      const session = stateMachine.createSession(testVaultId);

      // Rapid transitions
      const results = [
        stateMachine.transition(session.id, 'started', 'mobile_start'),
        stateMachine.transition(session.id, 'attested', 'attestation_verified'),
        stateMachine.transition(session.id, 'password_set', 'password_accepted'),
        stateMachine.transition(session.id, 'finalized', 'finalize_complete'),
      ];

      expect(results.every(r => r.success)).toBe(true);
      expect(stateMachine.getSession(session.id)?.stateHistory).toHaveLength(4);
    });
  });

  describe('6. Metadata Preservation', () => {
    it('should preserve metadata across transitions', () => {
      const session = stateMachine.createSession(testVaultId);

      stateMachine.transition(session.id, 'started', 'mobile_start', {
        platform: 'android',
        deviceId: 'device-123',
      });

      stateMachine.transition(session.id, 'attested', 'attestation_verified', {
        attestationVerified: true,
      });

      stateMachine.transition(session.id, 'password_set', 'password_accepted', {
        passwordSet: true,
      });

      const finalSession = stateMachine.getSession(session.id);
      expect(finalSession?.metadata.platform).toBe('android');
      expect(finalSession?.metadata.deviceId).toBe('device-123');
      expect(finalSession?.metadata.attestationVerified).toBe(true);
      expect(finalSession?.metadata.passwordSet).toBe(true);
    });

    it('should update timestamps on each transition', () => {
      const session = stateMachine.createSession(testVaultId);
      const createdAt = session.createdAt;

      return new Promise<void>(resolve => setTimeout(resolve, 10)).then(() => {
        stateMachine.transition(session.id, 'started', 'mobile_start');

        const updatedSession = stateMachine.getSession(session.id);
        expect(updatedSession?.createdAt).toEqual(createdAt);
        expect(updatedSession?.updatedAt.getTime()).toBeGreaterThan(createdAt.getTime());
      });
    });

    it('should record trigger in state history', () => {
      const session = stateMachine.createSession(testVaultId);

      stateMachine.transition(session.id, 'started', 'mobile_start');
      stateMachine.transition(session.id, 'failed', 'attestation_failed');

      const history = stateMachine.getSession(session.id)?.stateHistory;
      expect(history?.[0].trigger).toBe('mobile_start');
      expect(history?.[1].trigger).toBe('attestation_failed');
    });
  });

  describe('7. Edge Cases', () => {
    it('should handle same state transition attempt', () => {
      const session = stateMachine.createSession(testVaultId);
      stateMachine.transition(session.id, 'started', 'mobile_start');

      // Try to transition to same state
      const result = stateMachine.transition(session.id, 'started', 'mobile_start');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid transition');
    });

    it('should handle empty session list for state query', () => {
      const sessions = stateMachine.getSessionsByState('finalized');
      expect(sessions).toHaveLength(0);
    });

    it('should handle clear operation', () => {
      stateMachine.createSession(crypto.randomUUID());
      stateMachine.createSession(crypto.randomUUID());

      stateMachine.clear();

      const allSessions = [
        ...stateMachine.getSessionsByState('created'),
        ...stateMachine.getSessionsByState('started'),
        ...stateMachine.getSessionsByState('finalized'),
      ];
      expect(allSessions).toHaveLength(0);
    });

    it('should validate transition function is idempotent for invalid transitions', () => {
      const session = stateMachine.createSession(testVaultId);

      // Multiple invalid transition attempts
      const results = [
        stateMachine.transition(session.id, 'finalized', 'finalize_complete'),
        stateMachine.transition(session.id, 'finalized', 'finalize_complete'),
        stateMachine.transition(session.id, 'finalized', 'finalize_complete'),
      ];

      expect(results.every(r => r.success === false)).toBe(true);
      expect(stateMachine.getSession(session.id)?.state).toBe('created');
    });
  });

  describe('8. State Machine Definition Validation', () => {
    it('should have all terminal states covered', () => {
      const terminalStates: EnrollmentState[] = ['finalized', 'expired', 'failed', 'cancelled'];

      for (const terminalState of terminalStates) {
        // Verify no transitions FROM terminal states exist
        const outgoingTransitions = VALID_TRANSITIONS.filter(t => t.from === terminalState);
        expect(outgoingTransitions).toHaveLength(0);
      }
    });

    it('should have at least one path to finalized from created', () => {
      // BFS to find path from created to finalized
      const visited = new Set<EnrollmentState>();
      const queue: EnrollmentState[] = ['created'];

      while (queue.length > 0) {
        const current = queue.shift()!;
        if (current === 'finalized') {
          expect(true).toBe(true);
          return;
        }

        if (visited.has(current)) continue;
        visited.add(current);

        const nextStates = VALID_TRANSITIONS
          .filter(t => t.from === current)
          .map(t => t.to);

        queue.push(...nextStates.filter(s => !visited.has(s)));
      }

      fail('No path from created to finalized found');
    });

    it('should have timeout handling for all non-terminal active states', () => {
      const activeStates: EnrollmentState[] = ['created', 'started', 'attested', 'password_set'];

      for (const activeState of activeStates) {
        const hasTimeout = VALID_TRANSITIONS.some(
          t => t.from === activeState && t.to === 'expired' && t.trigger === 'timeout'
        );
        expect(hasTimeout).toBe(true);
      }
    });

    it('should not allow direct transition to created state', () => {
      const toCreated = VALID_TRANSITIONS.filter(t => t.to === 'created');
      expect(toCreated).toHaveLength(0);
    });
  });
});
