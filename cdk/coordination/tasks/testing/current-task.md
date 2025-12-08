# Task: Phase 5 - Vault Instance Testing

## Phase
Phase 5: Vault Instance (EC2)

## Assigned To
Testing Instance

## Repository
`github.com/mesmerverse/vettid-dev`

## Status
Phase 4 complete. Ready for Phase 5 vault instance testing.

## Overview

Phase 5 introduces the Vault Instance - an EC2-based service that runs on ARM64 t4g.nano instances. The vault instance:
- Runs a local NATS server
- Connects to the central NATS cluster
- Executes the Vault Manager service (Go)
- Processes events from the mobile app via NATS

## New Infrastructure

### Vault Provisioning Handlers
- `POST /vault/provision` - Spin up EC2 instance for user
- `POST /vault/initialize` - Configure vault after provision
- `POST /vault/stop` - Stop vault instance
- `POST /vault/terminate` - Terminate vault instance
- `GET /vault/health` - Health check endpoint

### Vault Manager Service
The Vault Manager is a Go service running on each vault instance:
```
vault-manager/
├── cmd/main.go
├── internal/
│   ├── nats/         # NATS client (local + central)
│   ├── events/       # Event processing
│   ├── handlers/     # WASM handler execution
│   └── health/       # Health monitoring
└── configs/
```

## Phase 5 Testing Tasks

### 1. Vault Provisioning Tests

Create tests for provisioning lifecycle:

```
cdk/tests/integration/vault/
├── provisioning.test.ts      # EC2 instance provisioning
├── initialization.test.ts    # Vault configuration
├── healthCheck.test.ts       # Health endpoint
└── gracefulShutdown.test.ts  # Stop/terminate flow
```

#### provisioning.test.ts
```typescript
describe('POST /vault/provision', () => {
  it('should provision vault for authenticated member');
  it('should return instance_id and provisioning status');
  it('should reject duplicate provisioning for same user');
  it('should assign unique security group per instance');
  it('should use correct AMI (ARM64, hardened)');
  it('should apply correct instance tags');
  it('should timeout if provisioning takes >2 minutes');
  it('should require active NATS account');
});
```

#### initialization.test.ts
```typescript
describe('POST /vault/initialize', () => {
  it('should configure vault after EC2 is running');
  it('should assign OwnerSpace namespace');
  it('should assign MessageSpace namespace');
  it('should start local NATS server');
  it('should connect to central NATS cluster');
  it('should install user credentials');
  it('should return initialization status');
  it('should fail gracefully if EC2 not ready');
});
```

#### healthCheck.test.ts
```typescript
describe('GET /vault/health', () => {
  it('should return healthy for running vault');
  it('should include local NATS status');
  it('should include central NATS connection status');
  it('should include Vault Manager process status');
  it('should include memory/CPU usage');
  it('should return unhealthy with details on failure');
  it('should require vault to be provisioned');
});
```

#### gracefulShutdown.test.ts
```typescript
describe('Vault Lifecycle', () => {
  describe('POST /vault/stop', () => {
    it('should stop vault gracefully');
    it('should flush pending events');
    it('should disconnect from central NATS');
    it('should preserve state for restart');
  });

  describe('POST /vault/terminate', () => {
    it('should terminate EC2 instance');
    it('should clean up security group');
    it('should revoke NATS credentials');
    it('should update vault status to terminated');
    it('should be idempotent');
  });
});
```

### 2. E2E Vault Lifecycle Tests

```typescript
// tests/e2e/vaultLifecycle.test.ts
describe('Full Vault Lifecycle', () => {
  it('should complete: provision → initialize → health → stop → terminate');
  it('should allow restart after stop');
  it('should recover from initialization failure');
  it('should handle concurrent health checks');
});
```

### 3. NATS Integration Tests

```typescript
// tests/integration/vault/natsIntegration.test.ts
describe('Vault NATS Integration', () => {
  it('should relay messages from central to local NATS');
  it('should relay messages from local to central NATS');
  it('should handle central NATS disconnection');
  it('should reconnect automatically after network issues');
  it('should buffer messages during reconnection');
});
```

### 4. Vault Manager Mock Tests

```typescript
// tests/integration/vault/vaultManager.test.ts
describe('Vault Manager', () => {
  describe('Event Processing', () => {
    it('should process events from forVault topic');
    it('should publish responses to forApp topic');
    it('should handle malformed events gracefully');
    it('should enforce rate limits');
  });

  describe('Control Topic', () => {
    it('should accept commands from control topic');
    it('should process shutdown command');
    it('should process backup command');
    it('should reject unauthorized commands');
  });

  describe('Health Reporting', () => {
    it('should report health to monitoring endpoint');
    it('should include handler execution metrics');
    it('should include NATS connection metrics');
  });
});
```

## Response Structures

### Provision Response
```typescript
{
  instance_id: string;
  status: 'provisioning' | 'running' | 'failed';
  region: string;
  availability_zone: string;
  private_ip?: string;
  estimated_ready_at: string;
}
```

### Initialize Response
```typescript
{
  status: 'initialized' | 'failed';
  local_nats_status: 'running' | 'stopped';
  central_nats_status: 'connected' | 'disconnected';
  owner_space_id: string;
  message_space_id: string;
}
```

### Health Response
```typescript
{
  status: 'healthy' | 'unhealthy' | 'degraded';
  uptime_seconds: number;
  local_nats: {
    status: 'running' | 'stopped';
    connections: number;
  };
  central_nats: {
    status: 'connected' | 'disconnected';
    latency_ms: number;
  };
  vault_manager: {
    status: 'running' | 'stopped';
    memory_mb: number;
    cpu_percent: number;
    handlers_loaded: number;
  };
  last_event_at?: string;
}
```

## Acceptance Criteria

- [ ] Provisioning tests validate EC2 lifecycle
- [ ] Initialization tests verify NATS setup
- [ ] Health check tests cover all status scenarios
- [ ] Graceful shutdown tests verify cleanup
- [ ] E2E tests cover full lifecycle
- [ ] NATS relay tests verify message routing
- [ ] All tests use mocks (no actual EC2 provisioning in CI)

## Status Update

```bash
cd /path/to/vettid-dev
git pull
# Create test files
git add cdk/tests/integration/vault/
git commit -m "Phase 5: Add vault instance tests"
git push

# Update status
# Edit cdk/coordination/status/testing.json
git add cdk/coordination/status/testing.json
git commit -m "Update Testing status: Phase 5 vault instance tests"
git push
```
