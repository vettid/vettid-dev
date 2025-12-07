# VettID Coordination Directory

This directory enables coordination between multiple Claude Code instances working on the VettID Vault Services implementation.

## Instance Roles

| Instance | Role | Primary Focus |
|----------|------|---------------|
| **Orchestrator** | Main coordinator | CDK infrastructure, Lambda handlers, task assignment |
| **Testing** | Quality assurance | API tests, integration tests, security validation |
| **Android** | Mobile (Android) | Android app development and testing |
| **iOS** | Mobile (iOS) | iOS app development and testing |

## Directory Structure

```
coordination/
├── README.md              # This file
├── status/                # Instance status files (JSON)
│   ├── orchestrator.json
│   ├── testing.json
│   ├── android.json
│   └── ios.json
├── tasks/                 # Current task assignments
│   ├── testing/
│   │   └── current-task.md
│   ├── android/
│   │   └── current-task.md
│   └── ios/
│       └── current-task.md
├── specs/                 # API and format specifications
│   ├── vault-services-api.yaml   # OpenAPI 3.0 spec
│   ├── nats-topics.md            # NATS topic structure
│   └── credential-format.md      # Credential blob format
├── results/               # Output from other instances
│   ├── test-results/      # Test execution results
│   └── issues/            # Discovered issues
└── handoffs/              # Phase completion documents
    └── {date}-{phase}-handoff.md
```

## Communication Protocol

### Status Updates

Each instance maintains a status file in `status/`. Update this file when:
- Starting a new task
- Completing a task
- Encountering a blocker
- Finishing a phase

**Status file format:**
```json
{
  "instance": "orchestrator|testing|android|ios",
  "phase": 0,
  "task": "Current task description",
  "status": "in_progress|blocked|completed|waiting",
  "blockers": [],
  "completedTasks": [],
  "lastUpdated": "2025-12-07T00:00:00Z",
  "notes": "Additional context"
}
```

### Task Assignment

The Orchestrator assigns tasks via `tasks/{instance}/current-task.md`. Other instances should:
1. Read their current task file
2. Update their status file to "in_progress"
3. Complete the task
4. Update status to "completed"
5. Document results in `results/`

### Reporting Issues

When discovering issues:
1. Create a file in `results/issues/` with format `{date}-{instance}-{brief-description}.md`
2. Include: description, reproduction steps, severity, suggested fix
3. Update status file if blocked

### Phase Handoffs

When the Orchestrator completes a phase:
1. Creates handoff document in `handoffs/`
2. Updates all task files with next phase assignments
3. Other instances acknowledge by updating their status

## Getting Started

1. Read the development plan: `cdk/docs/DEVELOPMENT_PLAN.md`
2. Read your assigned task: `tasks/{your-instance}/current-task.md`
3. Read relevant specs in `specs/`
4. Update your status file
5. Begin work
6. Report progress and issues

## Specs Quick Reference

- **API Endpoints**: See `specs/vault-services-api.yaml`
- **NATS Topics**: See `specs/nats-topics.md`
- **Credential Format**: See `specs/credential-format.md`

## Current Phase

**Phase 0: Foundation & Coordination Setup**

See `cdk/docs/DEVELOPMENT_PLAN.md` for full phase details.
