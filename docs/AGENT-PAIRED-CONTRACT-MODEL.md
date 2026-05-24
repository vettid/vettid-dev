# Agent Paired+Contract Model — Plan

Status: drafted 2026-05-24. Locked decisions captured below.

## Why

The agent today inherits the desktop-pairing data model wholesale —
`AgentSession` mirrors `DeviceSession` (status, expires_at,
last_active_at, key_rotation_count). That model fits a desktop client
that holds an authenticated UI session: you start it, it runs for an
hour or a day, it ends, you start a new one. An agent doesn't behave
that way. An agent is a long-lived sidecar that does (or doesn't)
have permission to do specific things on the user's behalf, period.

When we paired an agent today the user saw status pills showing
"session expired", expiry timers, key-rotation counters — fields that
don't correspond to anything the user has a mental model for. The
agent isn't a UI session that ended; it's a paired entity with a
running contract.

## The new model

An agent connection is in one of **two persistent states**:

| State | Meaning |
|---|---|
| `paired` | Pairing is in force. The agent can act within its Contract. |
| `revoked` | Owner has revoked the pairing. Terminal. |

Plus a **transient liveness signal**:

| Signal | Source | UI |
|---|---|---|
| Online | NATS heartbeat / presence | green dot on the card |
| Offline | absence of heartbeat for > N seconds | no dot |

There is **no `expired` state**. The pairing is persistent until the
owner revokes it (locked decision).

## Contract

The Contract — already partly implemented under
`ConnectionRecord.Contract` — is the single source of truth for what
the agent can do:

```
Contract {
    scope         []string   // e.g. ["secrets.catalog.read", "message.send"]
    approval_mode string     // "always_ask" | "auto_within_contract"
    rate_limit    int        // ops/hour cap; 0 = unlimited
}
```

The owner edits the Contract on the phone. Vault enforces. There's no
session-level fields (no expires_at, no last_active_at as state).
Last-active timestamp may still be tracked for the UI's "last seen"
display but is not a state field.

## Key rotation (kept under the hood)

The vault continues to rotate the per-pair session key periodically
for forward-secrecy hygiene — same protocol as today's
`agent.extend-session`. The owner sees nothing about this. The agent
auto-handles rotation on its side without prompting the user.

This means:
- `agent.extend-session` stays, but becomes a vault↔agent affair —
  no UI surface, no `key_rotations: N` row.
- The per-pair key is not the same byte-for-byte from pair time to
  revoke; the owner just doesn't have to think about it.

## What goes away

User-facing concepts that disappear with this model:

- "Session" as a noun (no `Session` section on the detail screen).
- "Started" / "Expires" / "Remaining" / "Key rotations" rows.
- The "End session now" button (an agent doesn't have a session to
  end; you either keep it paired or revoke it).
- Anywhere `AgentSession.Status == "expired"` is surfaced.

What replaces them on the detail screen:

- A "Contract" section showing Scope (list), Approval mode, Rate
  limit, with an Edit affordance.
- "Paired since" line (the original ConnectedAt — unchanged).
- "Last active" line (informational; not a state).
- Online dot on the avatar when the heartbeat is fresh.

## Migration of existing agents

The two agents we paired today (and any future test agents before
this lands) have `AgentSession.Status` populated. The vault will
treat any non-revoked record as `paired`. No data migration script
needed — we ignore the session-status field on read.

## Implementation phases

Each phase is a separate commit so we can ship + verify in order.

### Phase A — Vault: status semantics

- `agent.list` response drops session-specific fields. Returns:
  `{connection_id, agent_name, agent_type, status: "paired"|"revoked",
    scope, approval_mode, rate_limit, hostname, platform, paired_at,
    last_active_at}`.
- `ConnectionRecord.IsAgent() && !revoked` → status: `paired`. No
  inferred `expired`.
- `agent.end-session` op stays at the wire (backwards compat) but
  becomes a no-op for new clients; the vault logs it for audit.
- Vault `agent.extend-session` keeps existing key-rotation behavior.
- New owner-side op `agent.update-contract` lets the owner change
  scope / approval mode / rate limit without re-pairing.

### Phase B — Android UI

- `DesktopConnectionDetailScreen` branches on `connectionType`:
  - `"device"` → existing "Session" section.
  - `"agent"` → new "Contract" section + "Last active" line.
- Status pill: paired (green) / revoked (red). No "expired".
- ConnectionAvatar gets an optional online-dot overlay; the
  agent.list response carries `last_active_at` from which the row VM
  derives `isOnline = (now - last_active_at) < 60s`.
- AgentManagementScreen aligns on the same status vocabulary.

### Phase C — Desktop UI

- Mirror Android: `ConnectionWorkspace`'s agent two-tab shape
  (Messages / History) gets a third tab "Contract" surfacing the
  same fields.
- Online dot on the Connections-list row.

### Phase D — Agent connector auto-rotation

- `vettid-agent start` auto-fires `agent.extend-session` on the
  rotation interval (today it's owner-triggered). Owner never sees a
  prompt for rotation.
- `vettid-agent extend` CLI command kept for ops debugging, hidden
  from the user-facing flow.

## Open follow-ups (not blocking the plan)

- Contract editing UI: the owner needs a flow to flip a scope token
  or change approval mode without re-pairing. Could fit on the
  detail screen's Contract section as a sheet.
- Per-tool scope grammar (e.g. `agent.action.<tool>` patterns):
  punted indefinitely per existing memo, but a Contract that names
  bounded toolsets is the more natural eventual home.
- Cross-device agent visibility: today each phone sees its own
  paired agents; multi-device users want their agents visible from
  any of their devices. Out of scope for this plan.
