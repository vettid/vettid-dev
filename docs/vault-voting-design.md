# Vault-Based Voting System Architecture

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Date | 2026-01-15 |
| Status | Proposal - Pending Review |
| Related | [NITRO-ENCLAVE-VAULT-ARCHITECTURE.md](./NITRO-ENCLAVE-VAULT-ARCHITECTURE.md) |

> **Note:** This document builds upon the Nitro Enclave Vault Architecture. For details on credential storage, key derivation, enrollment flows, and the Protean Credential system, see [NITRO-ENCLAVE-VAULT-ARCHITECTURE.md](./NITRO-ENCLAVE-VAULT-ARCHITECTURE.md).

---

## Executive Summary

This document outlines the architecture for migrating VettID's voting system from web-based to vault-based signing. The key innovation is that **user vaults sign votes**—the mobile app is a thin client that conveys user intent to the Nitro Enclave vault-manager.

### Goals

1. **Cryptographic Non-Repudiation**: Every vote is signed by the user's identity_keypair (inside the Protean Credential), creating an immutable audit trail
2. **Active Subscriber Enforcement**: Only users with active subscriptions can vote—verified at signing time
3. **Proposal Authenticity**: VettID signs proposals with an organizational key, so users can verify proposals are genuine
4. **Hardware-Backed Security**: Keys exist only inside attested Nitro Enclaves
5. **Password-Protected Operations**: Each vote requires credential password authorization

### Benefits

| Current (Web) | New (Vault) |
|---------------|-------------|
| No cryptographic proof | Ed25519 signatures on every vote |
| Trust web session | Trust attested Nitro Enclave |
| Subscription checked at login | Subscription verified at vote time |
| No proposal verification | VettID-signed proposals |
| Session-based authentication | Password-authorized vault operation |

---

## Vault Architecture Summary

> **Full details:** See [NITRO-ENCLAVE-VAULT-ARCHITECTURE.md](./NITRO-ENCLAVE-VAULT-ARCHITECTURE.md)

### Key Points for Voting

1. **Multi-tenant Nitro Enclave**: Multiple vault-manager processes run within a single hardware-isolated enclave
2. **Per-user SQLite database**: Each user has their own SQLite DB (in-memory, DEK-encrypted, synced to S3)
3. **Protean Credential**: User holds an encrypted blob containing their identity_keypair and crypto_keys—only the vault-manager can decrypt it
4. **Two-factor authentication**:
   - **PIN**: Unlocks the vault (DEK derivation) on app open
   - **Credential Password**: Authorizes each vault operation (like signing)

### Credential Storage

| Component | Location | Encryption |
|-----------|----------|------------|
| Protean Credential blob | Mobile app | CEK (X25519) |
| CEK private key | Vault SQLite | DEK |
| DEK | Derived in enclave | NSM sealed material + PIN |
| identity_keypair | Inside Protean Credential | CEK |

---

## Trust Model

```
┌────────────────────────────────────────────────────────────────────┐
│                      SYMMETRIC TRUST                                │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   VettID (Organization)              User (Voter)                   │
│   ─────────────────────              ─────────────                  │
│                                                                     │
│   Signs PROPOSALS with              Signs VOTES with                │
│   VettID org key (KMS)              identity_keypair (Ed25519)     │
│                                     inside Protean Credential       │
│                                                                     │
│   Proves: "This proposal            Proves: "I authorized my        │
│   is authentic and                  vault to cast this vote"        │
│   authorized by VettID"                                            │
│                                                                     │
│   Verified by: Mobile app           Verified by: Backend Lambda     │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘
```

---

## Vote Signing Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         Vote Operation Flow                                       │
│                                                                                  │
│  ┌────────────┐     ┌─────────────┐     ┌─────────────┐     ┌────────────────┐  │
│  │ Mobile App │     │ Central NATS│     │  Enclave    │     │ Backend Lambda │  │
│  └─────┬──────┘     └──────┬──────┘     └──────┬──────┘     └───────┬────────┘  │
│        │                   │                   │                    │           │
│        │ 1. Fetch proposals (verify VettID signature)              │           │
│        │◄──────────────────────────────────────────────────────────│           │
│        │                   │                   │                    │           │
│        │ 2. User taps "Vote Yes" on Proposal X │                    │           │
│        │                   │                   │                    │           │
│        │ 3. Send operation request             │                    │           │
│        │   { credential: <blob>,               │                    │           │
│        │     operation: "cast_vote",           │                    │           │
│        │     proposal_id: "...",               │                    │           │
│        │     choice: "yes" }                   │                    │           │
│        │──────────────────►│                   │                    │           │
│        │                   │──────────────────►│                    │           │
│        │                   │                   │                    │           │
│        │                   │                   │ 4. Decrypt credential          │
│        │                   │                   │    with CEK private key        │
│        │                   │                   │                    │           │
│        │ 5. Challenge: "Enter credential password"                 │           │
│        │◄──────────────────────────────────────│                    │           │
│        │   { challenge_id, utk_id }            │                    │           │
│        │                   │                   │                    │           │
│        │ 6. User enters password               │                    │           │
│        │    hash = Argon2id(password, salt)    │                    │           │
│        │    encrypted = UTK.Encrypt(hash)      │                    │           │
│        │                   │                   │                    │           │
│        │ 7. Send encrypted password hash       │                    │           │
│        │──────────────────►│──────────────────►│                    │           │
│        │                   │                   │                    │           │
│        │                   │                   │ 8. Verify password             │
│        │                   │                   │                    │           │
│        │                   │                   │ 9. Verify subscription         │
│        │                   │                   │                    │           │
│        │                   │                   │ 10. Create vote payload        │
│        │                   │                   │                    │           │
│        │                   │                   │ 11. Sign with identity_keypair │
│        │                   │                   │                    │           │
│        │                   │                   │ 12. Submit to backend          │
│        │                   │                   │────────────────────►│          │
│        │                   │                   │                    │           │
│        │                   │                   │                    │ 13. Verify│
│        │                   │                   │                    │  + Store  │
│        │                   │                   │◄────────────────────│          │
│        │                   │                   │                    │           │
│        │                   │                   │ 14. Rotate CEK                 │
│        │                   │                   │                    │           │
│        │ 15. Response: { receipt, new_credential }                 │           │
│        │◄──────────────────────────────────────│                    │           │
│        │                   │                   │                    │           │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Why Password Required

Voting is a **sensitive vault operation** that uses the user's identity_keypair to create a non-repudiable signature. Like signing a Bitcoin transaction, it requires the credential password to authorize:

- Physical device possession alone cannot cast votes
- User explicitly authorizes each vote
- Stolen credential blob is useless without password

---

## Component Changes

### 1. Mobile App

**New Screens:**
- Proposals List (fetch from backend, verify VettID signatures)
- Proposal Detail (show proposal, VettID signature status, vote options)
- Vote Confirmation (show signed receipt after voting)

**New Vault Operation:**
```typescript
const response = await vaultOperation({
  operation: "cast_vote",
  params: {
    proposal_id: "uuid",
    choice: "yes",  // "yes" | "no" | "abstain"
  }
});
// User prompted for credential password during operation
// Response includes signed receipt + rotated credential
```

### 2. Vault-Manager (New Operation)

**New Operation: `cast_vote`**

The vault-manager (inside the Nitro Enclave) handles this operation:

1. Decrypt credential with CEK
2. Challenge user for credential password
3. Verify password hash matches
4. Check subscription is active
5. Fetch proposal and verify VettID signature
6. Create vote payload: `{ proposal_id, choice, owner_id, public_key, timestamp, nonce }`
7. Sign with `identity_keypair.private_key` (Ed25519)
8. Submit signed vote to backend
9. Rotate CEK and return new credential blob

### 3. Backend Changes

#### 3.1 Proposal Signing (createProposal.ts)

Add KMS signing when creating proposals:

```typescript
const signedPayload = JSON.stringify({
  proposal_id, proposal_number, proposal_title,
  proposal_text, opens_at, closes_at, category,
  quorum_type, quorum_value, created_at
});

const signature = await kms.sign({
  KeyId: PROPOSAL_SIGNING_KEY,
  Message: Buffer.from(signedPayload),
  SigningAlgorithm: 'ECDSA_SHA_256',
});

// Store with proposal
proposal.signed_payload = signedPayload;
proposal.org_signature = signature;
```

#### 3.2 New Endpoint: Receive Signed Vote

**Endpoint:** `POST /vault/votes` (called by vault-manager)

1. Verify enclave attestation
2. Verify Ed25519 signature on vote payload
3. Verify public_key matches owner_id's enrolled identity
4. Check timestamp is recent (replay protection)
5. Store vote with signature
6. Return success

### 4. Admin Portal

**Minimal changes:** Proposal signing happens automatically on backend. Optionally show "Signed ✓" indicator.

### 5. Database Schema Changes

**Proposals Table** - Add:
- `signed_payload` (String) - Canonical JSON that was signed
- `org_signature` (String) - Base64 ECDSA signature from KMS
- `signing_key_id` (String) - KMS key ARN
- `merkle_root` (String) - Computed after voting closes
- `vote_list_url` (String) - S3 URL to published anonymized vote list
- `results_yes` (Number) - Final count
- `results_no` (Number) - Final count
- `results_abstain` (Number) - Final count

**Votes Table** - Add:
- `vote_hash` (String) - SHA256(proposal_id || nonce), for anonymized list
- `voting_public_key` (String) - Derived key (unlinkable to identity)
- `signature` (String) - Ed25519 signature with voting key
- `nonce` (String) - Random, known only to user for verification
- `identity_public_key` (String) - For backend verification only (not published)

**New GSI on Votes Table:**
- `proposal-voting-key-index`: PK=`proposal_id`, SK=`voting_public_key`
  - Allows lookup by voting key for verification

---

## Results Display & Verification (Hybrid Approach)

The results display balances three requirements:
1. **Privacy**: No one can identify how a specific person voted
2. **Transparency**: Anyone can independently verify the results
3. **Individual Verification**: Each voter can prove their vote was counted

### Design: Anonymized Bulletin Board + Merkle Proof

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Published After Polls Close                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Proposal: P0000123 - Budget Allocation 2026                                │
│  Status: CLOSED | Quorum: MET (200/150)                                     │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  RESULTS                                                            │    │
│  │  ═══════                                                            │    │
│  │  Yes:     127 votes (63.5%)  ████████████████████░░░░░░░░░░        │    │
│  │  No:       58 votes (29.0%)  █████████░░░░░░░░░░░░░░░░░░░░░        │    │
│  │  Abstain:  15 votes (7.5%)   ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░        │    │
│  │                                                                     │    │
│  │  Total: 200 votes                                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  Merkle Root: 3Qx7m9Np2kL8vR4tY6uI0oP...                                   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  ANONYMIZED VOTE LIST (for public audit)                           │    │
│  │  ════════════════════════════════════════                          │    │
│  │                                                                     │    │
│  │  Vote Hash        │ Choice  │ Voting Key          │ Sig Valid      │    │
│  │  ─────────────────┼─────────┼─────────────────────┼────────────    │    │
│  │  a8f3c2d9...      │ Yes     │ vk_7Hf9a2K...       │ ✓              │    │
│  │  b2d9e1f4...      │ No      │ vk_9Kp3b7L...       │ ✓              │    │
│  │  c5a7f3b8...      │ Yes     │ vk_2Nm8c4Q...       │ ✓              │    │
│  │  d1e6c9a2...      │ Abstain │ vk_5Rt7d9M...       │ ✓              │    │
│  │  ...              │ ...     │ ...                 │ ...            │    │
│  │                                                                     │    │
│  │  [Download Full List (JSON)]  [Verify All Signatures]              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  Anyone can:                                                                 │
│    ✓ Download the vote list and recount independently                      │
│    ✓ Verify all Ed25519 signatures are valid                               │
│    ✓ Verify Merkle root matches the vote list                              │
│    ✓ Confirm no votes were added, removed, or modified                     │
│                                                                              │
│  No one can:                                                                 │
│    ✗ Link a vote to a voter's identity (voting key ≠ identity key)         │
│    ✗ Determine who cast which vote                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### How Anonymity Works

Each vote is signed with a **one-time voting keypair** derived from the user's identity:

```
Derivation (inside vault-manager):
  voting_keypair = HKDF(
    ikm = identity_private_key,
    salt = proposal_id,
    info = "vettid-vote-v1"
  )

Published:
  voting_public_key  ← Different for each proposal, unlinkable to identity
  signature          ← Valid Ed25519, verifiable with voting_public_key

Privacy guarantee:
  - voting_public_key cannot be linked back to identity_public_key
  - Same user has different voting_public_key for each proposal
  - No pattern analysis possible across proposals
```

### Individual Verification (Mobile App)

Each voter can verify their own vote was included:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  My Vote - P0000123                                                          │
│  ═══════════════════                                                         │
│                                                                              │
│  Your Vote: YES                                                              │
│  Voted: January 15, 2026 at 2:32 PM                                         │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Verification                                                         │  │
│  │  ────────────                                                         │  │
│  │  ✓ Your signature is valid                                           │  │
│  │  ✓ Your vote appears in the published list                           │  │
│  │  ✓ Your vote is included in the Merkle tree                          │  │
│  │  ✓ The Merkle root matches the published root                        │  │
│  │                                                                       │  │
│  │  Your Vote Hash: a8f3c2d9...                                         │  │
│  │  Merkle Proof: [hash1, hash2, hash3, ...]                            │  │
│  │                                                                       │  │
│  │  [View Technical Details]                                             │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

The app can find the user's vote in the published list because it knows:
- The `voting_public_key` (derived deterministically from identity + proposal_id)
- The `vote_hash` (derived from nonce known only to the user)

### Data Structures

**Vote Record (stored in DynamoDB):**
```typescript
{
  proposal_id: string,
  vote_hash: string,              // SHA256(proposal_id || nonce) - for anonymized list
  choice: 'yes' | 'no' | 'abstain',
  voting_public_key: string,      // Derived key, unlinkable to identity
  signature: string,              // Ed25519 signature with voting key
  timestamp: number,
  nonce: string,                  // Known only to user, for finding their vote

  // Private fields (not published)
  owner_id: string,               // For internal lookup only
  identity_public_key: string,    // For backend verification only
}
```

**Published Vote List (after polls close):**
```json
{
  "proposal_id": "uuid",
  "merkle_root": "3Qx7m9Np2...",
  "votes": [
    {
      "vote_hash": "a8f3c2d9...",
      "choice": "yes",
      "voting_public_key": "vk_7Hf9a2K...",
      "signature": "sig_base64...",
      "timestamp": 1705334400000
    }
  ],
  "summary": {
    "yes": 127,
    "no": 58,
    "abstain": 15,
    "total": 200
  }
}
```

### Verification Capabilities

| Actor | Can Verify | Cannot Determine |
|-------|------------|------------------|
| **Any observer** | All signatures valid, totals correct, Merkle root matches | Who voted for what |
| **Individual voter** | Their vote is in the list and tree | Others' votes |
| **VettID admin** | All of the above | Who voted for what (owner_id not in published data) |
| **Third-party auditor** | Complete independent recount | Voter identities |

### Admin Portal Display

```typescript
// Proposal results component (admin portal)
function ProposalResults({ proposal }) {
  return (
    <div className="proposal-results">
      <h3>{proposal.proposal_number}: {proposal.proposal_title}</h3>

      <ResultsBar
        yes={proposal.results.yes}
        no={proposal.results.no}
        abstain={proposal.results.abstain}
      />

      <div className="verification-status">
        <span className="verified">✓ All {proposal.results.total} signatures verified</span>
        <span className="merkle">Merkle Root: {proposal.merkle_root.slice(0, 16)}...</span>
      </div>

      <button onClick={() => downloadVoteList(proposal.proposal_id)}>
        Download Vote List (JSON)
      </button>

      <button onClick={() => verifyAllSignatures(proposal.proposal_id)}>
        Run Independent Verification
      </button>
    </div>
  );
}
```

---

## Security Model

### Cryptographic Primitives

| Purpose | Algorithm | Key Location |
|---------|-----------|--------------|
| Proposal Signing | ECDSA-SHA256 | AWS KMS |
| Vote Signing | Ed25519 | identity_keypair in Protean Credential |
| Credential Encryption | X25519 + ChaCha20-Poly1305 | CEK in vault SQLite |
| Password Transport | X25519 (UTK/LTK) | Single-use keys |
| Database Encryption | AES-256 (DEK) | Derived from PIN + sealed_material |

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Forged proposal | VettID KMS signature verification |
| Forged vote | Ed25519 signature + public key binding |
| Replay attack | Timestamp window + unique nonce |
| Subscription bypass | Vault checks before signing |
| Compromised mobile | Keys only in Nitro Enclave |
| Password brute force | Rate limiting in vault-manager |
| Vote manipulation | Signatures stored for audit |

---

## Migration Path

### Phase 1: Backend Preparation
- Create KMS key for proposal signing
- Update `createProposal.ts` with signing
- Add signature fields to Proposals table
- Create `receiveSignedVote` endpoint
- Add signature fields to Votes table

### Phase 2: Vault-Manager Update
- Add `cast_vote` operation handler
- Add subscription + proposal verification
- Deploy updated enclave image

### Phase 3: Mobile App
- Add proposal list with signature verification
- Add vote flow with password challenge
- Add confirmation screen

### Phase 4: Parallel Operation
- Web voting remains for transition
- App voting for enrolled users

### Phase 5: Full Migration
- Web voting deprecated
- App voting required

---

## Open Questions

1. **Subscription caching**: Cache in vault or API call each vote?
2. **Vote changes**: Allow changing vote before close?
3. **Public key storage**: Store identity_public_key during enrollment for verification?
4. **Web read-only**: Show proposals on web (read-only)?

---

## Implementation Checklist

### Infrastructure (vettid-dev)
- [ ] Create KMS key for proposal signing (`vettid-proposal-signing`)
- [ ] Update Proposals table schema (add signature fields)
- [ ] Update Votes table schema (add voting_public_key, signature, vote_hash, nonce)
- [ ] Create receiveSignedVote Lambda
- [ ] Create publishVoteList Lambda (runs when proposal closes)
- [ ] Create S3 bucket for published vote lists

### Backend Lambda (vettid-dev)
- [ ] Update createProposal.ts with KMS signing
- [ ] Create receiveSignedVote.ts (verify signature, store vote)
- [ ] Create getPublishedVotes.ts (return anonymized vote list)
- [ ] Create generateMerkleRoot.ts (build tree when proposal closes)
- [ ] Create getVoteMerkleProof.ts (return proof for user's vote)
- [ ] Update closeExpiredProposals.ts to trigger vote list publication
- [ ] Add @noble/ed25519 and merkle tree library

### Vault-Manager (vettid-dev/enclave)
- [ ] Add cast_vote operation handler
- [ ] Implement voting keypair derivation (HKDF from identity + proposal_id)
- [ ] Add subscription verification
- [ ] Add proposal signature verification (verify VettID KMS signature)
- [ ] Return vote receipt with nonce (for user to find their vote later)
- [ ] Deploy updated enclave image (new PCRs)

### Mobile App - Android (vettid-android)
- [ ] Add Proposals list screen
- [ ] Verify VettID signature on proposals before display
- [ ] Add vote casting flow with password challenge
- [ ] Store vote receipt (nonce) locally after voting
- [ ] Add "My Votes" screen showing past votes
- [ ] Add vote verification: find vote in published list by voting_public_key
- [ ] Add Merkle proof verification UI
- [ ] Add "Download Vote List" / "Verify All" functionality

### Mobile App - iOS (vettid-ios)
- [ ] Add Proposals list screen
- [ ] Verify VettID signature on proposals before display
- [ ] Add vote casting flow with password challenge
- [ ] Store vote receipt (nonce) locally after voting
- [ ] Add "My Votes" screen showing past votes
- [ ] Add vote verification: find vote in published list by voting_public_key
- [ ] Add Merkle proof verification UI
- [ ] Add "Download Vote List" / "Verify All" functionality

### Admin Portal (vettid-dev/frontend/admin)
- [ ] Add proposal results display with vote counts
- [ ] Show Merkle root after proposal closes
- [ ] Add "Download Vote List (JSON)" button
- [ ] Add "Verify All Signatures" button
- [ ] Show signature verification status
