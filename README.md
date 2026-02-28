# Oath Protocol

> The open protocol for cryptographically verifiable human intent.

Oath is an open protocol for cryptographically verifiable human intent attestation. It enables any human to sign a structured statement of intent locally, store it in a tamper-evident append-only log, and allow any system anywhere to verify that statement — without trusting any central authority, server, or intermediary.

---

## The Problem

Did a specific human actually intend this — and can you prove it, after the fact, without trusting anyone?

That question is older than computing. It shows up when an AI agent takes an action nobody authorized. When a petition gets inflated by bots. When a commitment in an informal market gets disputed. When collective consent is manufactured rather than given.

Every existing authorization system answers a different question: *"does this service have permission to act on my behalf?"*

Oath answers the harder one: **"did this specific human actually intend for this specific action to happen, and can I prove it cryptographically, after the fact, without trusting any intermediary?"**

---

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  Human signs intent locally   →   Agent verifies before acting  │
│  No server. No network. No authority. Just cryptography.    │
└─────────────────────────────────────────────────────────────┘
```

1. **Human attests intent** — `oath attest --action "database:delete_records:project_alpha" --context "cleanup approved"`
2. **Agent checks before acting** — one function call: `oath::verify("database:delete_records:project_alpha")`
3. **Result is cryptographic proof** — verified or blocked, with a tamper-evident audit trail

---

## What You Get

After an agent completes a task, Oath produces an unforgeable audit log:

```
TASK AUDIT — "Clean up project workspace"
─────────────────────────────────────────────────────────────────────
✓ ATTESTED   db:compress_logs:alpha     proof: sha256:a1b2c3  09:12:01Z
✓ ATTESTED   email:send:team_status     proof: sha256:d4e5f6  09:14:22Z
✗ NO PROOF   db:delete_records:alpha    no attestation found  09:16:03Z
✗ NO PROOF   pr:approve:main            no attestation found  09:16:04Z
✗ NO PROOF   publish:release_notes:v2   no attestation found  09:16:05Z
─────────────────────────────────────────────────────────────────────
2 of 5 actions were explicitly authorized by a verified human.
3 of 5 actions were blocked — no cryptographic proof of intent.
```

The absence of a signature is itself evidence. This is what no existing authorization system can produce.

---

## Design Principles

- **Local first** — valid from the moment of signing, on a single device, with no network connection
- **No trusted intermediary** — self-verifying attestations; no server, no CA, no blockchain
- **Immutable facts** — signed attestations cannot be altered, only extended
- **Precise intent** — `database:delete_records:project_alpha` does not authorize `database:delete_records:project_beta`
- **Offline capable** — works on a $30 Android phone with intermittent connectivity

---

## Use Cases

**AI Agent Authorization** — Prove which actions your agent was explicitly authorized to take. One function call before any sensitive operation.

**Verifiable Collective Intent** — Cryptographically signed group decisions that no AI can fake. Aggregated without a central server, offline-capable.

**Informal Market Reputation** — Peer-to-peer trust attestations for informal economies. No bank account required.

---

## Implementation (Coming Soon)

OathKit is the reference implementation in Rust.

```toml
[dependencies]
oathkit-core = "0.1"
```

```rust
use oathkit_core::{attest, verify, history};

// Human authorizes an action
attest("database:delete_records:project_alpha", "cleanup approved")?;

// Agent checks before acting
let result = verify("database:delete_records:project_alpha")?;
if result.verified {
    // proceed
}

// Full audit trail
let log = history()?;
```

---

## Protocol Specification

The Oath Protocol specification is in [`spec/OATH_SPEC.md`](spec/OATH_SPEC.md).

The specification is released under **CC0 1.0 Universal** (public domain). Anyone can implement the protocol in any language. The reference implementation (OathKit) is released under the **MIT License**.

---

## Status

**Current status:** Protocol specification complete. Reference implementation in active development.

- [x] Protocol specification (v1.0.0-draft)
- [x] Architecture design
- [x] oathkit-core (Rust library)
- [x] oath CLI
- [ ] Python SDK
- [ ] Demo

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The spec is the source of truth — read it before writing code.

---

*Built with the conviction that in an age of AI-generated everything, the most valuable infrastructure is the kind that proves what humans actually meant.*
