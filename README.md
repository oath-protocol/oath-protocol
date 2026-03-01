# Oath Protocol

> The open protocol for cryptographically verifiable human intent.

Oath enables any human to sign a structured statement of intent locally, store it in a tamper-evident append-only log, and allow any system anywhere to verify that statement — without trusting any central authority, server, or intermediary.

---

## The Problem

Did a specific human actually intend this — and can you prove it, after the fact, without trusting anyone?

That question is older than computing. It shows up when an AI agent takes an action nobody authorized. When a petition gets inflated by bots. When a commitment in an informal market gets disputed. When collective consent is manufactured rather than given.

Every existing authorization system answers a different question: *"does this service have permission to act on my behalf?"*

Oath answers the harder one: **"did this specific human actually intend for this specific action to happen, and can I prove it cryptographically, after the fact, without trusting any intermediary?"**

---

## Try It

```sh
# Build
cargo build --release

# Initialize your keypair (run once)
./target/release/oath init

# Sign your intent before the agent runs
./target/release/oath attest \
  --action "database:delete_records:project_alpha" \
  --context "cleanup approved for project alpha"

# The agent checks before acting
./target/release/oath verify --action "database:delete_records:project_alpha"
# → ✓ ATTESTED   proof: a1b2c3d4

./target/release/oath verify --action "database:delete_records:production"
# → ✗ NO ATTESTATION

# Full audit trail
./target/release/oath history
```

Or run the full demo — an agent executing five actions, two authorized, three blocked:

```sh
python demo/agent.py --setup   # shows which actions to attest first
python demo/agent.py           # runs the agent
```

---

## What the Audit Looks Like

```
  ✓ ATTESTED   filesystem:read:project_logs
               proof: ed7e90b1
               Scanning project logs...

  ✓ ATTESTED   email:send:team_status
               proof: dd9f41a9
               Sending status email to team...

  ✗ BLOCKED    database:delete_records:old_sessions
               no attestation
               Would delete 47,832 database records.

  ✗ BLOCKED    publish:release_notes:v1_0
               no attestation
               Would notify 12,000 subscribers.

  ────────────────────────────────────────────────────────────────
  2 of 5 actions were explicitly authorized by a verified human.
  3 of 5 actions were blocked — no cryptographic proof of intent.

  The absence of a signature is itself evidence.
```

The proof IDs are attestation UUIDs. You can verify any of them independently, years later, without a server.

---

## Integrating into Your Agent

One function call before any consequential action:

```python
import subprocess, json

def oath_verify(action_class: str) -> bool:
    result = subprocess.run(
        ["oath", "verify", "--action", action_class, "--json"],
        capture_output=True, text=True,
    )
    data = json.loads(result.stdout or result.stderr)
    return data.get("verified", False)

# Before any sensitive action:
if not oath_verify("database:delete_records:project_alpha"):
    raise PermissionError("No human attestation for this action")
```

The human signs intent ahead of time. The agent checks at runtime. The log proves what happened, to anyone, forever.

---

## Design Principles

- **Local first** — valid from the moment of signing, on a single device, with no network connection
- **No trusted intermediary** — self-verifying attestations; no server, no CA, no blockchain
- **Immutable facts** — signed attestations cannot be altered, only extended
- **Precise intent** — `database:delete_records:project_alpha` does not authorize `database:delete_records:production`
- **Offline capable** — works anywhere you can run a binary

---

## Use Cases

**AI Agent Authorization** — Prove which actions your agent was explicitly authorized to take. One function call before any sensitive operation.

**Verifiable Collective Intent** — Cryptographically signed group decisions that no AI can fake. Aggregated without a central server, offline-capable.

**Informal Market Reputation** — Peer-to-peer trust attestations for informal economies. No bank account required.

---

## Protocol Specification

The Oath Protocol specification is in [`spec/OATH_SPEC.md`](spec/OATH_SPEC.md) — version 1.0.0, final.

The specification is released under **CC0 1.0 Universal** (public domain). Anyone can implement the protocol in any language. The reference implementation (OathKit) is released under the **MIT License**.

---

## Status

- [x] Protocol specification (v1.0.0)
- [x] oathkit-core — Rust library
- [x] oath CLI — `init`, `attest`, `verify`, `history`, `whoami`
- [x] Demo agent — "I Never Said That"
- [ ] Python SDK
- [ ] Offline sync

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The spec is the source of truth — read it before writing code.

---

*Built with the conviction that in an age of AI-generated everything, the most valuable infrastructure is the kind that proves what humans actually meant.*
