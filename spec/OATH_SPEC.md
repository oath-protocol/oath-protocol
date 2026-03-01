
# Oath Protocol Specification

**Version:** 1.0.0
**Status:** Final
**Authors:** Oath Protocol Contributors
**Created:** 2026-02-25
**Repository:** github.com/oath-protocol/oath-protocol

---

## Abstract

Oath is an open protocol for cryptographically verifiable human intent
attestation. It enables any human to sign a structured statement of intent
locally, store it in a tamper-evident append-only log, and allow any system
anywhere to verify that statement — without trusting any central authority,
server, or intermediary.

The protocol is designed to answer one question that no existing authorization
system answers correctly:

> **"Did a specific human actually intend for this specific action to happen,
> and can I prove it — cryptographically, after the fact, without trusting
> any intermediary?"**

Oath is transport-agnostic, offline-first, and language-agnostic. This
document is the canonical reference. Any implementation that correctly
follows this specification is a valid Oath implementation and will be
compatible with every other valid implementation.

---

## Table of Contents

1. [Terminology](#1-terminology)
2. [Design Principles](#2-design-principles)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
4. [The Attestation Object](#4-the-attestation-object)
5. [Action Class Format](#5-action-class-format)
6. [Canonical Serialization](#6-canonical-serialization)
7. [Signing an Attestation](#7-signing-an-attestation)
8. [Verifying an Attestation](#8-verifying-an-attestation)
9. [The Attestation Store](#9-the-attestation-store)
10. [Revocation](#10-revocation)
11. [Sync and Merge Protocol](#11-sync-and-merge-protocol)
12. [Key Management](#12-key-management)
13. [Wire Format](#13-wire-format)
14. [Error Codes](#14-error-codes)
15. [Protocol Versioning](#15-protocol-versioning)
16. [Security Considerations](#16-security-considerations)
17. [Conformance Requirements](#17-conformance-requirements)
18. [Test Vectors](#18-test-vectors)

---

## 1. Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this
document are to be interpreted as described in RFC 2119.

**Attestation** — A cryptographically signed record stating that a specific
human intended a specific action class at a specific moment in time.

**Attestor** — The human who signs an attestation using their private key.

**Verifier** — Any system (agent, application, human) that checks an
attestation's validity before proceeding with an action.

**Action Class** — A structured three-part identifier describing the category
of action being attested. See Section 5.

**Attestation Store** — A CRDT-based append-only log of attestations on a
given node. See Section 9.

**Node** — Any device running an Oath implementation that maintains a local
attestation store.

**Keypair** — An Ed25519 public/private key pair. The private key is held
exclusively by the attestor. The public key is embedded in every attestation.

**Fingerprint** — The first 16 bytes of the SHA-256 hash of the public key,
encoded as lowercase hex. Used as a human-readable key identifier.

**Revocation** — A special attestation that marks a previous attestation as
no longer active. See Section 10.

**Sync** — The process by which two nodes exchange attestation store state
and arrive at a consistent merged view. See Section 11.

---

## 2. Design Principles

These principles govern every decision in this specification. When in doubt
about a design choice, return to these principles in order.

**P1 — Local first.** An attestation is valid from the moment it is signed,
on a single device, with no network connection. Sync is additive and optional.
No operation requires a network call.

**P2 — No trusted intermediary.** The protocol MUST NOT require trust in any
central server, certificate authority, blockchain, or third party. Validity
is determined entirely by the cryptographic relationship between a signature
and a public key.

**P3 — Immutability of signed facts.** A signed attestation is an immutable
record of a moment in time. It cannot be altered. It can only be superseded
by a revocation, which is itself an immutable signed record.

**P4 — Minimal surface area.** The protocol defines only what is necessary
for correct interoperability. Application logic, threshold rules, aggregation,
and UI are out of scope. Implementations MUST NOT extend the wire format in
ways that break conformance.

**P5 — Precision of intent.** An attestation authorizes exactly the action
class it names, in exactly the scope it specifies, at exactly the moment it
was signed. No implicit or inherited authorization. No scope creep.

**P6 — Legibility.** Every field in an attestation MUST be human-readable
when rendered as JSON. A human MUST be able to read a raw attestation and
understand exactly what was authorized, by whom, and when.

---

## 3. Cryptographic Primitives

### 3.1 Signature Scheme

Oath uses **Ed25519** as defined in RFC 8032.

Implementations MUST use Ed25519. No other signature scheme is permitted in
v1 of this protocol.

Ed25519 was chosen for the following properties:
- Small signature size: 64 bytes
- Small public key size: 32 bytes
- Fast verification: suitable for high-frequency agent authorization checks
- Resistance to timing attacks by construction
- No dependency on random number generation during signing
- Wide availability of audited implementations across all major languages

### 3.2 Hashing

Oath uses **SHA-256** as defined in FIPS 180-4 for all hashing operations.

Specifically:
- Context strings are hashed with SHA-256 before being included in
  attestations. The raw context string is NOT included in the attestation.
- Key fingerprints are derived as the first 16 bytes of SHA-256(public_key).
- The canonical serialization of an attestation (Section 6) is the input
  to the Ed25519 signing operation.

### 3.3 Encoding

- Binary values (signatures, public keys, hashes) are encoded as
  **base64url without padding** (RFC 4648 Section 5) in JSON representations.
- The same values are encoded as raw bytes in the CBOR wire format.
- Timestamps are **Unix milliseconds** as unsigned 64-bit integers.
- UUIDs are version 4 (RFC 4122), represented as lowercase hyphenated strings
  in JSON and as 16 raw bytes in CBOR.

---

## 4. The Attestation Object

An attestation is the atomic unit of the Oath protocol. Every other component
of the protocol exists to create, store, sync, or verify attestations.

### 4.1 JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/oath-protocol/oath-protocol/schemas/attestation/1.0.0",
  "title": "Oath Attestation",
  "type": "object",
  "required": [
    "id",
    "protocol_version",
    "action_class",
    "context_hash",
    "timestamp_ms",
    "public_key",
    "signature"
  ],
  "properties": {
    "id": {
      "type": "string",
      "format": "uuid",
      "description": "UUID v4. Generated at signing time. Globally unique."
    },
    "protocol_version": {
      "type": "string",
      "pattern": "^oath/[0-9]+\\.[0-9]+$",
      "description": "Protocol version. MUST be 'oath/1.0' for this version."
    },
    "action_class": {
      "type": "string",
      "pattern": "^[a-z0-9_]+:[a-z0-9_]+:[a-z0-9_\\-\\.]+$",
      "description": "Three-part action class. See Section 5."
    },
    "context_hash": {
      "type": "string",
      "description": "SHA-256 hash of the human-readable context string. base64url, no padding."
    },
    "timestamp_ms": {
      "type": "integer",
      "minimum": 0,
      "description": "Unix timestamp in milliseconds at signing time."
    },
    "public_key": {
      "type": "string",
      "description": "Ed25519 public key of the attestor. base64url, no padding."
    },
    "signature": {
      "type": "string",
      "description": "Ed25519 signature over canonical serialization. base64url, no padding."
    },
    "expires_at_ms": {
      "type": "integer",
      "minimum": 0,
      "description": "Optional. Unix timestamp in milliseconds after which this attestation is considered expired. MUST be greater than timestamp_ms if present."
    },
    "nonce": {
      "type": "string",
      "description": "Optional. Random base64url string. Use when uniqueness per attestation matters beyond the UUID."
    }
  },
  "additionalProperties": false
}
```

### 4.2 Field Definitions

#### `id` (REQUIRED)
A UUID v4 generated fresh at signing time. This is the primary key of the
attestation in the store. Implementations MUST generate a new UUID for every
attestation — UUIDs MUST NOT be reused or predicted.

#### `protocol_version` (REQUIRED)
The version of the Oath protocol under which this attestation was created.
For this version of the spec, the value MUST be the string `"oath/1.0"`.
Implementations MUST reject attestations with unrecognized protocol versions.

#### `action_class` (REQUIRED)
A three-part colon-separated identifier for the category of action being
attested. See Section 5 for the full specification of action class format,
valid characters, and reserved namespaces.

#### `context_hash` (REQUIRED)
The SHA-256 hash of the human-provided context string, encoded as base64url
without padding. The context string itself is NOT stored in the attestation —
only its hash. This ensures the context cannot be altered after signing while
keeping the attestation compact.

Implementations MUST store the original context string separately, associated
with the attestation ID, to allow human-readable display. The context string
is NOT part of the protocol — it is application data.

#### `timestamp_ms` (REQUIRED)
The Unix timestamp in milliseconds at the moment of signing. This is
generated by the signing implementation from the system clock.

Implementations SHOULD use a monotonic clock source where available.
Implementations MUST NOT allow the attestor to provide an arbitrary timestamp
— it must be generated at signing time.

#### `public_key` (REQUIRED)
The Ed25519 public key of the attestor, encoded as base64url without padding.
This is the key against which the signature is verified. The corresponding
private key MUST remain on the attestor's device and MUST NOT be transmitted.

#### `signature` (REQUIRED)
The Ed25519 signature over the canonical serialization of all other fields.
See Section 6 for the exact canonical serialization procedure. The signature
MUST be computed last, after all other fields are finalized.

#### `expires_at_ms` (OPTIONAL)
If present, the attestation is considered expired after this timestamp.
Verification MUST return `EXPIRED` for any attestation where the current
time exceeds `expires_at_ms`, regardless of signature validity.

This field MUST be greater than `timestamp_ms` if present. Implementations
MUST reject attestations where `expires_at_ms <= timestamp_ms`.

#### `nonce` (OPTIONAL)
A random string used when the same action class may be legitimately attested
multiple times and each attestation must be cryptographically distinct beyond
its UUID. If present, it is included in the canonical serialization and
therefore in the signature.

### 4.3 Example Attestation (JSON)

```json
{
  "id": "7f3d9a2e-1b4c-4e8f-a5d6-2c9e0f1a3b7d",
  "protocol_version": "oath/1.0",
  "action_class": "database:delete_records:project_alpha",
  "context_hash": "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
  "timestamp_ms": 1740384723000,
  "public_key": "MCowBQYDK2VwAyEA2a9LjxjIL1J7Z8Kqm3PvNt5XwYhR6mD4cE0sF9pQ3Uk",
  "signature": "ZmFrZXNpZ25hdHVyZWZvcmRvY3VtZW50YXRpb25wdXJwb3Nlc29ubHkAAAAAAAAA",
  "expires_at_ms": 1740388323000
}
```

---

## 5. Action Class Format

The action class is the most important design decision in the protocol. It
is what makes attestations precise rather than broad. Getting it wrong means
an agent can reuse an attestation for actions the human never intended to
cover.

### 5.1 Structure

An action class is a string with exactly three parts separated by colons:

```
namespace:action:scope
```

All three parts are REQUIRED. Two-part action classes are NOT valid.

### 5.2 Character Rules

Each part MUST match the regular expression `[a-z0-9_]` for namespace and
action, and `[a-z0-9_\-\.]` for scope. Uppercase is NOT permitted.
Spaces are NOT permitted. The colon character MUST only appear as a separator.

### 5.3 Part Definitions

**`namespace`** — The domain or system in which the action occurs.
Examples: `database`, `email`, `filesystem`, `api`, `payment`, `git`, `ai`

**`action`** — The specific operation within the namespace.
Examples: `delete_records`, `send_message`, `write_file`, `approve_pr`,
`transfer_funds`, `publish`

**`scope`** — The specific target, resource, or context within which the
action is authorized. This is the part that prevents scope creep.
Examples: `project_alpha`, `main_branch`, `user_notifications`, `prod_db`,
`q1_budget`, `team_status_updates`

### 5.4 Scope Specificity Principle

An attestation for `database:delete_records:project_alpha` does NOT
authorize `database:delete_records:project_beta`. Each scope is independent.

An attestation for `database:delete_records:project_alpha` does NOT
authorize `database:truncate_table:project_alpha`. Each action is independent.

There is no wildcard syntax in v1. An attestation covers exactly the
action class it names. No more, no less.

This is intentional. Wildcard authorization is how scope creep enters
authorization systems. The correct model is to attest each action class
explicitly, or to use a short expiry window for broad tasks.

### 5.5 Reserved Namespaces

The following namespaces are reserved by the Oath Protocol and carry
defined semantics:

| Namespace | Reserved for |
|---|---|
| `oath` | Protocol-internal actions (revocation, key rotation) |
| `test` | Test and development attestations — verifiers MAY reject these in production |

### 5.6 Valid Examples

```
database:delete_records:project_alpha
email:send:team_status_updates
filesystem:write_file:config_dir
api:call_external:payment_provider
payment:transfer_funds:q1_expenses
git:merge:main_branch
ai:execute_tool:calendar_agent
oath:revoke:7f3d9a2e-1b4c-4e8f-a5d6-2c9e0f1a3b7d
```

### 5.7 Invalid Examples

```
Database:delete_records:project_alpha   ← uppercase not permitted
database:delete_records                 ← scope part missing
database::project_alpha                 ← action part empty
database:delete records:alpha           ← spaces not permitted
*:*:*                                   ← wildcards not permitted
```

---

## 6. Canonical Serialization

The signature in an attestation is computed over a canonical serialization
of the attestation fields. The canonical serialization MUST be deterministic
— given the same field values, every implementation MUST produce exactly the
same byte sequence.

### 6.1 Procedure

The canonical serialization is a UTF-8 encoded JSON object with the following
rules:

1. Include ALL fields that are present in the attestation, EXCEPT `signature`.
2. Fields MUST appear in the following fixed order:
   `id`, `protocol_version`, `action_class`, `context_hash`, `timestamp_ms`,
   `public_key`, `expires_at_ms` (if present), `nonce` (if present)
3. No whitespace between tokens (compact JSON).
4. String values MUST be UTF-8 encoded with no unnecessary escape sequences.
5. Integer values MUST be represented as JSON numbers without quotes.
6. Optional fields that are absent MUST NOT appear in the serialization.

### 6.2 Example

For the attestation in Section 4.3 (without nonce), the canonical
serialization is:

```
{"id":"7f3d9a2e-1b4c-4e8f-a5d6-2c9e0f1a3b7d","protocol_version":"oath/1.0","action_class":"database:delete_records:project_alpha","context_hash":"n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg","timestamp_ms":1740384723000,"public_key":"MCowBQYDK2VwAyEA2a9LjxjIL1J7Z8Kqm3PvNt5XwYhR6mD4cE0sF9pQ3Uk","expires_at_ms":1740388323000}
```

The Ed25519 signing operation is applied to the UTF-8 bytes of this string.

### 6.3 Implementation Note

Implementations MUST NOT serialize and then deserialize before signing —
this introduces a risk of field reordering. The canonical serialization MUST
be constructed directly in the specified field order.

---

## 7. Signing an Attestation

This section defines the exact procedure for producing a valid signed
attestation.

### 7.1 Prerequisites

- A valid Ed25519 keypair (see Section 12)
- The action class string to be attested
- The human-readable context string describing the reason for attestation

### 7.2 Signing Procedure

1. **Generate ID.** Generate a UUID v4. Store as `id`.

2. **Set protocol version.** Set `protocol_version` to `"oath/1.0"`.

3. **Validate action class.** Validate that `action_class` conforms to
   Section 5. MUST reject invalid action classes before proceeding.

4. **Hash context.** Compute `SHA-256(UTF-8(context_string))`. Encode as
   base64url without padding. Store as `context_hash`. Store the original
   `context_string` locally associated with `id` — this is application data,
   not protocol data.

5. **Set timestamp.** Record current time as Unix milliseconds. Store as
   `timestamp_ms`. MUST be generated at this moment — not passed in by the
   caller.

6. **Set public key.** Encode the attestor's Ed25519 public key as base64url
   without padding. Store as `public_key`.

7. **Set optional fields.** If `expires_at_ms` is provided by the caller,
   validate that it is greater than `timestamp_ms`. Store if valid, reject
   if not. If `nonce` is provided, include it.

8. **Produce canonical serialization.** Construct the canonical serialization
   per Section 6, using all fields set in steps 1–7.

9. **Sign.** Compute `Ed25519_Sign(private_key, canonical_bytes)`. Encode
   the 64-byte result as base64url without padding. Store as `signature`.

10. **Zero private key from memory.** The private key MUST be zeroed from
    memory immediately after the signing operation completes.

11. **Append to store.** Append the complete signed attestation to the local
    attestation store (Section 9).

12. **Return attestation.** Return the complete attestation to the caller.

---

## 8. Verifying an Attestation

### 8.1 Verify Result Object

Every verification operation returns a `VerifyResult` object:

```json
{
  "verified": false,
  "attestation_id": "7f3d9a2e-1b4c-4e8f-a5d6-2c9e0f1a3b7d",
  "reason": "EXPIRED",
  "checked_at_ms": 1740391923000
}
```

`verified` is `true` only when reason is `ATTESTED`. All other reasons
produce `verified: false`.

`reason` MUST be one of the values defined in Section 14.

### 8.2 Verification Procedure

Given an `action_class` string and access to a local attestation store:

1. **Validate action class.** Validate the input `action_class` against
   Section 5 rules. Return `INVALID_ACTION_CLASS` if invalid.

2. **Query store.** Look up all attestations in the store where
   `attestation.action_class == input_action_class`. If none found,
   return `NO_ATTESTATION`.

3. **Filter revoked.** Remove any attestation that has a corresponding
   revocation record in the store. See Section 10.

4. **For each remaining attestation, in descending `timestamp_ms` order:**

   a. **Check expiry.** If `expires_at_ms` is present and
      `current_time_ms > expires_at_ms`, skip this attestation
      (reason: `EXPIRED`).

   b. **Reconstruct canonical serialization.** Reconstruct the canonical
      serialization from the attestation fields per Section 6, excluding
      the `signature` field.

   c. **Verify signature.** Compute
      `Ed25519_Verify(public_key, canonical_bytes, signature)`.
      If verification fails, skip this attestation (reason:
      `INVALID_SIGNATURE`).

   d. **Return success.** Return `VerifyResult { verified: true,
      attestation_id: id, reason: "ATTESTED", checked_at_ms: now }`.

5. **If no attestation passed all checks:** Return the most specific failure
   reason encountered. Priority order: `REVOKED` > `EXPIRED` >
   `INVALID_SIGNATURE` > `NO_ATTESTATION`.

### 8.3 Verify by ID

Implementations MUST also support verification of a specific attestation
by ID — not just by action class. This is used for audit and traceability.
The procedure is identical to Section 8.2 step 4, applied to the specific
attestation.

### 8.4 Non-Blocking Contract

Verification MUST NOT block the calling code. It returns a result and the
caller decides what to do with it. The protocol does not enforce behavior —
it provides proof. Enforcement is the application's responsibility.

---

## 9. The Attestation Store

### 9.1 Data Model

The attestation store is a **Grow-only Set CRDT (G-Set)**. It has one
operation: add. Attestations are never deleted or modified — only added.

The store is keyed by attestation `id`. Since IDs are UUID v4, collisions
are astronomically improbable. In the event of an ID collision (which MUST
be treated as a bug in the UUID generator), the attestation with the earlier
`timestamp_ms` is retained.

### 9.2 Required Operations

Implementations MUST support the following store operations:

**`store.append(attestation)`** — Add a signed attestation to the store.
MUST validate the attestation signature before appending. MUST reject
attestations that fail signature verification.

**`store.get(id)`** — Retrieve a specific attestation by ID.
Returns the attestation or null if not found.

**`store.query(action_class)`** — Retrieve all attestations matching a
given action class. Returns a list, possibly empty.

**`store.history()`** — Return all attestations in the store, ordered by
`timestamp_ms` descending.

**`store.merge(remote_store)`** — Merge a remote store's state into the
local store. See Section 11.

**`store.size()`** — Return the number of attestations in the store.

### 9.3 Storage Backend

The protocol does not mandate a specific storage backend. Implementations
MUST support at minimum an append-only flat file as the default backend
requiring zero configuration.

Implementations MAY support additional backends (SQLite, embedded key-value
stores) as optional extensions, but MUST NOT require them for basic operation.

### 9.4 Store Integrity

The store MUST maintain an integrity hash — the SHA-256 of the concatenated
IDs of all attestations in insertion order. This is used during sync to
detect divergence without transmitting full attestation data.

---

## 10. Revocation

Attestations are immutable — they cannot be deleted. Revocation is the
mechanism by which an attestation is marked as no longer active.

### 10.1 Revocation Attestation

A revocation is itself an attestation with:

- `action_class`: `oath:revoke:<target_id>` where `<target_id>` is the UUID
  of the attestation being revoked.
- `context_hash`: Hash of a human-readable reason for revocation.
- All other fields: standard attestation fields.

A revocation MUST be signed by the same keypair that signed the original
attestation. Implementations MUST reject revocations signed by a different key.

### 10.2 Revocation Semantics

A revoked attestation is NOT deleted from the store. It remains in the log
as a historical record. The revocation attestation is added alongside it.

Verification (Section 8) MUST check for revocations before returning
`ATTESTED`. If a valid revocation exists for an attestation, verification
MUST return `REVOKED`.

### 10.3 Revocation of Revocations

Revocations cannot be revoked. Once an attestation is revoked, it is
permanently inactive. This is by design — if re-authorization is needed,
a new attestation must be created.

---

## 11. Sync and Merge Protocol

### 11.1 Sync Model

Sync is a voluntary, additive operation. Two nodes exchange attestation
store state and merge it using the G-Set CRDT semantics: the merged state
is the union of both stores.

Because attestations are immutable and the G-Set has no delete operation,
merge is always conflict-free. There are no competing writes. The union is
always the correct result.

### 11.2 Sync Handshake

When two nodes initiate sync, they MUST follow this handshake:

1. **Exchange store summaries.** Each node sends its store integrity hash
   and store size to the other.

2. **Determine delta.** If integrity hashes are equal, stores are identical
   and sync is complete. If different, proceed.

3. **Exchange ID lists.** Each node sends the list of all attestation IDs
   it holds to the other.

4. **Request missing attestations.** Each node computes the set difference
   and requests the attestations it does not have from the other node.

5. **Validate and append.** For each received attestation, the receiving
   node MUST verify its signature before appending it to the local store.
   Attestations that fail verification MUST be rejected and MUST NOT be
   appended.

6. **Confirm merge.** Both nodes recompute their integrity hashes. If they
   now match, sync is complete.

### 11.3 Transport Agnosticism

The sync protocol is transport-agnostic. Implementations MUST support TCP/IP
as the baseline transport. Implementations MAY additionally support:

- mDNS-based peer discovery on local networks
- Bluetooth RFCOMM for proximity sync
- File export/import for air-gapped environments

The sync protocol payload MUST be encoded in the CBOR wire format
(Section 13) for all transports.

### 11.4 Sync Security

A node MUST NOT accept attestations from an untrusted peer without
verifying each attestation's signature independently. Trusting a peer
to vouch for attestation validity is NOT permitted. Every attestation
is self-verifying.

---

## 12. Key Management

### 12.1 Key Generation

Implementations MUST generate Ed25519 keypairs using a cryptographically
secure random number generator. The private key is 32 bytes of random seed.
The public key is derived deterministically from the private key.

### 12.2 Key Storage

**Private key at rest:** Implementations MUST store the private key encrypted.
The preferred method is the operating system's secure keychain:
- macOS: Keychain Services
- Linux: Secret Service API (via libsecret) or encrypted file
- Windows: Windows Credential Manager

If no system keychain is available, implementations MUST encrypt the private
key file using AES-256-GCM with a key derived from a user-provided passphrase
using Argon2id (RFC 9106).

**Private key in memory:** The private key MUST be loaded into memory only
for the duration of a signing operation. It MUST be zeroed from memory
immediately after the operation completes using a guaranteed memory zeroing
function that cannot be optimized away by the compiler.

**Public key:** The public key MAY be stored unencrypted. It is not sensitive.

### 12.3 Key Rotation

A user MAY generate a new keypair at any time. Old attestations remain valid
under the old key — they embed the public key they were signed with, so
verifiers always know which key to check.

New attestations after rotation are signed with the new key. There is no
migration process. There is no central key registry to update.

### 12.4 Key Fingerprint

The key fingerprint is defined as:

```
fingerprint = hex(SHA-256(public_key_bytes)[0:16])
```

This produces a 32-character lowercase hex string used for human-readable
key identification. The fingerprint MUST be displayed wherever a key is
referenced in human-facing output.

### 12.5 Default Key Location

The default location for key files and the attestation store is:

- Unix: `~/.oath/`
- Windows: `%APPDATA%\oath\`

Implementations MUST support overriding this location via an environment
variable `OATH_DIR`.

---

## 13. Wire Format

### 13.1 JSON (Human-Readable)

JSON is used for all human-facing output: CLI display, configuration files,
and the canonical serialization for signing (Section 6).

JSON representations MUST use the field names and types defined in
Section 4.1.

### 13.2 CBOR (Binary, Sync)

CBOR (RFC 8949) is used for all inter-node communication during sync and
for compact storage when the implementation chooses a binary backend.

The CBOR encoding uses integer keys for compactness:

| Integer Key | Field Name |
|---|---|
| 0 | id (16 bytes, binary UUID) |
| 1 | protocol_version |
| 2 | action_class |
| 3 | context_hash (32 bytes, raw SHA-256) |
| 4 | timestamp_ms |
| 5 | public_key (32 bytes, raw Ed25519 public key) |
| 6 | signature (64 bytes, raw Ed25519 signature) |
| 7 | expires_at_ms (optional) |
| 8 | nonce (optional) |

CBOR-encoded attestations MUST be validated against the same rules as
JSON attestations before being accepted into the store.

---

## 14. Error Codes

### 14.1 Verify Result Reasons

| Code | Meaning |
|---|---|
| `ATTESTED` | Valid attestation found. `verified: true`. |
| `NO_ATTESTATION` | No attestation found for this action class. |
| `EXPIRED` | Attestation found but `expires_at_ms` has passed. |
| `REVOKED` | Attestation found but a valid revocation exists. |
| `INVALID_SIGNATURE` | Attestation found but signature verification failed. |
| `INVALID_ACTION_CLASS` | The queried action class string is malformed. |

### 14.2 Store Error Codes

| Code | Meaning |
|---|---|
| `STORE_SIGNATURE_REJECTED` | Attempted to append an attestation with an invalid signature. |
| `STORE_VERSION_UNSUPPORTED` | Attestation uses an unsupported protocol version. |
| `STORE_DUPLICATE_ID` | An attestation with this ID already exists in the store. |
| `STORE_INVALID_EXPIRY` | `expires_at_ms` is not greater than `timestamp_ms`. |

---

## 15. Protocol Versioning

### 15.1 Version String Format

Protocol versions follow the format `oath/MAJOR.MINOR` where MAJOR and
MINOR are non-negative integers.

- MAJOR version increment: breaking changes to the attestation schema,
  signing procedure, or verification procedure. Implementations of different
  major versions are NOT required to be compatible.
- MINOR version increment: additive, backward-compatible changes. An
  implementation of a higher minor version MUST be able to verify attestations
  from lower minor versions of the same major version.

### 15.2 Current Version

This specification defines `oath/1.0`.

### 15.3 Version Negotiation During Sync

During sync (Section 11), nodes MUST exchange their supported protocol
versions in the handshake. Attestations with unsupported protocol versions
MUST NOT be accepted into the store.

---

## 16. Security Considerations

### 16.1 Timestamp Trust

Timestamps in attestations are generated by the signing implementation from
the system clock. They are NOT verified by an external time authority.
This means a dishonest attestor could sign an attestation with an incorrect
timestamp.

This is a deliberate design decision: requiring an external time authority
would violate Principle P2 (no trusted intermediary). The protocol makes
the attestation's timestamp visible and signed — if a verifier has reason
to distrust the timestamp, they can examine the attestation and make their
own judgment.

Applications that require strict time guarantees SHOULD use short expiry
windows and consider additional out-of-band timestamp verification.

### 16.2 Single-Device Key Compromise

If a private key is compromised, an attacker can produce valid attestations
that will pass verification. The mitigation is:

1. Detect compromise as early as possible
2. Generate a new keypair immediately
3. Revoke any outstanding attestations signed with the compromised key
   (if the compromised key is still accessible)

There is no mechanism to retroactively invalidate attestations signed before
the compromise was detected. This is consistent with the immutability
principle and is a known limitation of local-key architectures.

### 16.3 Replay Attacks

A valid attestation can be replayed — if an agent captures a valid
attestation, it can present it again later. Mitigations:

- Use `expires_at_ms` to bound the validity window of sensitive attestations
- Use `nonce` when a one-time-use attestation is required
- Applications MAY track attestation IDs that have been "consumed" and
  refuse to accept the same ID twice

### 16.4 Context Hash Limitations

The context string is hashed, not stored in the attestation. This means
a verifier cannot read the original context from the attestation alone —
they need the separately stored context string. Implementations MUST store
the original context string and associate it with the attestation ID.
Loss of the context string means loss of the human-readable reason for
the attestation, but does NOT affect cryptographic validity.

---

## 17. Conformance Requirements

An implementation is a **conforming Oath implementation** if and only if
it satisfies ALL of the following:

1. It generates attestations that validate against the JSON Schema in
   Section 4.1.
2. It uses Ed25519 for all signing and verification operations.
3. It uses SHA-256 for all hashing operations.
4. It produces the canonical serialization per Section 6 exactly.
5. It implements the verification procedure per Section 8 completely,
   including expiry and revocation checks.
6. It implements the G-Set store model per Section 9.
7. It implements the sync handshake per Section 11.
8. It passes all test vectors in Section 18.
9. It zeros private keys from memory after signing.
10. It rejects attestations with invalid signatures at store append time.

Partial implementations are NOT conforming. An implementation that passes
9 of 10 requirements is not a conforming Oath implementation.

---

## 18. Test Vectors

The following test vectors MUST be used to validate implementations.
All values are in the formats defined in this specification.

### 18.1 Vector 1 — Basic Attestation

**Input:**
```
action_class:  "database:delete_records:test_scope"
context:       "Authorized cleanup of test database records"
timestamp_ms:  1740384723000
id:            00000000-0000-4000-8000-000000000001
keypair seed:  0000000000000000000000000000000000000000000000000000000000000001
```

**Derived public key (Ed25519, base64url no padding):**
```
TLWr9q15-_WrvMr8wmnYXNJlHtS4hbWGnyQa7fCluik=
```

**Expected context_hash (SHA-256, base64url no padding):**
```
zNVumuIL02rlvxkNNh6386UjVMK3hHwRgHZ8hOBB98Y=
```

**Expected canonical serialization:**
```
{"id":"00000000-0000-4000-8000-000000000001","protocol_version":"oath/1.0","action_class":"database:delete_records:test_scope","context_hash":"zNVumuIL02rlvxkNNh6386UjVMK3hHwRgHZ8hOBB98Y=","timestamp_ms":1740384723000,"public_key":"TLWr9q15-_WrvMr8wmnYXNJlHtS4hbWGnyQa7fCluik="}
```

**Expected signature (Ed25519, base64url no padding):**
```
xTXoHNfeRthzNdTiKTy10OnYtFuYU1SLULaJE_jyAUNEqvLH925UJkp77_Txj1DxbKqCxeWPiHcwK9xn-dU8AQ==
```

> These values were computed by the oathkit-core reference implementation
> and locked at spec version 1.0.0. All conforming implementations MUST
> produce identical output for identical inputs.

### 18.2 Vector 2 — Expired Attestation

An attestation identical to Vector 1 but with `expires_at_ms` set to
`timestamp_ms + 1`. Verification at any time after signing MUST return
`EXPIRED`.

### 18.3 Vector 3 — Revocation

An attestation identical to Vector 1, followed by a valid revocation
attestation for its ID. Verification MUST return `REVOKED`.

### 18.4 Vector 4 — Invalid Signature

An attestation identical to Vector 1 but with the final byte of the
signature incremented by 1. Verification MUST return `INVALID_SIGNATURE`.

---

## Appendix A — Rationale for Design Decisions

### Why not a blockchain?

Blockchains require network connectivity for every write, introduce token
economics that create perverse incentives, carry finality delays that make
real-time agent authorization impractical, and require users to understand
Web3 tooling. Oath requires none of these. A blockchain is the right tool
for global consensus without a central authority. Oath solves a different
problem: local verifiability of personal intent.

### Why not OAuth / OpenID Connect?

OAuth and OIDC are excellent for delegating access between applications.
They are not designed for proving that a human intended a specific action —
they prove that a service has permission to act on a user's behalf, which
is a different and weaker statement. OAuth requires a central authorization
server. Oath requires only a keypair.

### Why not W3C Verifiable Credentials?

VCs are designed for institutional attestation — a university attesting
a degree, a government attesting an identity. Oath is designed for
self-attestation — a human attesting their own intent. VCs require issuers
and verifiers to register with each other. Oath requires neither.

### Why G-Set instead of a richer CRDT?

The simplest CRDT that correctly models the data is always preferable.
Attestations are immutable facts. They are never updated. They are only
added. A G-Set models this exactly. More complex CRDTs (LWW registers,
OR-Sets) would add complexity without adding correctness.

### Why Ed25519 and not secp256k1?

secp256k1 is Bitcoin's curve. Using it carries blockchain associations that
create the wrong framing for this protocol — Oath is not a blockchain project
and should not look like one. Ed25519 is faster, produces smaller keys and
signatures, and is not vulnerable to the timing attacks that poorly-implemented
ECDSA on other curves can exhibit.

---

*Oath Protocol Specification v1.0.0*
*February 2026*
*This document is released under CC0 1.0 Universal (Public Domain).*
*The reference implementation (OathKit) is released under the MIT License.*
