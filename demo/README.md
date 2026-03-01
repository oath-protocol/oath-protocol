# Demo — "I Never Said That"

An agent receives a task and plans five actions. Two were explicitly
authorized by the human. Three were not. Oath makes the difference
cryptographically provable — after the fact, without trusting anyone.

## What you'll see

```
  Task: "prepare and publish the weekly project update"

  Agent planning actions...

    → Read recent activity logs           [filesystem:read:project_logs]
    → Send weekly status to team          [email:send:team_status]
    → Clean up old session records        [database:delete_records:old_sessions]
    → Merge pending pull requests         [git:merge:main_branch]
    → Publish release announcement        [publish:release_notes:v1_0]

──────────────────────────────────────────────────────────────────────
  EXECUTING
──────────────────────────────────────────────────────────────────────

  ✓ ATTESTED   filesystem:read:project_logs
               proof: 3f8a1c2b
               Scanning project logs...

  ✓ ATTESTED   email:send:team_status
               proof: 9e4d7f01
               Sending status email to team...

  ✗ BLOCKED    database:delete_records:old_sessions
               no attestation found
               Would delete 47,832 database records.

  ✗ BLOCKED    git:merge:main_branch
               no attestation found
               Would merge 3 PRs into main.

  ✗ BLOCKED    publish:release_notes:v1_0
               no attestation found
               Would notify 12,000 subscribers.

──────────────────────────────────────────────────────────────────────
  TASK AUDIT
──────────────────────────────────────────────────────────────────────

  ✓ ATTESTED   filesystem:read:project_logs
  ✓ ATTESTED   email:send:team_status
  ✗ NO PROOF   database:delete_records:old_sessions
  ✗ NO PROOF   git:merge:main_branch
  ✗ NO PROOF   publish:release_notes:v1_0

  2 of 5 actions were explicitly authorized by a verified human.
  3 of 5 actions were blocked — no cryptographic proof of intent.

  The absence of a signature is itself evidence.
```

## Setup

**1. Build the `oath` binary**

```sh
cargo build --release
```

The demo will also find a debug build at `target/debug/oath` if you
haven't run a release build.

**2. Initialize your keypair**

```sh
./target/release/oath init
```

This generates a keypair and stores it at `~/.oath/private_key.hex`.
Run it once — it won't overwrite an existing key.

**3. Attest the two authorized actions**

```sh
./target/release/oath attest \
  --action "filesystem:read:project_logs" \
  --context "reading logs is always safe"

./target/release/oath attest \
  --action "email:send:team_status" \
  --context "weekly status email approved"
```

Or run `python demo/agent.py --setup` to see these commands printed.

**4. Run the demo**

```sh
python demo/agent.py
```

## What's happening under the hood

Each time the agent wants to execute an action, it calls:

```sh
oath verify --action <action_class> --json
```

The CLI checks the local attestation store (`~/.oath/attestations.jsonl`)
for a valid, unexpired attestation matching that action class. It returns
JSON with `verified: true/false`, the `reason`, and the `attestation_id`
if found.

The agent proceeds only if `verified` is true. No attestation means no
execution — the agent is blocked by cryptographic absence, not policy rules
that can be overridden.

The attestations themselves are Ed25519-signed. You can take the
`attestation_id` from the audit log and verify the signature independently,
years after the fact, without trusting any intermediary.

## Integrating Oath into your own agent

The pattern is one function call before any consequential action:

```python
import subprocess, json

def oath_verify(action_class: str) -> bool:
    result = subprocess.run(
        ["oath", "verify", "--action", action_class, "--json"],
        capture_output=True, text=True,
    )
    data = json.loads(result.stdout or result.stderr)
    return data.get("verified", False)

# Before any action:
if not oath_verify("database:delete_records:old_sessions"):
    raise PermissionError("No human attestation for this action")
```

That's it. The human signs intent ahead of time. The agent checks at
runtime. The log proves what happened, to anyone, forever.
