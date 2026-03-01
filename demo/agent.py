#!/usr/bin/env python3
"""
Oath Protocol Demo — "I Never Said That"

An agent receives a task and plans five actions. Two were explicitly
authorized by the human. Three were not. Oath makes the difference
cryptographically provable, after the fact, without trusting anyone.

Usage:
    python agent.py          # run the demo
    python agent.py --setup  # show the setup commands (run these first)
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

# ── Task definition ──────────────────────────────────────────────────────────

TASK = "prepare and publish the weekly project update"

ACTIONS = [
    {
        "action_class": "filesystem:read:project_logs",
        "description": "Read recent activity logs",
        "consequence": "Scanning project logs...",
        "expected": True,   # human attested this
    },
    {
        "action_class": "email:send:team_status",
        "description": "Send weekly status to team",
        "consequence": "Sending status email to team...",
        "expected": True,   # human attested this
    },
    {
        "action_class": "database:delete_records:old_sessions",
        "description": "Clean up old session records",
        "consequence": "Would delete 47,832 database records.",
        "expected": False,  # not attested — blocked
    },
    {
        "action_class": "git:merge:main_branch",
        "description": "Merge pending pull requests",
        "consequence": "Would merge 3 PRs into main.",
        "expected": False,  # not attested — blocked
    },
    {
        "action_class": "publish:release_notes:v1_0",
        "description": "Publish release announcement",
        "consequence": "Would notify 12,000 subscribers.",
        "expected": False,  # not attested — blocked
    },
]

# ── Oath binary resolution ────────────────────────────────────────────────────

def find_oath_binary():
    """Find the oath binary — check PATH first, then the build directory."""
    if shutil.which("oath"):
        return "oath"

    # Look relative to this file: ../../target/debug/oath
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "..", "target", "release", "oath"),
        os.path.join(here, "..", "target", "debug", "oath"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return os.path.abspath(path)

    return None


def oath_verify(binary, action_class):
    """Call `oath verify` and return the parsed JSON result."""
    result = subprocess.run(
        [binary, "verify", "--action", action_class, "--json"],
        capture_output=True,
        text=True,
    )
    try:
        return json.loads(result.stdout or result.stderr)
    except json.JSONDecodeError:
        return {"verified": False, "reason": "PARSE_ERROR"}


# ── Output helpers ────────────────────────────────────────────────────────────

WIDTH = 68

def line(char="─"):
    print(char * WIDTH)

def header():
    print()
    line("═")
    title = "OATH PROTOCOL DEMO — \"I Never Said That\""
    print(f"  {title}")
    line("═")
    print()

def section(label):
    print()
    line()
    print(f"  {label}")
    line()
    print()

def slow(text, delay=0.03):
    """Print text character by character for effect."""
    if not sys.stdout.isatty():
        print(text)
        return
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()


# ── Setup instructions ────────────────────────────────────────────────────────

def show_setup(binary):
    print()
    print("Run these commands before the demo to sign the two authorized actions:")
    print()
    print(f"  {binary} attest \\")
    print(f"    --action \"filesystem:read:project_logs\" \\")
    print(f"    --context \"reading logs is always safe\"")
    print()
    print(f"  {binary} attest \\")
    print(f"    --action \"email:send:team_status\" \\")
    print(f"    --context \"weekly status email approved\"")
    print()
    print("Then run:  python agent.py")
    print()


# ── Main demo ─────────────────────────────────────────────────────────────────

def run_demo(binary):
    header()

    print(f"  Task: \"{TASK}\"")
    print()
    print("  Agent planning actions...")
    print()

    for action in ACTIONS:
        print(f"    → {action['description']:<36}  [{action['action_class']}]")

    time.sleep(1)
    section("EXECUTING")

    audit = []

    for action in ACTIONS:
        ac = action["action_class"]
        result = oath_verify(binary, ac)
        verified = result.get("verified", False)
        reason = result.get("reason", "UNKNOWN")
        attestation_id = result.get("attestation_id", "")

        if verified:
            proof_short = attestation_id[:8] if attestation_id else "unknown"
            print(f"  ✓ ATTESTED   {ac}")
            print(f"               proof: {proof_short}")
            slow(f"               {action['consequence']}")
            audit.append(("ATTESTED", ac, attestation_id))
        else:
            print(f"  ✗ BLOCKED    {ac}")
            print(f"               {reason.lower().replace('_', ' ')}")
            slow(f"               {action['consequence']}")
            audit.append(("BLOCKED", ac, None))

        print()
        time.sleep(0.4)

    # ── Audit summary ──────────────────────────────────────────────────────

    section("TASK AUDIT")

    attested = [a for a in audit if a[0] == "ATTESTED"]
    blocked  = [a for a in audit if a[0] == "BLOCKED"]

    for status, ac, att_id in audit:
        if status == "ATTESTED":
            print(f"  ✓ ATTESTED   {ac}")
        else:
            print(f"  ✗ NO PROOF   {ac}")

    print()
    line()
    print()
    print(f"  {len(attested)} of {len(audit)} actions were explicitly authorized by a verified human.")
    print(f"  {len(blocked)} of {len(audit)} actions were blocked — no cryptographic proof of intent.")
    print()
    print("  The absence of a signature is itself evidence.")
    print()

    if blocked:
        print("  To authorize an action:")
        print(f"    oath attest --action \"<action_class>\" --context \"<reason>\"")
        print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Oath Protocol demo — provable human intent"
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Show the setup commands to run before the demo",
    )
    args = parser.parse_args()

    binary = find_oath_binary()
    if not binary:
        print("Error: oath binary not found.")
        print("Build it first:  cargo build --release")
        print("Or install it:   cargo install --path crates/oath-cli")
        sys.exit(1)

    if args.setup:
        show_setup(binary)
    else:
        run_demo(binary)


if __name__ == "__main__":
    main()
