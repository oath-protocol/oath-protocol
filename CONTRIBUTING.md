# Contributing to Oath Protocol

Thank you for your interest in contributing. Oath is designed to be open infrastructure — the kind that belongs to everyone. That means contributions are genuinely welcome, and the process is designed to be as frictionless as possible.

## Before You Write Code

**Read the spec first.** The protocol specification in `spec/OATH_SPEC.md` is the source of truth. Every implementation decision must be traceable back to the spec. If the spec is ambiguous, open an issue before writing code.

**The spec is CC0 (public domain). The code is MIT.** This means anyone can implement the protocol in any language without restriction. The reference implementation (OathKit, in Rust) is MIT licensed.

## Types of Contributions

### Spec contributions
Changes to `spec/OATH_SPEC.md` are the most consequential kind of contribution. They affect every implementation, in every language, forever. Open an issue using the `spec_discussion` template before proposing spec changes. Spec changes require discussion before a PR.

### Implementation contributions
Bug fixes, performance improvements, and new features in `oathkit-core`, `oath-cli`, or the Python SDK. Follow the existing code style. Run `cargo test` before submitting.

### New language implementations
If you want to build an Oath implementation in a language not yet covered, please open an issue first so we can coordinate and ensure the implementation is listed in the official registry.

### Documentation contributions
Typos, clarifications, examples — always welcome, no discussion needed.

## Development Setup

```bash
git clone https://github.com/oath-protocol/oath-protocol
cd oath-protocol
cargo build
cargo test
```

Python SDK:
```bash
cd sdk/python
pip install -e ".[dev]"
pytest
```

## Conformance

Any implementation claiming to be a conforming Oath implementation MUST pass all test vectors in `spec/OATH_SPEC.md` Section 18. When the reference implementation locks the test vectors at v1.0.0, we will publish a conformance test suite.

## Issue Templates

- **Bug report** — for bugs in the reference implementation
- **Spec discussion** — for proposed changes to the protocol specification

## Code of Conduct

Be direct. Be honest. Be respectful. This is infrastructure that matters — treat it accordingly.
