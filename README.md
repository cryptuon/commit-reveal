# commit-reveal

**A fairness primitive for the agent economy: commit-reveal schemes with Schnorr zero-knowledge proofs. Pure Python. Zero dependencies.**

[![PyPI version](https://img.shields.io/pypi/v/commit-reveal)](https://pypi.org/project/commit-reveal/)
[![Python versions](https://img.shields.io/pypi/pyversions/commit-reveal)](https://pypi.org/project/commit-reveal/)
[![License: MIT](https://img.shields.io/github/license/cryptuon/commit-reveal)](https://github.com/cryptuon/commit-reveal/blob/main/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/cryptuon/commit-reveal/ci.yml?branch=main&label=CI)](https://github.com/cryptuon/commit-reveal/actions)
[![codecov](https://img.shields.io/codecov/c/github/cryptuon/commit-reveal)](https://codecov.io/gh/cryptuon/commit-reveal)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000)](https://github.com/psf/black)
[![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy%20strict-blue)](https://mypy-lang.org/)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow)](https://github.com/PyCQA/bandit)

**[🌐 Site](https://commit-reveal.cryptuon.com/) · [📚 Docs](https://docs.cryptuon.com/commit-reveal/) · [📦 PyPI package](https://pypi.org/project/commit-reveal/) · [🗺️ Roadmap](ROADMAP.md) · [🔬 Cryptuon Research](https://github.com/cryptuon)**

---

## Why this matters in 2026

Most of the money lost or extracted on public chains comes from one root cause: **someone sees your action before it is final and reacts to it.** Front-running, sandwich attacks, copy-trading bots, and oracle games are all timing attacks on information that leaked too early. Commit-reveal is the oldest, smallest, most auditable fix for that class of problem — you *bind* to a value now and *announce* it later, so nobody can act on what they cannot yet see.

That primitive is having a moment. The narratives driving crypto in 2026 — **agentic payments, verifiable on-chain AI, prediction markets, MEV mitigation, and intent-based DEXs** — all need cheap, verifiable fairness at their core:

- **Anti-MEV / fair ordering** — order intents commit during a sealed window, then reveal for matching. Front-runners cannot react to orders they have not yet seen.
- **Sealed-bid auctions** — bidders publish commitments; nobody, not even the auctioneer, reads a bid before the reveal deadline. The natural settlement layer for RWA and NFT auctions.
- **Commit-reveal randomness** — many parties commit to seeds, then reveal; the result is a hash of all reveals, uniform and unmanipulable as long as one participant is honest.
- **Verifiable AI** — in networks where independent agents (e.g. DFPN-style inference or forecasting nodes) must submit answers *without copying each other*, each agent commits to its output first and reveals after the window closes. The Schnorr ZKP then lets an agent prove "this reveal matches my commitment" without re-broadcasting the payload.
- **Prediction-market resolution** — resolvers commit to an outcome before it is public, removing the last-look advantage.

`commit-reveal` is a **small, dependency-free primitive** you drop into that infrastructure. It is a **library, not a network** — it computes and verifies commitments and proofs; it does not run consensus, hold funds, or settle on-chain by itself. What ships on-chain is your choice: the reference path to a minimal on-chain verifier is laid out in [ROADMAP.md](ROADMAP.md#cheapest-path-to-production).

## Highlights

- **Multi-algorithm commitments** &mdash; SHA-256, SHA-512, SHA-3, BLAKE2b/2s
- **Schnorr zero-knowledge proofs** on secp256k1 (same curve as Bitcoin)
- **Tamper-evident audit trail** with cryptographic integrity verification
- **Secure CLI** that never stores plaintext values on disk
- **Zero external dependencies** &mdash; stdlib only
- **90%+ test coverage**, mypy strict, property-based testing with Hypothesis

## Installation

```bash
pip install commit-reveal
```

Or with [Poetry](https://python-poetry.org/):

```bash
poetry add commit-reveal
```

## Quick Start

### Basic commit-reveal

```python
from commit_reveal import CommitRevealScheme

scheme = CommitRevealScheme()

# Commit phase — share the commitment, keep the salt secret
commitment, salt = scheme.commit("my secret value")

# Reveal phase — prove you committed to this value
assert scheme.reveal("my secret value", salt, commitment)  # True
assert not scheme.reveal("wrong value", salt, commitment)   # False
```

### With zero-knowledge proofs

```python
scheme = CommitRevealScheme(use_zkp=True)

commitment, salt = scheme.commit("secret")
public_key, R_compressed, challenge, response = scheme.create_zkp_proof(
    "secret", salt, commitment
)

# Anyone can verify you know the secret — without learning it
assert scheme.verify_zkp_proof(
    commitment, public_key, R_compressed, challenge, response
)
```

### CLI

```bash
# Commit to a value (prompts securely, no echo)
commit-reveal-secure commit my-secret

# Verify the value later
commit-reveal-secure reveal my-secret

# List stored commitments
commit-reveal-secure list
```

## Supported Hash Algorithms

| Algorithm | Output | Notes |
|-----------|--------|-------|
| `sha256` | 32 bytes | Default, widely compatible |
| `sha384` | 48 bytes | |
| `sha512` | 64 bytes | Higher security margin |
| `sha3_256` | 32 bytes | NIST post-quantum family |
| `sha3_384` | 48 bytes | |
| `sha3_512` | 64 bytes | |
| `blake2b` | 64 bytes | Fast on 64-bit platforms |
| `blake2s` | 32 bytes | Fast on 32-bit platforms |

## API at a Glance

```python
class CommitRevealScheme:
    def __init__(self, hash_algorithm='sha256', use_zkp=False, enable_audit=True): ...

    def commit(value, salt=None) -> tuple[bytes, bytes]: ...
    def reveal(value, salt, commitment) -> bool: ...
    def verify(value, salt, commitment) -> bool: ...  # alias for reveal

    # Zero-knowledge proofs (requires use_zkp=True)
    def create_zkp_proof(value, salt, commitment) -> tuple: ...
    def verify_zkp_proof(commitment, public_key, R_compressed, challenge, response) -> bool: ...
    def verify_commitment_consistency(value, salt, commitment, public_key) -> bool: ...
```

**Exceptions:** `ValidationError` for invalid input, `SecurityError` for insecure operations (e.g., MD5/SHA-1).

Full API reference: [documentation](https://docs.cryptuon.com/commit-reveal/api-reference/)

## CLI Tools

| Command | Description |
|---------|-------------|
| `commit-reveal-secure` | Production CLI &mdash; never stores plaintext |
| `commit-reveal-migrate` | Migrate from legacy to secure format |
| `commit-reveal` | Legacy CLI (deprecated) |

Enable ZKP for any command with `--zkp`:

```bash
commit-reveal-secure --zkp commit my-secret
commit-reveal-secure --zkp verify-proof my-secret
```

## Where this fits in 2026 infrastructure

| Narrative | The unfairness it removes | How commit-reveal helps |
|-----------|---------------------------|-------------------------|
| **MEV mitigation / fair ordering** | Searchers front-run and sandwich pending transactions | Commit intents in a sealed window; reveal for matching. No peeking, no reordering advantage. |
| **Verifiable on-chain AI** | Agents copy each other's answers instead of computing independently | Each agent commits to its output first; reveals after the window; proves consistency with a Schnorr ZKP. |
| **Sealed-bid auctions (RWA, NFTs)** | Late bidders read earlier bids | Bids are commitments until the deadline; the auctioneer cannot read them either. |
| **On-chain randomness** | A single party biases the seed | Multi-party commit-reveal RNG; honest-minority safe. |
| **Prediction-market resolution** | Resolvers exploit last-look information | Resolvers commit to an outcome before it is public. |

For the full "where it fits and how to get to production" picture, see **[ROADMAP.md](ROADMAP.md)**.

> **Scope, stated plainly:** commit-reveal is a *primitive library*, not a sequencer, a mempool, or an L2. It gives you the cryptographic core (bind, reveal, prove) that fairness-preserving systems are built from. The system design — who commits, when the window closes, where reveals are posted — is yours.

## Documentation

Full documentation available at [docs.cryptuon.com/commit-reveal](https://docs.cryptuon.com/commit-reveal/).

- [Getting Started](https://docs.cryptuon.com/commit-reveal/getting-started/)
- [API Reference](https://docs.cryptuon.com/commit-reveal/api-reference/)
- [Use Cases](https://docs.cryptuon.com/commit-reveal/use-cases/) (auctions, voting, gaming, blockchain)
- [Security Guide](https://docs.cryptuon.com/commit-reveal/security/)

## Development

```bash
# Install with dev dependencies
poetry install --with dev

# Run tests
poetry run pytest

# Type checking
poetry run mypy commit_reveal/ --strict

# Formatting
poetry run black commit_reveal/ tests/

# Security scan
poetry run bandit -r commit_reveal/
```

## Security

See [SECURITY.md](SECURITY.md) for the full security policy, threat model, and vulnerability reporting process.

## License

[MIT](LICENSE) &copy; 2025 Dipankar Sarkar

---

## Part of Cryptuon Research

`commit-reveal` is one of [20 open-source blockchain-infrastructure projects](https://www.cryptuon.com/projects) from **[Cryptuon Research](https://www.cryptuon.com)** — blockchain theory, shipped as protocols.

**Related projects:** [blockchain-compression](https://blockchain-compression.cryptuon.com/) · [StxScript](https://stxscript.cryptuon.com/) · [nklave](https://nklave.cryptuon.com/)

Docs: [docs.cryptuon.com/commit-reveal](https://docs.cryptuon.com/commit-reveal/) · Contact: [contact@cryptuon.com](mailto:contact@cryptuon.com)
