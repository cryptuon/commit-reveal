# commit-reveal

**Cryptographic commit-reveal schemes with zero-knowledge proofs. Pure Python. Zero dependencies.**

[![PyPI version](https://img.shields.io/pypi/v/commit-reveal)](https://pypi.org/project/commit-reveal/)
[![Python versions](https://img.shields.io/pypi/pyversions/commit-reveal)](https://pypi.org/project/commit-reveal/)
[![License: MIT](https://img.shields.io/github/license/cryptuon/commit-reveal)](https://github.com/cryptuon/commit-reveal/blob/main/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/cryptuon/commit-reveal/ci.yml?branch=main&label=CI)](https://github.com/cryptuon/commit-reveal/actions)
[![codecov](https://img.shields.io/codecov/c/github/cryptuon/commit-reveal)](https://codecov.io/gh/cryptuon/commit-reveal)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000)](https://github.com/psf/black)
[![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy%20strict-blue)](https://mypy-lang.org/)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow)](https://github.com/PyCQA/bandit)

---

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

Full API reference: [documentation](https://cryptuon.github.io/commit-reveal/api-reference/)

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

## Documentation

Full documentation available at [cryptuon.github.io/commit-reveal](https://cryptuon.github.io/commit-reveal/).

- [Getting Started](https://cryptuon.github.io/commit-reveal/getting-started/)
- [API Reference](https://cryptuon.github.io/commit-reveal/api-reference/)
- [Use Cases](https://cryptuon.github.io/commit-reveal/use-cases/) (auctions, voting, gaming, blockchain)
- [Security Guide](https://cryptuon.github.io/commit-reveal/security/)

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
