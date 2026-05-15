# commit-reveal

**Cryptographic commit-reveal schemes with zero-knowledge proofs. Pure Python. Zero dependencies.**

---

<div class="grid cards" markdown>

-   **Multi-Algorithm Commitments**

    SHA-256, SHA-512, SHA-3, BLAKE2b/2s -- choose the right hash for your use case.

-   **Zero-Knowledge Proofs**

    Schnorr signatures on secp256k1. Prove you know a secret without revealing it.

-   **Tamper-Evident Audit Trail**

    Cryptographic integrity verification for every operation. Compliance-ready logging.

-   **Secure CLI**

    Production command-line tool that never stores plaintext values on disk.

-   **Zero External Dependencies**

    Pure Python standard library. No supply-chain risk.

-   **Battle-Tested**

    90%+ test coverage, mypy strict, property-based testing with Hypothesis.

</div>

## Quick Install

```bash
pip install commit-reveal
```

## Quick Example

```python
from commit_reveal import CommitRevealScheme

scheme = CommitRevealScheme()

# Commit phase -- share the commitment, keep the salt secret
commitment, salt = scheme.commit("my secret value")

# Reveal phase -- prove you committed to this value
assert scheme.reveal("my secret value", salt, commitment)
```

### With Zero-Knowledge Proofs

```python
scheme = CommitRevealScheme(use_zkp=True)

commitment, salt = scheme.commit("secret")
public_key, R_compressed, challenge, response = scheme.create_zkp_proof(
    "secret", salt, commitment
)

# Anyone can verify -- without learning the secret
assert scheme.verify_zkp_proof(
    commitment, public_key, R_compressed, challenge, response
)
```

## Next Steps

- [Getting Started](getting-started.md) -- installation and first steps
- [API Reference](api-reference.md) -- full method documentation
- [Use Cases](use-cases/index.md) -- auctions, voting, gaming, blockchain
- [Security Guide](security/index.md) -- threat model and best practices
