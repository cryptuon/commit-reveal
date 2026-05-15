# Getting Started

## What is a Commit-Reveal Scheme?

A commit-reveal scheme is a cryptographic protocol with two phases:

1. **Commit phase** -- participants commit to a value without revealing it
2. **Reveal phase** -- participants reveal their values and prove they match their commitments

This prevents participants from changing their minds after seeing others' commitments, ensuring fairness in auctions, voting, gaming, and other applications.

## Installation

=== "pip"

    ```bash
    pip install commit-reveal
    ```

=== "Poetry"

    ```bash
    poetry add commit-reveal
    ```

=== "From source"

    ```bash
    git clone https://github.com/cryptuon/commit-reveal.git
    cd commit-reveal
    poetry install
    ```

## Basic Usage

### Your First Commit-Reveal

```python
from commit_reveal import CommitRevealScheme

# Create a scheme instance
cr = CommitRevealScheme()

# Commit to a secret value
secret = "my secret data"
commitment, salt = cr.commit(secret)

print(f"Commitment: {commitment.hex()}")
print(f"Salt: {salt.hex()}")

# Later, reveal the value
is_valid = cr.reveal(secret, salt, commitment)
print(f"Reveal successful: {is_valid}")  # True

# Wrong value fails
is_valid = cr.reveal("wrong value", salt, commitment)
print(f"Wrong reveal: {is_valid}")  # False
```

### Understanding the Output

| Term | Description |
|------|-------------|
| **Commitment** | A cryptographic hash that binds you to your secret without revealing it |
| **Salt** | Random data ensuring identical values produce different commitments |
| **Reveal** | Verification that your revealed value matches your original commitment |

## Zero-Knowledge Proofs

Zero-knowledge proofs let you prove you know a secret without revealing it.

```python
cr = CommitRevealScheme(use_zkp=True)

# Commit
secret = "auction bid: $1000"
commitment, salt = cr.commit(secret)

# Create a zero-knowledge proof
public_key, R_compressed, challenge, response = cr.create_zkp_proof(
    secret, salt, commitment
)

# Anyone can verify you know the secret without seeing it
is_valid = cr.verify_zkp_proof(
    commitment, public_key, R_compressed, challenge, response
)
print(f"ZKP verification: {is_valid}")  # True

# Later, when you reveal, verify consistency
consistency = cr.verify_commitment_consistency(
    secret, salt, commitment, public_key
)
print(f"Consistency check: {consistency}")  # True
```

## Supported Data Types

```python
cr = CommitRevealScheme()

# Strings
commitment, salt = cr.commit("hello world")

# Integers
commitment, salt = cr.commit(42)

# Bytes
commitment, salt = cr.commit(b"binary data")
```

## Hash Algorithms

```python
# SHA-256 (default, recommended)
cr = CommitRevealScheme(hash_algorithm='sha256')

# SHA-512 for extra security
cr = CommitRevealScheme(hash_algorithm='sha512')

# SHA-3 variants
cr = CommitRevealScheme(hash_algorithm='sha3_256')

# BLAKE2 (fast and secure)
cr = CommitRevealScheme(hash_algorithm='blake2b')
```

!!! warning
    Insecure algorithms like MD5 and SHA-1 are automatically rejected with a `SecurityError`.

## Command Line Usage

The secure CLI never stores your secrets on disk:

```bash
# Commit to a value (prompts securely)
commit-reveal-secure commit my-auction-bid

# Reveal your value
commit-reveal-secure reveal my-auction-bid

# List your commitments
commit-reveal-secure list

# Use zero-knowledge proofs
commit-reveal-secure --zkp commit my-vote
commit-reveal-secure --zkp verify-proof my-vote
```

## Error Handling

```python
from commit_reveal import CommitRevealScheme, ValidationError, SecurityError

try:
    cr = CommitRevealScheme(hash_algorithm='md5')
except SecurityError as e:
    print(f"Security error: {e}")

try:
    cr = CommitRevealScheme()
    cr.commit(-42)
except ValidationError as e:
    print(f"Validation error: {e}")
```

## Next Steps

- [API Reference](api-reference.md) -- complete method documentation
- [CLI Guide](cli.md) -- full command-line reference
- [Use Cases](use-cases/index.md) -- real-world application examples
- [Security Guide](security/index.md) -- production deployment guidance
