# Commit-Reveal Library

A Python library that implements commit-reveal schemes using zero-knowledge proofs.

## Overview

The commit-reveal scheme is a cryptographic protocol that allows one party to commit to a value while keeping it hidden, with the ability to reveal it later. This library provides a simple implementation of this scheme with the following features:

- Simple API for committing to values and revealing them later
- Support for strings, integers, and bytes
- Cryptographically secure implementation using SHA-256
- Optional zero-knowledge proof capabilities
- Command-line interface for local testing

## Installation

```bash
pip install commit-reveal
```

## Usage

### Basic Usage

```python
from commit_reveal import CommitRevealScheme

# Create an instance
cr = CommitRevealScheme()

# Commit phase
value = "my secret"
commitment, salt = cr.commit(value)
print(f"Commitment: {commitment.hex()}")

# Reveal phase (later)
is_valid = cr.reveal(value, salt, commitment)
print(f"Reveal valid: {is_valid}")
```

### Advanced Usage with Zero-Knowledge Proofs

```python
from commit_reveal import CommitRevealScheme

# Create an instance with ZKP enabled
cr = CommitRevealScheme(use_zkp=True)

# Commit phase
value = "my secret"
commitment, salt = cr.commit(value)

# Create a zero-knowledge proof
nonce, challenge, response = cr.create_zkp_proof(value, salt, commitment)

# Verify the zero-knowledge proof (without revealing the value)
is_proof_valid = cr.verify_zkp_proof(commitment, nonce, challenge, response)
print(f"ZKP proof valid: {is_proof_valid}")

# Reveal phase (later)
is_valid = cr.reveal(value, salt, commitment)
print(f"Reveal valid: {is_valid}")
```

### Command-Line Interface

The library includes a command-line interface for local testing:

```bash
# Commit to a value
commit-reveal commit my-secret "This is my secret"

# Reveal a value
commit-reveal reveal my-secret "This is my secret"

# Verify a value without revealing
commit-reveal verify my-secret "This is my secret"

# List all commitments
commit-reveal list

# Delete a commitment
commit-reveal delete my-secret

# Using ZKP functionality
commit-reveal --zkp commit my-secret "This is my secret"
commit-reveal --zkp prove my-secret
commit-reveal --zkp verify-proof my-secret
```

The CLI stores commitments in a `.commit-reveal` directory in your home folder.

## API

### CommitRevealScheme(hash_algorithm='sha256', use_zkp=False)

Initialize the commit-reveal scheme.

**Parameters:**
- `hash_algorithm` (str): The hash algorithm to use (default: sha256)
- `use_zkp` (bool): Whether to enable zero-knowledge proof functionality (default: False)

### commit(value, salt=None)

Commit to a value.

**Parameters:**
- `value` (str, int, bytes): The value to commit to
- `salt` (bytes, optional): Salt for the commitment. If None, a random salt is generated.

**Returns:**
- `tuple`: (commitment, salt)

### reveal(value, salt, commitment)

Reveal a value and verify it matches the commitment.

**Parameters:**
- `value` (str, int, bytes): The original value
- `salt` (bytes): The salt used in the commitment
- `commitment` (bytes): The original commitment

**Returns:**
- `bool`: True if the revealed value matches the commitment, False otherwise

### verify(value, salt, commitment)

Alias for `reveal()`.

### create_zkp_proof(value, salt, commitment)

Create a zero-knowledge proof for the commitment.

**Parameters:**
- `value` (str, int, bytes): The original value
- `salt` (bytes): The salt used in the commitment
- `commitment` (bytes): The commitment to prove knowledge of

**Returns:**
- `tuple`: (nonce, challenge, response)

### verify_zkp_proof(commitment, nonce, challenge, response)

Verify a zero-knowledge proof.

**Parameters:**
- `commitment` (bytes): The commitment
- `nonce` (bytes): The nonce used in the proof
- `challenge` (int): The challenge value
- `response` (int): The response to the challenge

**Returns:**
- `bool`: True if the proof is valid, False otherwise

## Security Notes

This implementation uses SHA-256 for hashing, which is considered cryptographically secure. The salt is generated using Python's `secrets` module, which provides access to the most secure source of randomness provided by the operating system.

The zero-knowledge proof implementation is a simplified version based on Schnorr-like protocols. For production use, consider using more established ZKP libraries.

## License

MIT