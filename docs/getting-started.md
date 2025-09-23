# Getting Started Guide

This guide will help you get up and running with the commit-reveal library quickly and securely.

## What is Commit-Reveal?

A commit-reveal scheme is a cryptographic protocol with two phases:

1. **Commit Phase**: Participants commit to a value without revealing what it is
2. **Reveal Phase**: Participants reveal their values and prove they match their commitments

This prevents participants from changing their minds after seeing others' commitments, ensuring fairness in auctions, voting, gaming, and other applications.

## Installation

### Basic Installation

```bash
pip install commit-reveal
```

### Using Poetry (Recommended for Development)

```bash
# Install Poetry if you haven't already
curl -sSL https://install.python-poetry.org | python3 -

# Clone and install the project
git clone https://github.com/dipankar/commit-reveal.git
cd commit-reveal
poetry install
```

### Development Installation

For development with all testing and linting tools:

```bash
# Using Poetry (recommended)
poetry install --with dev

# Using pip (alternative)
git clone https://github.com/dipankar/commit-reveal.git
cd commit-reveal
pip install -e ".[dev]"
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

# Try with wrong value
is_valid = cr.reveal("wrong value", salt, commitment)
print(f"Wrong reveal: {is_valid}")  # False
```

### Understanding the Output

- **Commitment**: A cryptographic hash that binds you to your secret without revealing it
- **Salt**: Random data that ensures identical values produce different commitments
- **Reveal**: Verification that your revealed value matches your original commitment

## Zero-Knowledge Proofs

Zero-knowledge proofs let you prove you know a secret without revealing it.

```python
from commit_reveal import CommitRevealScheme

# Enable ZKP functionality
cr = CommitRevealScheme(use_zkp=True)

# Commit to a value
secret = "auction bid: $1000"
commitment, salt = cr.commit(secret)

# Create a zero-knowledge proof
public_key, R_compressed, challenge, response = cr.create_zkp_proof(
    secret, salt, commitment
)

print("ZKP proof created successfully!")

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

## Command Line Usage

### Secure CLI (Recommended)

The secure CLI never stores your secrets on disk:

```bash
# Commit to a value (prompts securely)
commit-reveal-secure commit my-auction-bid

# Reveal your value (prompts securely)
commit-reveal-secure reveal my-auction-bid

# List your commitments
commit-reveal-secure list

# Use zero-knowledge proofs
commit-reveal-secure --zkp commit my-vote
commit-reveal-secure --zkp verify-proof my-vote
```

### CLI Security Features

- **No Plaintext Storage**: Your secrets are never saved to disk
- **Secure Prompting**: Uses `getpass` so your input isn't echoed
- **File Permissions**: All files created with 0600 permissions (owner-only)
- **Audit Trail**: All operations logged for security compliance

## Data Types Supported

The library supports multiple data types:

```python
cr = CommitRevealScheme()

# Strings
commitment1, salt1 = cr.commit("hello world")

# Integers
commitment2, salt2 = cr.commit(42)

# Bytes
commitment3, salt3 = cr.commit(b"binary data")

# Unicode strings
commitment4, salt4 = cr.commit("🔐 secure data 🔒")
```

## Hash Algorithms

Choose from cryptographically secure hash algorithms:

```python
# SHA-256 (default, recommended)
cr1 = CommitRevealScheme(hash_algorithm='sha256')

# SHA-512 for extra security
cr2 = CommitRevealScheme(hash_algorithm='sha512')

# SHA-3 variants
cr3 = CommitRevealScheme(hash_algorithm='sha3_256')

# BLAKE2 (fast and secure)
cr4 = CommitRevealScheme(hash_algorithm='blake2b')
```

Insecure algorithms like MD5 and SHA-1 are automatically rejected.

## Error Handling

The library provides specific exceptions for different error types:

```python
from commit_reveal import CommitRevealScheme, ValidationError, SecurityError

try:
    # This will fail - MD5 is insecure
    cr = CommitRevealScheme(hash_algorithm='md5')
except SecurityError as e:
    print(f"Security error: {e}")

try:
    # This will fail - negative integers not supported
    cr = CommitRevealScheme()
    cr.commit(-42)
except ValidationError as e:
    print(f"Validation error: {e}")
```

## Security Best Practices

### 1. Use the Secure CLI

Always use `commit-reveal-secure` instead of the legacy CLI:

```bash
# Good
commit-reveal-secure commit my-secret

# Avoid (legacy, stores plaintext)
commit-reveal commit my-secret "plaintext value"
```

### 2. Handle Exceptions Properly

```python
from commit_reveal import CommitRevealScheme, ValidationError, SecurityError

def safe_commit_reveal(secret):
    try:
        cr = CommitRevealScheme()
        commitment, salt = cr.commit(secret)

        # Store commitment and salt securely
        # ...

        return commitment, salt

    except ValidationError as e:
        print(f"Invalid input: {e}")
        return None, None
    except SecurityError as e:
        print(f"Security violation: {e}")
        return None, None
```

### 3. Use ZKP When Appropriate

Zero-knowledge proofs are useful when you need to prove knowledge without revelation:

```python
# For auctions - prove you have a valid bid without revealing amount
cr = CommitRevealScheme(use_zkp=True)
commitment, salt = cr.commit(bid_amount)
proof = cr.create_zkp_proof(bid_amount, salt, commitment)

# For voting - prove eligibility without revealing vote
commitment, salt = cr.commit(vote_choice)
proof = cr.create_zkp_proof(vote_choice, salt, commitment)
```

### 4. Enable Audit Trails

For compliance and security monitoring:

```python
# Audit trail enabled by default
cr = CommitRevealScheme(enable_audit=True)

# Check audit integrity
from commit_reveal.audit import get_audit_trail
audit = get_audit_trail()
integrity_check = audit.verify_integrity()
print(f"Audit integrity: {integrity_check['integrity_verified']}")
```

## Common Patterns

### Two-Party Fair Exchange

```python
def fair_exchange_protocol():
    cr = CommitRevealScheme(use_zkp=True)

    # Alice commits to her offer
    alice_offer = "100 coins"
    alice_commitment, alice_salt = cr.commit(alice_offer)

    # Bob commits to his offer
    bob_offer = "rare sword"
    bob_commitment, bob_salt = cr.commit(bob_offer)

    # Both create ZKP proofs they have valid offers
    alice_proof = cr.create_zkp_proof(alice_offer, alice_salt, alice_commitment)
    bob_proof = cr.create_zkp_proof(bob_offer, bob_salt, bob_commitment)

    # Verify proofs without seeing offers
    alice_valid = cr.verify_zkp_proof(alice_commitment, *alice_proof)
    bob_valid = cr.verify_zkp_proof(bob_commitment, *bob_proof)

    if alice_valid and bob_valid:
        # Both reveals happen simultaneously
        alice_reveal = cr.reveal(alice_offer, alice_salt, alice_commitment)
        bob_reveal = cr.reveal(bob_offer, bob_salt, bob_commitment)

        return alice_offer, bob_offer

    return None, None
```

### Sealed Bid Auction

```python
def sealed_bid_auction(bids_dict):
    cr = CommitRevealScheme(use_zkp=True)
    commitments = {}

    # Commit phase
    for bidder, bid in bids_dict.items():
        commitment, salt = cr.commit(bid)
        zkp_proof = cr.create_zkp_proof(bid, salt, commitment)
        commitments[bidder] = (commitment, salt, zkp_proof)

    # Verify all bidders have valid bids (without revealing)
    for bidder, (commitment, salt, proof) in commitments.items():
        is_valid = cr.verify_zkp_proof(commitment, *proof)
        if not is_valid:
            print(f"Invalid bid from {bidder}")
            return None

    # Reveal phase
    revealed_bids = {}
    for bidder, bid in bids_dict.items():
        commitment, salt, _ = commitments[bidder]
        if cr.reveal(bid, salt, commitment):
            revealed_bids[bidder] = bid

    # Find winner
    winner = max(revealed_bids, key=revealed_bids.get)
    return winner, revealed_bids[winner]
```

## Testing

Run the comprehensive test suite:

```bash
# Using Poetry (recommended)
poetry install --with dev
poetry run pytest

# Run with coverage
poetry run pytest --cov=commit_reveal

# Run only fast tests
poetry run pytest -m "not slow"

# Run security tests
poetry run pytest -m security

# Run performance benchmarks
poetry run pytest -m performance

# Using pip (alternative)
pip install -e ".[dev]"
pytest
```

## Development Tools

### Code Quality

```bash
# Format code
poetry run black commit_reveal/ tests/

# Sort imports
poetry run isort commit_reveal/ tests/

# Run linting
poetry run flake8 commit_reveal/ tests/

# Type checking
poetry run mypy commit_reveal/

# Security scanning
poetry run bandit -r commit_reveal/
```

### Pre-commit Hooks

```bash
# Install pre-commit hooks
poetry run pre-commit install

# Run all hooks manually
poetry run pre-commit run --all-files
```

## Next Steps

- Read the [Use Cases Guide](use-cases.md) for detailed application examples
- Check the [API Reference](api-reference.md) for complete method documentation
- Review the [Security Guide](security-guide.md) for production deployment
- See [Advanced Features](advanced-features.md) for ZKP and audit trail details

## Need Help?

- Check the [FAQ](faq.md) for common questions
- Review the [Troubleshooting Guide](troubleshooting.md) for common issues
- Report bugs at [GitHub Issues](https://github.com/dipankar/commit-reveal/issues)
- Read the [Security Policy](../SECURITY.md) for security-related questions