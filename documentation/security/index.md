# Security

## Security Model

The commit-reveal library operates under these assumptions:

1. **Trusted execution environment** -- the OS and hardware are not compromised
2. **Secure randomness** -- Python's `secrets` module provides cryptographically secure random numbers
3. **Hash function security** -- the selected algorithms (SHA-256, SHA-512, etc.) remain cryptographically secure
4. **Network security** -- when used in distributed systems, secure channels (TLS) are used

## Threat Model

### Threats We Protect Against

| Threat | Mitigation |
|--------|------------|
| **Timing attacks** | Constant-time comparisons via `hmac.compare_digest` |
| **Side-channel attacks** | Secure random number generation, careful memory handling |
| **Input injection** | Comprehensive validation and sanitization |
| **Information leakage** | No plaintext values stored in secure mode |
| **Replay attacks** | Timestamping and nonce usage |
| **Commitment tampering** | Cryptographic binding prevents changes after commit |

### Out of Scope

- Physical/hardware attacks
- OS-level compromise
- Network-level attacks (MITM)
- Social engineering

## Cryptographic Primitives

### Hash Algorithms

The library enforces secure algorithm selection:

```python
# Allowed
SECURE_ALGORITHMS = {
    'sha256', 'sha384', 'sha512',
    'sha3_256', 'sha3_384', 'sha3_512',
    'blake2b', 'blake2s'
}

# Rejected with SecurityError
DEPRECATED_ALGORITHMS = {'md5', 'sha1', 'sha224'}
```

### Salt Requirements

- Minimum 16 bytes (128 bits)
- Maximum 1024 bytes
- Must have sufficient entropy (at least 4 unique byte values)
- All-zero salts are rejected

### Zero-Knowledge Proofs

- **Curve**: secp256k1 (same as Bitcoin)
- **Scheme**: Schnorr signatures
- **Non-interactive**: Fiat-Shamir heuristic
- **Point compression**: 33-byte compressed representation

!!! warning "ZKP Limitations"
    - Each proof should only be used once
    - Public keys should not be reused across commitments
    - For high-stakes applications, consider a professional audit

## Reporting Vulnerabilities

See [SECURITY.md](https://github.com/cryptuon/commit-reveal/blob/main/SECURITY.md) for the full security policy and reporting process.

!!! danger "Do Not"
    Create public GitHub issues for security vulnerabilities. Report them privately.

## Further Reading

- [Best Practices](best-practices.md) -- production deployment guidance
- [Audit Trail](audit-trail.md) -- tamper-evident logging
- [ZKP Internals](../advanced/zkp-internals.md) -- cryptographic details
