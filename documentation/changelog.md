# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-01

### Added

**Core Library**

- Production-ready commit-reveal scheme with cryptographically secure implementation
- Zero-knowledge proof system using Schnorr signatures on secp256k1
- Comprehensive input validation with security-focused error handling
- Support for multiple data types: strings, integers, and bytes
- Multiple hash algorithms: SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2
- Type hints throughout for better development experience

**Zero-Knowledge Proofs**

- Elliptic curve cryptography implementation (secp256k1)
- Non-interactive proofs using Fiat-Shamir heuristic
- Schnorr signature scheme for proving knowledge without revelation
- Point compression and validation for efficient proof transmission
- Commitment consistency verification for revealed values

**Security Features**

- Cryptographically secure random number generation using `secrets` module
- Timing-safe comparisons using `hmac.compare_digest()`
- Input sanitization to prevent injection attacks
- Secure hash algorithm validation (deprecates MD5, SHA-1)
- File permission security (0600) for stored data

**Command Line Interface**

- Secure CLI (`commit-reveal-secure`) that never stores plaintext values
- Legacy CLI deprecation with security warnings
- Migration tool (`commit-reveal-migrate`) for upgrading from insecure format
- Secure input prompting using `getpass` without echo
- ZKP proof verification without value revelation

**Testing**

- Comprehensive test suite with >90% coverage requirement
- Property-based testing using Hypothesis
- Performance benchmarks for all major operations
- Security-focused tests for timing attacks and edge cases
- Integration tests for CLI functionality

**CI/CD**

- Multi-platform testing (Linux, macOS, Windows)
- Multi-version Python support (3.8-3.12)
- Automated security scanning with Bandit and Safety
- Code quality enforcement with Black, Flake8, MyPy strict

### Changed (Breaking)

- CLI interface redesigned for security (values not stored in plaintext)
- ZKP API returns proper cryptographic proofs instead of simplified hashes
- Error handling uses specific `ValidationError` and `SecurityError` types
- File format updated to secure storage format (v2.0)

### Deprecated

- Legacy CLI (`commit-reveal`) in favor of `commit-reveal-secure`
- Plaintext value storage

### Security

- Fixed timing attack vulnerability in commitment verification
- Eliminated plaintext storage in CLI applications
- Added comprehensive input validation against injection attacks
- Implemented secure file permissions for stored commitments

### Migration from v0.x

1. Update CLI usage:
   ```bash
   # Old
   commit-reveal commit name "value"
   # New
   commit-reveal-secure commit name
   ```

2. Migrate existing data:
   ```bash
   commit-reveal-migrate --all
   ```

3. Update ZKP API:
   ```python
   # Old
   nonce, challenge, response = cr.create_zkp_proof(value, salt, commitment)
   # New
   public_key, R_compressed, challenge, response = cr.create_zkp_proof(value, salt, commitment)
   ```

4. Handle new exceptions:
   ```python
   from commit_reveal import ValidationError, SecurityError
   ```

## [0.1.0] (Legacy)

- Basic commit-reveal scheme implementation
- Simple CLI tool
- SHA-256 support only

!!! warning
    Version 0.x stored values in plaintext and had known timing attack vulnerabilities. Upgrade to 1.0+.

## Support Policy

- **Current version (1.x)**: Full support with security updates
- **Legacy versions (0.x)**: No longer supported
