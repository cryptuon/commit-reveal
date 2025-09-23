# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-01

### Added

#### Core Library
- **Production-ready commit-reveal scheme** with cryptographically secure implementation
- **Proper zero-knowledge proof system** using Schnorr signatures on secp256k1
- **Comprehensive input validation** with security-focused error handling
- **Support for multiple data types**: strings, integers, and bytes
- **Multiple hash algorithms**: SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2
- **Type hints throughout** for better development experience

#### Zero-Knowledge Proofs
- **Elliptic curve cryptography** implementation (secp256k1)
- **Non-interactive zero-knowledge proofs** using Fiat-Shamir heuristic
- **Proper Schnorr signature scheme** for proving knowledge without revelation
- **Point compression and validation** for efficient proof transmission
- **Commitment consistency verification** for revealed values

#### Security Features
- **Cryptographically secure random number generation** using `secrets` module
- **Timing-safe comparisons** using `hmac.compare_digest()`
- **Input sanitization** to prevent injection attacks
- **Secure hash algorithm validation** (deprecates MD5, SHA-1)
- **File permission security** (0600) for stored data

#### Command Line Interface
- **Secure CLI** (`commit-reveal-secure`) that never stores plaintext values
- **Legacy CLI deprecation** with security warnings
- **Migration tool** (`commit-reveal-migrate`) for upgrading from insecure format
- **Secure input prompting** using `getpass` without echo
- **Interactive confirmations** for destructive operations
- **ZKP proof verification** without value revelation

#### Testing and Quality Assurance
- **Comprehensive test suite** with >90% coverage requirement
- **Property-based testing** using Hypothesis for robust validation
- **Performance benchmarks** for all major operations
- **Security-focused tests** for timing attacks and edge cases
- **Integration tests** for CLI functionality
- **Stateful testing** for complex interaction patterns

#### CI/CD Pipeline
- **Multi-platform testing** (Linux, macOS, Windows)
- **Multi-version Python support** (3.7-3.12)
- **Automated security scanning** with Bandit and Safety
- **Code quality enforcement** with Black, Flake8, MyPy
- **Performance monitoring** with automated benchmarks
- **Dependency vulnerability scanning** with GitHub Actions
- **CodeQL security analysis** for comprehensive code review

#### Development Tools
- **Poetry dependency management** for modern Python packaging
- **Pre-commit hooks** for code quality and security
- **Type checking** with MyPy in strict mode
- **Code formatting** with Black and isort
- **Security linting** with Bandit
- **Documentation linting** with pydocstyle
- **YAML validation** with yamllint
- **Secret detection** with detect-secrets

### Changed

#### Breaking Changes
- **CLI interface redesigned** for security (values not stored in plaintext)
- **ZKP API changed** to return proper cryptographic proofs instead of simplified hashes
- **Error handling improved** with specific `ValidationError` and `SecurityError` types
- **File format updated** to secure storage format (v2.0)

#### Performance Improvements
- **Optimized elliptic curve operations** for better ZKP performance
- **Efficient point compression** for reduced storage/transmission overhead
- **Streamlined validation pipeline** for faster input processing

### Deprecated

- **Legacy CLI** (`commit-reveal`) deprecated in favor of secure version
- **Plaintext value storage** deprecated for security reasons
- **Simplified ZKP implementation** replaced with proper cryptographic proofs

### Security

- **Fixed timing attack vulnerability** in commitment verification
- **Eliminated plaintext storage** in CLI applications
- **Added comprehensive input validation** to prevent injection attacks
- **Implemented secure file permissions** for stored commitments
- **Added protection against directory traversal** in filename handling

### Migration Guide

#### From v0.x to v1.0

1. **Update CLI usage**:
   ```bash
   # Old (deprecated)
   commit-reveal commit name "value"

   # New (secure)
   commit-reveal-secure commit name
   # (prompts securely for value)
   ```

2. **Migrate existing data**:
   ```bash
   commit-reveal-migrate --all
   ```

3. **Update code**:
   ```python
   # Old ZKP API
   nonce, challenge, response = cr.create_zkp_proof(value, salt, commitment)

   # New ZKP API
   public_key, R_compressed, challenge, response = cr.create_zkp_proof(value, salt, commitment)
   ```

4. **Handle new exceptions**:
   ```python
   from commit_reveal import ValidationError, SecurityError

   try:
       cr.commit(value)
   except ValidationError as e:
       # Handle validation errors
       pass
   except SecurityError as e:
       # Handle security violations
       pass
   ```

## [0.1.0] - 2023-XX-XX (Legacy)

### Added
- Basic commit-reveal scheme implementation
- Simple CLI tool
- Basic zero-knowledge proof concept
- SHA-256 hash support

### Known Issues (Fixed in 1.0.0)
- Stored values in plaintext (security vulnerability)
- Simplified ZKP implementation (not cryptographically robust)
- Limited input validation
- Timing attack vulnerability
- No comprehensive test suite

---

## Release Schedule

- **Major releases** (x.0.0): Annual or when breaking changes are needed
- **Minor releases** (x.y.0): Quarterly with new features
- **Patch releases** (x.y.z): As needed for bug fixes and security updates

## Support Policy

- **Current version** (1.x): Full support with security updates
- **Previous major version**: Security updates only for 1 year
- **Legacy versions** (0.x): No longer supported

For security vulnerabilities, see our [Security Policy](SECURITY.md).