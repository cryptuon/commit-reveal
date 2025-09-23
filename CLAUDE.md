# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a production-ready Python library implementing cryptographically secure commit-reveal schemes with zero-knowledge proofs. The library uses Poetry for dependency management and provides both a core library and multiple CLI interfaces.

## Essential Commands

### Development Setup
```bash
# Install all dependencies (including dev tools)
poetry install --with dev

# Run all tests with coverage (90% minimum required)
poetry run pytest

# Run specific test categories
poetry run pytest -m "not slow"           # Skip slow tests
poetry run pytest -m security             # Security-focused tests
poetry run pytest -m performance          # Performance benchmarks
poetry run pytest tests/test_core.py      # Single test file
poetry run pytest tests/test_core.py::TestCommitRevealScheme::test_basic_commit_reveal  # Single test
```

### Code Quality
```bash
# Format code
poetry run black commit_reveal/ tests/

# Check types
poetry run mypy commit_reveal/ --strict

# Run security analysis
poetry run bandit -r commit_reveal/

# Run all pre-commit hooks
poetry run pre-commit run --all-files
```

### Build and Package
```bash
# Check Poetry configuration
poetry check

# Build package
poetry build

# Install package locally in development mode
poetry install
```

## Architecture Overview

### Core Components

**commit_reveal/core.py** - Main `CommitRevealScheme` class that orchestrates all functionality:
- Integrates validation, ZKP, and audit systems
- Supports multiple hash algorithms (SHA-256, SHA-512, SHA-3, BLAKE2)
- Optional zero-knowledge proof system via `use_zkp=True`
- Audit trail logging via `enable_audit=True`

**commit_reveal/zkp.py** - Complete elliptic curve cryptography implementation:
- Custom secp256k1 curve implementation (same as Bitcoin)
- Schnorr signature-based zero-knowledge proofs
- Fiat-Shamir heuristic for non-interactive proofs
- Point compression for efficient storage/transmission

**commit_reveal/validation.py** - Comprehensive input validation and security:
- Custom exceptions: `ValidationError`, `SecurityError`
- Input sanitization and type checking
- Security-focused validation (blocks insecure algorithms like MD5/SHA-1)
- Timing-safe comparisons for cryptographic operations

**commit_reveal/audit.py** - Tamper-evident audit trail system:
- Cryptographic integrity verification
- Session tracking and operation logging
- Immutable audit records with hash chains

### CLI Architecture

Three separate CLI interfaces with different security models:

1. **commit_reveal/cli.py** - Legacy CLI (deprecated, stores plaintext)
2. **commit_reveal/secure_cli.py** - Secure CLI (never stores plaintext values)
3. **commit_reveal/migrate.py** - Migration tool (upgrades from legacy format)

Console scripts defined in `pyproject.toml`:
- `commit-reveal` → `commit_reveal.cli:main`
- `commit-reveal-secure` → `commit_reveal.secure_cli:main`
- `commit-reveal-migrate` → `commit_reveal.migrate:main`

### Test Architecture

**tests/conftest.py** - Central test configuration:
- Fixtures for different scheme configurations (`scheme`, `zkp_scheme`, `sha512_scheme`)
- Comprehensive test data fixtures (`test_values`) covering strings, integers, bytes
- Custom pytest markers: `slow`, `security`, `performance`, `integration`, `unit`
- Automatic marker assignment based on test names and paths

**Test Categories:**
- **Unit tests** (`test_core.py`) - Core functionality
- **CLI tests** (`test_cli.py`) - Command-line interface testing
- **Property-based tests** (`test_properties.py`) - Uses Hypothesis for robust validation
- **Performance tests** (`test_performance.py`) - Benchmarking and performance validation

### Configuration

**pyproject.toml** - Single source of truth for all project configuration:
- Poetry dependencies (main + dev groups)
- Tool configurations (Black, MyPy, pytest, Bandit, etc.)
- Coverage requirements (90% minimum)
- Console script definitions

## Key Design Principles

### Security-First Architecture
- All cryptographic operations use secure randomness (`secrets` module)
- Timing-safe comparisons prevent timing attacks
- Input validation prevents injection attacks
- No plaintext storage in secure CLI mode
- Comprehensive audit trails for compliance

### Modular Zero-Knowledge Proof System
- ZKP system is optional and can be enabled per-instance
- Uses proper elliptic curve cryptography (secp256k1)
- Implements Schnorr signatures for non-interactive proofs
- Point compression reduces storage overhead

### Type Safety and Validation
- Complete type hints throughout codebase
- MyPy strict mode compliance required
- Custom exception hierarchy for clear error handling
- Comprehensive input validation at all entry points

### Testing Strategy
- Property-based testing with Hypothesis for edge cases
- 90% code coverage requirement enforced
- Performance benchmarking for cryptographic operations
- Security-focused tests for timing attacks and validation

## Development Notes

### When Working with Cryptographic Code
- Always validate inputs using functions from `validation.py`
- Use timing-safe comparisons (`hmac.compare_digest`) for secret data
- Generate randomness with `secrets` module, never `random`
- Test against the security test suite when making changes

### When Adding New CLI Commands
- Follow the secure CLI pattern in `secure_cli.py`
- Never store plaintext values on disk
- Use `getpass` for sensitive input prompting
- Implement proper error handling and user confirmations

### When Modifying ZKP System
- Understand that the ZKP implementation is a complete elliptic curve system
- Changes to `zkp.py` require careful validation of mathematical correctness
- Test with both unit tests and property-based tests
- Verify compatibility with existing proof formats

### Version Management
- Update `__version__` in `commit_reveal/__init__.py`
- Follow semantic versioning
- Update `CHANGELOG.md` with breaking changes
- Security fixes should be clearly documented