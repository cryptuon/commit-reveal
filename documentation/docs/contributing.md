# Contributing

## Development Setup

```bash
git clone https://github.com/cryptuon/commit-reveal.git
cd commit-reveal
poetry install --with dev
```

## Running Tests

```bash
# Full test suite with coverage
poetry run pytest

# Skip slow tests
poetry run pytest -m "not slow"

# Security tests only
poetry run pytest -m security

# Performance benchmarks
poetry run pytest -m performance

# Single test file
poetry run pytest tests/test_core.py

# Single test
poetry run pytest tests/test_core.py::TestCommitRevealScheme::test_basic_commit_reveal
```

Coverage must be 90% or higher. The test suite includes:

- **Unit tests** (`test_core.py`) -- core functionality
- **CLI tests** (`test_cli.py`) -- command-line interface
- **Property-based tests** (`test_properties.py`) -- Hypothesis-driven edge case testing
- **Performance tests** (`test_performance.py`) -- benchmarks

## Code Quality

```bash
# Format code
poetry run black commit_reveal/ tests/

# Sort imports
poetry run isort commit_reveal/ tests/

# Lint
poetry run flake8 commit_reveal/ tests/

# Type checking (strict mode)
poetry run mypy commit_reveal/ --strict

# Security scan
poetry run bandit -r commit_reveal/
```

## Pre-commit Hooks

```bash
# Install hooks
poetry run pre-commit install

# Run all hooks manually
poetry run pre-commit run --all-files
```

## Building Documentation

```bash
poetry install --with docs
poetry run mkdocs serve    # Preview at http://localhost:8000
poetry run mkdocs build    # Build static site to site/
```

## Code Style

- **Formatter**: Black (88 char line length)
- **Import sorting**: isort (black profile)
- **Type hints**: Required on all public functions, mypy strict
- **Docstrings**: Google style

## When Working with Cryptographic Code

- Validate all inputs using functions from `validation.py`
- Use timing-safe comparisons (`hmac.compare_digest`) for secret data
- Generate randomness with `secrets`, never `random`
- Test against the security test suite

## Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all checks pass: `poetry run pre-commit run --all-files`
5. Submit a pull request

## Reporting Bugs

Open an issue at [github.com/cryptuon/commit-reveal/issues](https://github.com/cryptuon/commit-reveal/issues).

For security vulnerabilities, see [SECURITY.md](https://github.com/cryptuon/commit-reveal/blob/main/SECURITY.md).
