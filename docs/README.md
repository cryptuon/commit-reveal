# Documentation

Welcome to the commit-reveal library documentation. This directory contains comprehensive guides and references for using the library in production applications.

## Documentation Index

### Getting Started
- **[Getting Started Guide](getting-started.md)** - Quick start tutorial and basic usage examples
- **[Installation Guide](getting-started.md#installation)** - Installation instructions and requirements

### Core Documentation
- **[API Reference](api-reference.md)** - Complete API documentation for all classes and methods
- **[Use Cases](use-cases.md)** - Detailed real-world application examples and implementations
- **[Security Guide](security-guide.md)** - Security considerations and best practices for production

### Additional Resources
- **[Advanced Features](advanced-features.md)** - Zero-knowledge proofs, audit trails, and advanced configurations
- **[CLI Documentation](cli-guide.md)** - Command-line interface usage and migration guide
- **[FAQ](faq.md)** - Frequently asked questions and common issues
- **[Troubleshooting](troubleshooting.md)** - Solutions to common problems

## Quick Navigation

### New Users
1. Start with [Getting Started Guide](getting-started.md)
2. Review [Use Cases](use-cases.md) to understand applications
3. Check [Security Guide](security-guide.md) for production deployment

### Developers
1. Review [API Reference](api-reference.md) for complete method documentation
2. Explore [Use Cases](use-cases.md) for implementation patterns
3. Study [Advanced Features](advanced-features.md) for ZKP and audit capabilities

### Security Engineers
1. Read [Security Guide](security-guide.md) thoroughly
2. Review [Advanced Features](advanced-features.md) for audit trail capabilities
3. Check [API Reference](api-reference.md) for validation and error handling

## Key Features Covered

### Core Functionality
- **Commit-Reveal Schemes**: Cryptographically secure two-phase protocols
- **Multiple Data Types**: Support for strings, integers, and binary data
- **Hash Algorithm Selection**: SHA-256, SHA-512, SHA-3, BLAKE2 support
- **Input Validation**: Comprehensive security-focused validation

### Advanced Features
- **Zero-Knowledge Proofs**: Schnorr signatures on secp256k1 curve
- **Audit Trails**: Tamper-evident logging with integrity verification
- **Secure CLI**: Production-ready command-line tools
- **Migration Tools**: Safe upgrade from legacy formats

### Security Features
- **Timing Attack Prevention**: Constant-time cryptographic operations
- **Input Sanitization**: Protection against injection attacks
- **Secure Random Generation**: Cryptographically secure randomness
- **No Plaintext Storage**: Secure CLI never stores sensitive values

## Documentation Standards

All documentation follows these principles:

- **Practical Examples**: Every concept includes working code examples
- **Security First**: Security considerations are highlighted throughout
- **Production Ready**: All examples are suitable for production use
- **Developer Friendly**: Clear explanations with practical context

## Contributing to Documentation

To improve the documentation:

1. Fork the repository
2. Update relevant documentation files
3. Test all code examples
4. Submit a pull request with clear description

## Need Help?

- **General Questions**: Check the [FAQ](faq.md)
- **Technical Issues**: See [Troubleshooting](troubleshooting.md)
- **Security Concerns**: Review [Security Guide](security-guide.md)
- **Bug Reports**: Open an issue on GitHub
- **Feature Requests**: Discuss on GitHub Discussions

## Version Information

This documentation covers commit-reveal library version 1.0.0 and later. For legacy versions (< 1.0), see the migration guide in [CLI Documentation](cli-guide.md).

---

**Next Steps**: Start with the [Getting Started Guide](getting-started.md) for a hands-on introduction to the library.