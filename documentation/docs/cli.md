# CLI Reference

commit-reveal ships three command-line tools with different security models.

## commit-reveal-secure (recommended)

The production CLI. Never stores plaintext values on disk. All sensitive input is prompted with no echo.

### Commands

#### commit

```bash
commit-reveal-secure commit <name>
commit-reveal-secure --zkp commit <name>
```

Commit to a value. Prompts securely for the value (no echo). Stores only the commitment hash and salt to `~/.commit-reveal/<name>.json`.

With `--zkp`, also generates and stores a Schnorr zero-knowledge proof.

#### reveal

```bash
commit-reveal-secure reveal <name>
```

Reveal and verify a previously committed value. Prompts securely for the value, then checks it against the stored commitment.

#### verify-proof

```bash
commit-reveal-secure --zkp verify-proof <name>
```

Verify a ZKP proof without revealing the value. Loads stored proof data and checks cryptographic validity.

#### list

```bash
commit-reveal-secure list
```

List all stored commitments with version and ZKP status.

```
Commitments:
  * my-password (ZKP) [v2.0]
  * api-key [v2.0]
```

#### delete

```bash
commit-reveal-secure delete <name>
```

Securely delete a commitment. Overwrites the file with random data before unlinking. Requires confirmation.

#### clean

```bash
commit-reveal-secure clean
```

Securely delete all commitments. Lists them first and requires confirmation.

### Global Options

| Option | Description |
|--------|-------------|
| `--zkp` | Enable zero-knowledge proof functionality |
| `--hash-algorithm` | Hash algorithm to use (default: `sha256`) |

### Security Features

- **No plaintext storage** -- values are never written to disk
- **Secure prompting** -- uses `getpass`, input is not echoed
- **File permissions** -- all files created with `0600` (owner-only)
- **Secure deletion** -- files overwritten with random data before removal
- **Audit trail** -- all operations logged

### Storage

Commitments are stored in `~/.commit-reveal/` as JSON files with `0600` permissions. The directory is created with `0700` permissions. Each file contains:

- Commitment hash (hex)
- Salt (hex)
- Hash algorithm
- Format version
- ZKP data (if `--zkp` was used)

---

## commit-reveal-migrate

Migration tool for upgrading from the legacy CLI format to the secure format.

```bash
# List commitments that need migration
commit-reveal-migrate --list

# Migrate all commitments
commit-reveal-migrate --all

# Migrate without backups (not recommended)
commit-reveal-migrate --all --no-backup
```

The migration tool:

- Creates secure backups of old data
- Removes plaintext values from the new format
- Sets proper file permissions
- Verifies integrity of migrated data

---

## commit-reveal (deprecated)

!!! warning "Deprecated"
    The legacy CLI stores values in plaintext. Use `commit-reveal-secure` for production.

```bash
commit-reveal commit <name> <value>
commit-reveal reveal <name> <value>
commit-reveal list
commit-reveal delete <name>
```

The legacy CLI accepts values as command-line arguments (visible in shell history) and stores them in plaintext JSON files. It exists only for backward compatibility.
