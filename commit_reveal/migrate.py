#!/usr/bin/env python3
"""
Migration utility for upgrading from insecure CLI storage to secure storage.

This utility helps users migrate from the old format that stored plaintext
values to the new secure format that doesn't store sensitive data.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any, List

from commit_reveal.validation import sanitize_filename


def get_storage_path() -> Path:
    """Get the path to the .commit-reveal directory."""
    home = Path.home()
    storage_path = home / ".commit-reveal"
    return storage_path


def load_old_commitment(name: str) -> Dict[str, Any]:
    """Load a commitment in the old format."""
    storage_path = get_storage_path()
    commitment_file = storage_path / f"{name}.json"

    if not commitment_file.exists():
        raise FileNotFoundError(f"Commitment '{name}' not found")

    with open(commitment_file, 'r') as f:
        data = json.load(f)

    return data


def save_secure_commitment(name: str, data: Dict[str, Any]) -> None:
    """Save a commitment in the new secure format."""
    storage_path = get_storage_path()
    safe_name = sanitize_filename(name)
    commitment_file = storage_path / f"{safe_name}.json"

    # Remove sensitive data and mark as secure version
    secure_data = {
        "name": safe_name,
        "commitment": data["commitment"],
        "salt": data["salt"],
        "zkp": data.get("zkp", False),
        "version": "2.0"
    }

    # Preserve ZKP data but remove value
    if data.get("zkp") and "zkp_data" in data:
        zkp_data = data["zkp_data"]
        secure_data["zkp_data"] = {
            "public_key": zkp_data.get("public_key", []),
            "R_compressed": zkp_data.get("R_compressed", ""),
            "challenge": zkp_data.get("challenge", 0),
            "response": zkp_data.get("response", 0)
        }

    with open(commitment_file, "w") as f:
        json.dump(secure_data, f, indent=2)

    # Set secure file permissions
    commitment_file.chmod(0o600)


def backup_commitment(name: str, data: Dict[str, Any]) -> None:
    """Create a backup of the old commitment format."""
    storage_path = get_storage_path()
    backup_dir = storage_path / "backup"
    backup_dir.mkdir(mode=0o700, exist_ok=True)

    backup_file = backup_dir / f"{name}.json.backup"
    with open(backup_file, "w") as f:
        json.dump(data, f, indent=2)

    backup_file.chmod(0o600)


def find_old_commitments() -> List[str]:
    """Find commitments that need migration."""
    storage_path = get_storage_path()
    if not storage_path.exists():
        return []

    old_commitments = []
    for file in storage_path.iterdir():
        if file.suffix == ".json" and not file.name.endswith(".backup"):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)

                # Check if it's an old format (has value or missing version)
                if "value" in data or data.get("version", "1.0") == "1.0":
                    old_commitments.append(file.stem)
            except (json.JSONDecodeError, IOError):
                continue

    return old_commitments


def migrate_commitment(name: str, create_backup: bool = True) -> bool:
    """
    Migrate a single commitment from old to new format.

    Args:
        name: Name of the commitment to migrate
        create_backup: Whether to create a backup of the old format

    Returns:
        True if migration was successful, False otherwise
    """
    try:
        # Load old data
        old_data = load_old_commitment(name)

        # Create backup if requested
        if create_backup:
            backup_commitment(name, old_data)

        # Save in new format (this removes the plaintext value)
        save_secure_commitment(name, old_data)

        return True

    except Exception as e:
        print(f"Error migrating '{name}': {e}", file=sys.stderr)
        return False


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Migrate commit-reveal storage from insecure to secure format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This utility migrates commitments from the old format (which stored plaintext
values) to the new secure format (which never stores sensitive data).

WARNING: After migration, you will no longer be able to use the old CLI
commands that relied on stored values. You must use the secure CLI instead.

The migration process:
1. Creates backups of all old commitments
2. Removes plaintext values from storage
3. Updates the format version
4. Sets secure file permissions

Examples:
  migrate --list                    # List commitments needing migration
  migrate --all                     # Migrate all commitments
  migrate --name my-commitment      # Migrate specific commitment
  migrate --all --no-backup         # Migrate without creating backups
        """
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List commitments that need migration"
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Migrate all commitments"
    )

    parser.add_argument(
        "--name",
        help="Migrate a specific commitment by name"
    )

    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Don't create backups (not recommended)"
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Force migration without confirmation prompts"
    )

    args = parser.parse_args()

    if not any([args.list, args.all, args.name]):
        parser.print_help()
        return

    try:
        if args.list:
            # List commitments needing migration
            old_commitments = find_old_commitments()
            if old_commitments:
                print(f"Found {len(old_commitments)} commitments needing migration:")
                for name in sorted(old_commitments):
                    print(f"  • {name}")
            else:
                print("No commitments need migration.")
            return

        create_backup = not args.no_backup

        if args.name:
            # Migrate specific commitment
            if args.name not in find_old_commitments():
                print(f"Commitment '{args.name}' doesn't need migration or doesn't exist.")
                return

            if not args.force:
                response = input(f"Migrate commitment '{args.name}'? (y/N): ").strip().lower()
                if response not in ('y', 'yes'):
                    print("Migration cancelled.")
                    return

            if migrate_commitment(args.name, create_backup):
                print(f"✓ Successfully migrated '{args.name}'")
                if create_backup:
                    print(f"  Backup created in backup/{args.name}.json.backup")
            else:
                print(f"✗ Failed to migrate '{args.name}'")
                sys.exit(1)

        elif args.all:
            # Migrate all commitments
            old_commitments = find_old_commitments()
            if not old_commitments:
                print("No commitments need migration.")
                return

            print(f"Found {len(old_commitments)} commitments to migrate:")
            for name in sorted(old_commitments):
                print(f"  • {name}")

            if not args.force:
                if create_backup:
                    print("\nBackups will be created for all commitments.")
                else:
                    print("\nWARNING: No backups will be created!")

                response = input("Proceed with migration? (y/N): ").strip().lower()
                if response not in ('y', 'yes'):
                    print("Migration cancelled.")
                    return

            migrated_count = 0
            for name in old_commitments:
                if migrate_commitment(name, create_backup):
                    migrated_count += 1
                    print(f"✓ Migrated '{name}'")
                else:
                    print(f"✗ Failed to migrate '{name}'")

            print(f"\nMigration complete: {migrated_count}/{len(old_commitments)} commitments migrated")
            if create_backup:
                print("Backups stored in backup/ directory")

    except KeyboardInterrupt:
        print("\nMigration cancelled.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()