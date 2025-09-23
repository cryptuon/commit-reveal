#!/usr/bin/env python3
"""
Secure CLI tool for the commit-reveal library.

This version eliminates plaintext value storage and implements proper
security practices for production use.
"""

import argparse
import json
import os
import sys
import getpass
from pathlib import Path
from typing import Optional, Dict, Any

from commit_reveal import CommitRevealScheme, ValidationError, SecurityError
from commit_reveal.validation import sanitize_filename


def get_storage_path() -> Path:
    """Get the path to the .commit-reveal directory."""
    home = Path.home()
    storage_path = home / ".commit-reveal"
    return storage_path


def ensure_storage_directory() -> Path:
    """Ensure the .commit-reveal directory exists with proper permissions."""
    storage_path = get_storage_path()
    storage_path.mkdir(mode=0o700, exist_ok=True)  # Owner read/write/execute only
    return storage_path


def save_secure_commitment(name: str, commitment: bytes, salt: bytes,
                          zkp_data: Optional[Dict[str, Any]] = None) -> None:
    """
    Save a commitment securely without storing the plaintext value.

    Args:
        name: Name for the commitment
        commitment: The commitment bytes
        salt: The salt bytes
        zkp_data: Optional ZKP proof data
    """
    storage_path = ensure_storage_directory()
    safe_name = sanitize_filename(name)
    commitment_file = storage_path / f"{safe_name}.json"

    data = {
        "name": safe_name,
        "commitment": commitment.hex(),
        "salt": salt.hex(),
        "zkp": zkp_data is not None,
        "version": "2.0"  # Mark as secure version
    }

    # Save ZKP data if provided (but never the original value)
    if zkp_data is not None:
        # Convert tuple coordinates to list for JSON serialization
        public_key = zkp_data["public_key"]
        data["zkp_data"] = {
            "public_key": [int(public_key[0]), int(public_key[1])],
            "R_compressed": zkp_data["R_compressed"].hex(),
            "challenge": int(zkp_data["challenge"]),
            "response": int(zkp_data["response"])
        }

    # Write with secure permissions
    with open(commitment_file, "w") as f:
        json.dump(data, f, indent=2)

    # Set secure file permissions (owner read/write only)
    commitment_file.chmod(0o600)


def load_commitment(name: str) -> Optional[Dict[str, Any]]:
    """Load a commitment from the storage directory."""
    storage_path = get_storage_path()
    safe_name = sanitize_filename(name)
    commitment_file = storage_path / f"{safe_name}.json"

    if not commitment_file.exists():
        return None

    # Check file permissions for security
    stat = commitment_file.stat()
    if stat.st_mode & 0o077:  # Check if group or others have any permissions
        print(f"Warning: Commitment file has insecure permissions", file=sys.stderr)

    with open(commitment_file, "r") as f:
        data = json.load(f)

    return data


def list_commitments() -> list:
    """List all commitments in the storage directory."""
    storage_path = get_storage_path()
    if not storage_path.exists():
        return []

    commitments = []
    for file in storage_path.iterdir():
        if file.suffix == ".json":
            commitments.append(file.stem)

    return commitments


def delete_commitment(name: str) -> bool:
    """Delete a commitment from the storage directory."""
    storage_path = get_storage_path()
    safe_name = sanitize_filename(name)
    commitment_file = storage_path / f"{safe_name}.json"

    if commitment_file.exists():
        # Secure deletion - overwrite file before unlinking
        try:
            # Write random data to overwrite the file
            import secrets
            with open(commitment_file, "wb") as f:
                f.write(secrets.token_bytes(1024))
            commitment_file.unlink()
            return True
        except OSError:
            # Fallback to regular deletion
            commitment_file.unlink()
            return True
    return False


def prompt_for_value(prompt: str) -> str:
    """Securely prompt for a value without echoing to terminal."""
    try:
        # Use getpass to avoid echoing sensitive values
        value = getpass.getpass(f"{prompt}: ")
        if not value.strip():
            raise ValueError("Value cannot be empty")
        return value
    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        sys.exit(1)


def confirm_action(prompt: str) -> bool:
    """Prompt for confirmation of potentially destructive actions."""
    try:
        response = input(f"{prompt} (y/N): ").strip().lower()
        return response in ('y', 'yes')
    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Secure Commit-Reveal CLI tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  commit-reveal commit my-secret
  commit-reveal reveal my-secret
  commit-reveal list
  commit-reveal delete my-secret
  commit-reveal --zkp commit my-secret
  commit-reveal --zkp verify-proof my-secret

Security Notes:
  - Values are never stored in plaintext
  - Files are created with secure permissions (0600)
  - Sensitive values are prompted securely without echo
  - ZKP proofs allow verification without revealing values
        """
    )

    parser.add_argument(
        "--zkp",
        action="store_true",
        help="Enable zero-knowledge proof functionality"
    )

    parser.add_argument(
        "--hash-algorithm",
        default="sha256",
        help="Hash algorithm to use (default: sha256)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Commit command
    commit_parser = subparsers.add_parser("commit", help="Commit to a value")
    commit_parser.add_argument("name", help="Name for the commitment")

    # Reveal command
    reveal_parser = subparsers.add_parser("reveal", help="Reveal a committed value")
    reveal_parser.add_argument("name", help="Name of the commitment")

    # Verify command (alias for reveal)
    verify_parser = subparsers.add_parser("verify", help="Verify a commitment")
    verify_parser.add_argument("name", help="Name of the commitment")

    # ZKP Verify Proof command
    verify_proof_parser = subparsers.add_parser("verify-proof", help="Verify a zero-knowledge proof")
    verify_proof_parser.add_argument("name", help="Name of the commitment")

    # List command
    subparsers.add_parser("list", help="List all commitments")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a commitment")
    delete_parser.add_argument("name", help="Name of the commitment to delete")

    # Clean command
    subparsers.add_parser("clean", help="Clean all commitments (with confirmation)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        # Initialize the commit-reveal scheme
        cr = CommitRevealScheme(hash_algorithm=args.hash_algorithm, use_zkp=args.zkp)

        if args.command == "commit":
            # Commit to a value
            value = prompt_for_value(f"Enter value to commit for '{args.name}'")

            try:
                commitment, salt = cr.commit(value)

                # Create ZKP proof if enabled
                zkp_data = None
                if args.zkp:
                    public_key, R_compressed, challenge, response = cr.create_zkp_proof(
                        value, salt, commitment
                    )
                    zkp_data = {
                        "public_key": public_key,
                        "R_compressed": R_compressed,
                        "challenge": challenge,
                        "response": response
                    }

                save_secure_commitment(args.name, commitment, salt, zkp_data)
                print(f"✓ Commitment '{args.name}' created successfully")
                print(f"Commitment: {commitment.hex()}")
                if args.zkp:
                    print("✓ Zero-knowledge proof generated")

            except (ValidationError, SecurityError) as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.command == "reveal":
            # Reveal a value
            data = load_commitment(args.name)
            if not data:
                print(f"Error: No commitment found with name '{args.name}'", file=sys.stderr)
                sys.exit(1)

            value = prompt_for_value(f"Enter value to reveal for '{args.name}'")

            try:
                is_valid = cr.reveal(value, bytes.fromhex(data["salt"]), bytes.fromhex(data["commitment"]))
                if is_valid:
                    print(f"✓ Reveal successful! The value matches the commitment.")

                    # If ZKP data exists, also verify consistency
                    if data.get("zkp") and "zkp_data" in data:
                        zkp_data = data["zkp_data"]
                        public_key = tuple(zkp_data["public_key"])
                        is_consistent = cr.verify_commitment_consistency(
                            value, bytes.fromhex(data["salt"]),
                            bytes.fromhex(data["commitment"]), public_key
                        )
                        if is_consistent:
                            print("✓ ZKP consistency verified")
                        else:
                            print("⚠ Warning: ZKP consistency check failed")
                else:
                    print(f"✗ Reveal failed! The value does not match the commitment.")
                    sys.exit(1)

            except (ValidationError, SecurityError) as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.command == "verify":
            # Alias for reveal
            args.command = "reveal"
            main()

        elif args.command == "verify-proof":
            # Verify a ZKP proof without revealing the value
            if not args.zkp:
                print("Error: ZKP functionality must be enabled with --zkp flag", file=sys.stderr)
                sys.exit(1)

            data = load_commitment(args.name)
            if not data:
                print(f"Error: No commitment found with name '{args.name}'", file=sys.stderr)
                sys.exit(1)

            if not data.get("zkp") or "zkp_data" not in data:
                print(f"Error: No ZKP proof found for commitment '{args.name}'", file=sys.stderr)
                sys.exit(1)

            try:
                commitment = bytes.fromhex(data["commitment"])
                zkp_data = data["zkp_data"]
                public_key = tuple(zkp_data["public_key"])
                R_compressed = bytes.fromhex(zkp_data["R_compressed"])
                challenge = zkp_data["challenge"]
                response = zkp_data["response"]

                is_valid = cr.verify_zkp_proof(commitment, public_key, R_compressed, challenge, response)
                if is_valid:
                    print(f"✓ ZKP proof verification successful for commitment '{args.name}'")
                    print("The prover knows the secret without revealing it.")
                else:
                    print(f"✗ ZKP proof verification failed for commitment '{args.name}'")
                    sys.exit(1)

            except (ValidationError, SecurityError) as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.command == "list":
            # List all commitments
            commitments = list_commitments()
            if commitments:
                print("Commitments:")
                for name in sorted(commitments):
                    data = load_commitment(name)
                    if data:
                        zkp_status = " (ZKP)" if data.get("zkp") else ""
                        version = data.get("version", "1.0")
                        print(f"  • {name}{zkp_status} [v{version}]")
                    else:
                        print(f"  • {name} (unreadable)")
            else:
                print("No commitments found.")

        elif args.command == "delete":
            # Delete a commitment
            if not confirm_action(f"Delete commitment '{args.name}'?"):
                print("Operation cancelled.")
                return

            if delete_commitment(args.name):
                print(f"✓ Commitment '{args.name}' deleted successfully.")
            else:
                print(f"Error: No commitment found with name '{args.name}'", file=sys.stderr)
                sys.exit(1)

        elif args.command == "clean":
            # Clean all commitments
            commitments = list_commitments()
            if not commitments:
                print("No commitments to clean.")
                return

            print(f"Found {len(commitments)} commitments to delete:")
            for name in sorted(commitments):
                print(f"  • {name}")

            if not confirm_action("Delete ALL commitments? This cannot be undone!"):
                print("Operation cancelled.")
                return

            deleted_count = 0
            for name in commitments:
                if delete_commitment(name):
                    deleted_count += 1

            print(f"✓ Deleted {deleted_count} commitments.")

    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()