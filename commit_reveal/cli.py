#!/usr/bin/env python3
"""
CLI tool for the commit-reveal library.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from commit_reveal import CommitRevealScheme


def get_storage_path():
    """Get the path to the .commit-reveal directory."""
    home = Path.home()
    storage_path = home / ".commit-reveal"
    return storage_path


def ensure_storage_directory():
    """Ensure the .commit-reveal directory exists."""
    storage_path = get_storage_path()
    storage_path.mkdir(exist_ok=True)
    return storage_path


def save_commitment(name, commitment, salt, value=None, zkp_data=None):
    """Save a commitment to the storage directory."""
    storage_path = ensure_storage_directory()
    commitment_file = storage_path / f"{name}.json"
    
    data = {
        "name": name,
        "commitment": commitment.hex(),
        "salt": salt.hex(),
        "zkp": zkp_data is not None
    }
    
    # Only save the value if it's provided (for testing purposes)
    if value is not None:
        data["value"] = value
    
    # Save ZKP data if provided
    if zkp_data is not None:
        data["zkp_data"] = {
            "nonce": zkp_data["nonce"].hex(),
            "challenge": int(zkp_data["challenge"]),  # Convert to int if it's not already
            "response": int(zkp_data["response"])     # Convert to int if it's not already
        }
    
    with open(commitment_file, "w") as f:
        json.dump(data, f, indent=2)


def load_commitment(name):
    """Load a commitment from the storage directory."""
    storage_path = get_storage_path()
    commitment_file = storage_path / f"{name}.json"
    
    if not commitment_file.exists():
        return None
    
    with open(commitment_file, "r") as f:
        data = json.load(f)
    
    return data


def list_commitments():
    """List all commitments in the storage directory."""
    storage_path = get_storage_path()
    if not storage_path.exists():
        return []
    
    commitments = []
    for file in storage_path.iterdir():
        if file.suffix == ".json":
            commitments.append(file.stem)
    
    return commitments


def delete_commitment(name):
    """Delete a commitment from the storage directory."""
    storage_path = get_storage_path()
    commitment_file = storage_path / f"{name}.json"
    
    if commitment_file.exists():
        commitment_file.unlink()
        return True
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Commit-Reveal CLI tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  commit-reveal commit my-secret "This is my secret"
  commit-reveal reveal my-secret "This is my secret"
  commit-reveal list
  commit-reveal delete my-secret
  commit-reveal --zkp commit my-secret "This is my secret"
  commit-reveal --zkp prove my-secret
  commit-reveal --zkp verify-proof my-secret
        """
    )
    
    parser.add_argument(
        "--zkp",
        action="store_true",
        help="Enable zero-knowledge proof functionality"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Commit command
    commit_parser = subparsers.add_parser("commit", help="Commit to a value")
    commit_parser.add_argument("name", help="Name for the commitment")
    commit_parser.add_argument("value", help="Value to commit to")
    
    # Reveal command
    reveal_parser = subparsers.add_parser("reveal", help="Reveal a committed value")
    reveal_parser.add_argument("name", help="Name of the commitment")
    reveal_parser.add_argument("value", help="Value to reveal")
    
    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a commitment without revealing")
    verify_parser.add_argument("name", help="Name of the commitment")
    verify_parser.add_argument("value", help="Value to verify")
    
    # ZKP Prove command
    prove_parser = subparsers.add_parser("prove", help="Create a zero-knowledge proof for a commitment")
    prove_parser.add_argument("name", help="Name of the commitment")
    
    # ZKP Verify Proof command
    verify_proof_parser = subparsers.add_parser("verify-proof", help="Verify a zero-knowledge proof")
    verify_proof_parser.add_argument("name", help="Name of the commitment")
    
    # List command
    subparsers.add_parser("list", help="List all commitments")
    
    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a commitment")
    delete_parser.add_argument("name", help="Name of the commitment to delete")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize the commit-reveal scheme
    cr = CommitRevealScheme(use_zkp=args.zkp)
    
    if args.command == "commit":
        # Commit to a value
        commitment, salt = cr.commit(args.value)
        
        # Create ZKP data if ZKP is enabled
        zkp_data = None
        if args.zkp:
            try:
                nonce, challenge, response = cr.create_zkp_proof(args.value, salt, commitment)
                zkp_data = {
                    "nonce": nonce,
                    "challenge": challenge,
                    "response": response
                }
            except ValueError as e:
                print(f"Error creating ZKP proof: {e}", file=sys.stderr)
                sys.exit(1)
        
        save_commitment(args.name, commitment, salt, args.value, zkp_data)
        print(f"Committed to '{args.value}' with name '{args.name}'")
        print(f"Commitment: {commitment.hex()}")
        print(f"Salt: {salt.hex()}")
        if args.zkp:
            print("ZKP proof created and stored.")
        
    elif args.command == "reveal":
        # Reveal a value
        data = load_commitment(args.name)
        if not data:
            print(f"Error: No commitment found with name '{args.name}'", file=sys.stderr)
            sys.exit(1)
        
        is_valid = cr.reveal(args.value, bytes.fromhex(data["salt"]), bytes.fromhex(data["commitment"]))
        if is_valid:
            print(f"Reveal successful! The value '{args.value}' matches the commitment.")
        else:
            print(f"Reveal failed! The value '{args.value}' does not match the commitment.")
            
    elif args.command == "verify":
        # Verify a value without revealing
        data = load_commitment(args.name)
        if not data:
            print(f"Error: No commitment found with name '{args.name}'", file=sys.stderr)
            sys.exit(1)
        
        is_valid = cr.verify(args.value, bytes.fromhex(data["salt"]), bytes.fromhex(data["commitment"]))
        if is_valid:
            print(f"Verification successful! The value '{args.value}' matches the commitment.")
        else:
            print(f"Verification failed! The value '{args.value}' does not match the commitment.")
            
    elif args.command == "prove":
        # Create a ZKP proof
        if not args.zkp:
            print("Error: ZKP functionality must be enabled with --zkp flag", file=sys.stderr)
            sys.exit(1)
            
        data = load_commitment(args.name)
        if not data:
            print(f"Error: No commitment found with name '{args.name}'", file=sys.stderr)
            sys.exit(1)
        
        # Check if we have the value stored (for testing purposes)
        if "value" not in data:
            print(f"Error: Value not stored for commitment '{args.name}'. Cannot create proof.", file=sys.stderr)
            sys.exit(1)
        
        commitment = bytes.fromhex(data["commitment"])
        salt = bytes.fromhex(data["salt"])
        value = data["value"]
        
        try:
            nonce, challenge, response = cr.create_zkp_proof(value, salt, commitment)
            # Update the stored data with ZKP proof
            zkp_data = {
                "nonce": nonce.hex(),  # Convert to hex string
                "challenge": int(challenge),  # Ensure it's an int
                "response": int(response)     # Ensure it's an int
            }
            data["zkp_data"] = zkp_data
            data["zkp"] = True
            
            # Save updated data
            storage_path = ensure_storage_directory()
            commitment_file = storage_path / f"{args.name}.json"
            with open(commitment_file, "w") as f:
                json.dump(data, f, indent=2)
            
            print(f"ZKP proof created for commitment '{args.name}'")
            print(f"Challenge: {challenge}")
            print("Proof stored locally.")
        except ValueError as e:
            print(f"Error creating ZKP proof: {e}", file=sys.stderr)
            sys.exit(1)
            
    elif args.command == "verify-proof":
        # Verify a ZKP proof
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
        
        commitment = bytes.fromhex(data["commitment"])
        zkp_data = data["zkp_data"]
        nonce = bytes.fromhex(zkp_data["nonce"])
        challenge = zkp_data["challenge"]
        response = zkp_data["response"]
        
        try:
            is_valid = cr.verify_zkp_proof(commitment, nonce, challenge, response)
            if is_valid:
                print(f"ZKP proof verification successful for commitment '{args.name}'")
            else:
                print(f"ZKP proof verification failed for commitment '{args.name}'")
        except ValueError as e:
            print(f"Error verifying ZKP proof: {e}", file=sys.stderr)
            sys.exit(1)
            
    elif args.command == "list":
        # List all commitments
        commitments = list_commitments()
        if commitments:
            print("Commitments:")
            for name in commitments:
                print(f"  - {name}")
        else:
            print("No commitments found.")
            
    elif args.command == "delete":
        # Delete a commitment
        if delete_commitment(args.name):
            print(f"Commitment '{args.name}' deleted successfully.")
        else:
            print(f"Error: No commitment found with name '{args.name}'", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()