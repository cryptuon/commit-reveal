# Commit-Reveal Library

A production-ready Python library implementing cryptographically secure commit-reveal schemes with zero-knowledge proofs.

## Overview

The commit-reveal scheme is a cryptographic protocol that allows one party to commit to a value while keeping it hidden, with the ability to reveal it later. This library provides a robust implementation with advanced features including zero-knowledge proofs for proving knowledge without revelation.

## Features

### Core Cryptographic Features
- **Secure Commitment Scheme**: SHA-256/SHA-512/SHA-3 based commitments with cryptographically secure salts
- **Zero-Knowledge Proofs**: Schnorr signatures on secp256k1 for proving knowledge without revealing values
- **Multiple Data Types**: Support for strings, integers, and bytes
- **Configurable Hash Algorithms**: SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2

### Security Features
- **Input Validation**: Comprehensive sanitization and validation of all inputs
- **Timing Attack Prevention**: Constant-time comparisons for all cryptographic operations
- **Secure Random Generation**: Uses Python's `secrets` module for cryptographically secure randomness
- **No Plaintext Storage**: Secure CLI never stores sensitive values on disk
- **Audit Trail**: Tamper-evident logging of all cryptographic operations

### Developer Experience
- **Type Safety**: Complete type hints with mypy strict mode compliance
- **Zero Dependencies**: Uses only Python standard library for core functionality
- **Comprehensive Testing**: 90%+ test coverage with property-based testing
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Python 3.8+**: Supports Python 3.8 through 3.12

## Installation

### Using pip

```bash
pip install commit-reveal
```

### Using Poetry (Recommended for Development)

```bash
# Install Poetry if you haven't already
curl -sSL https://install.python-poetry.org | python3 -

# Clone and install the project
git clone https://github.com/dipankar/commit-reveal.git
cd commit-reveal
poetry install
```

### Development Installation

For development with all testing and linting tools:

```bash
# Using Poetry (recommended)
poetry install --with dev

# Using pip
pip install commit-reveal[dev]
```

## Quick Start

### Basic Commit-Reveal

```python
from commit_reveal import CommitRevealScheme

# Initialize the scheme
cr = CommitRevealScheme()

# Commit to a value
commitment, salt = cr.commit("my secret value")
print(f"Commitment: {commitment.hex()}")

# Later, reveal the value
is_valid = cr.reveal("my secret value", salt, commitment)
print(f"Reveal successful: {is_valid}")  # True
```

### Zero-Knowledge Proofs

```python
from commit_reveal import CommitRevealScheme

# Initialize with ZKP support
cr = CommitRevealScheme(use_zkp=True)

# Commit to a value
commitment, salt = cr.commit("secret data")

# Create a zero-knowledge proof
public_key, R_compressed, challenge, response = cr.create_zkp_proof(
    "secret data", salt, commitment
)

# Verify the proof without knowing the original value
is_valid = cr.verify_zkp_proof(
    commitment, public_key, R_compressed, challenge, response
)
print(f"ZKP verification: {is_valid}")  # True

# Later, when value is revealed, verify consistency
consistency = cr.verify_commitment_consistency(
    "secret data", salt, commitment, public_key
)
print(f"Consistency verified: {consistency}")  # True
```

## Use Cases

### 1. Secure Auctions and Bidding

Sealed-bid auctions where bidders commit to their bids without revealing them until the reveal phase.

```python
from commit_reveal import CommitRevealScheme
from datetime import datetime, timedelta

class SecureAuction:
    def __init__(self):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.bids = {}
        self.commit_deadline = None
        self.reveal_deadline = None

    def start_auction(self, commit_hours=24, reveal_hours=2):
        now = datetime.now()
        self.commit_deadline = now + timedelta(hours=commit_hours)
        self.reveal_deadline = self.commit_deadline + timedelta(hours=reveal_hours)
        print(f"Auction started. Commit by {self.commit_deadline}")

    def submit_bid(self, bidder_id, bid_amount):
        if datetime.now() > self.commit_deadline:
            raise ValueError("Commit phase has ended")

        commitment, salt = self.cr.commit(bid_amount)

        # Create ZKP to prove bidder knows their bid without revealing it
        public_key, R_compressed, challenge, response = self.cr.create_zkp_proof(
            bid_amount, salt, commitment
        )

        self.bids[bidder_id] = {
            'commitment': commitment,
            'salt': salt,
            'zkp_proof': (public_key, R_compressed, challenge, response),
            'revealed_bid': None
        }

        return commitment.hex()  # Return commitment as receipt

    def reveal_bid(self, bidder_id, bid_amount):
        if datetime.now() > self.reveal_deadline:
            raise ValueError("Reveal phase has ended")

        if bidder_id not in self.bids:
            raise ValueError("No bid found for bidder")

        bid_data = self.bids[bidder_id]

        # Verify the revealed bid matches the commitment
        if self.cr.reveal(bid_amount, bid_data['salt'], bid_data['commitment']):
            bid_data['revealed_bid'] = bid_amount
            return True
        return False

    def get_winner(self):
        if datetime.now() < self.reveal_deadline:
            raise ValueError("Reveal phase not complete")

        valid_bids = {
            bidder: data['revealed_bid']
            for bidder, data in self.bids.items()
            if data['revealed_bid'] is not None
        }

        if not valid_bids:
            return None

        winner = max(valid_bids, key=valid_bids.get)
        return winner, valid_bids[winner]

# Usage
auction = SecureAuction()
auction.start_auction()

# Bidders submit commitments
auction.submit_bid("alice", 100)
auction.submit_bid("bob", 150)
auction.submit_bid("charlie", 120)

# Later, in reveal phase
auction.reveal_bid("alice", 100)
auction.reveal_bid("bob", 150)
auction.reveal_bid("charlie", 120)

winner, winning_bid = auction.get_winner()
print(f"Winner: {winner} with bid: {winning_bid}")
```

### 2. Secure Voting Systems

Anonymous voting where voters commit to their choices, with zero-knowledge proofs for eligibility verification.

```python
from commit_reveal import CommitRevealScheme
import hashlib

class SecureVoting:
    def __init__(self, candidates):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.candidates = candidates
        self.eligible_voters = set()
        self.votes = {}
        self.voting_open = False
        self.reveal_open = False

    def register_voter(self, voter_id):
        """Register an eligible voter"""
        self.eligible_voters.add(voter_id)

    def open_voting(self):
        self.voting_open = True
        print("Voting is now open")

    def cast_vote(self, voter_id, candidate):
        if not self.voting_open:
            raise ValueError("Voting is not open")

        if voter_id not in self.eligible_voters:
            raise ValueError("Voter not eligible")

        if voter_id in self.votes:
            raise ValueError("Voter has already voted")

        if candidate not in self.candidates:
            raise ValueError("Invalid candidate")

        # Commit to the vote
        commitment, salt = self.cr.commit(candidate)

        # Create ZKP proof of vote validity without revealing choice
        public_key, R_compressed, challenge, response = self.cr.create_zkp_proof(
            candidate, salt, commitment
        )

        self.votes[voter_id] = {
            'commitment': commitment,
            'salt': salt,
            'zkp_proof': (public_key, R_compressed, challenge, response),
            'revealed_vote': None
        }

        print(f"Vote cast by {voter_id}")
        return commitment.hex()

    def open_reveal(self):
        self.voting_open = False
        self.reveal_open = True
        print("Reveal phase is now open")

    def reveal_vote(self, voter_id, candidate):
        if not self.reveal_open:
            raise ValueError("Reveal phase is not open")

        if voter_id not in self.votes:
            raise ValueError("No vote found for voter")

        vote_data = self.votes[voter_id]

        # Verify the revealed vote matches the commitment
        if self.cr.reveal(candidate, vote_data['salt'], vote_data['commitment']):
            vote_data['revealed_vote'] = candidate
            return True
        return False

    def tally_votes(self):
        if not self.reveal_open:
            raise ValueError("Cannot tally before reveal phase")

        results = {candidate: 0 for candidate in self.candidates}

        for voter_id, vote_data in self.votes.items():
            if vote_data['revealed_vote']:
                results[vote_data['revealed_vote']] += 1

        return results

# Usage
voting = SecureVoting(["Alice", "Bob", "Charlie"])

# Register voters
for voter in ["voter1", "voter2", "voter3", "voter4"]:
    voting.register_voter(voter)

# Voting phase
voting.open_voting()
voting.cast_vote("voter1", "Alice")
voting.cast_vote("voter2", "Bob")
voting.cast_vote("voter3", "Alice")
voting.cast_vote("voter4", "Charlie")

# Reveal phase
voting.open_reveal()
voting.reveal_vote("voter1", "Alice")
voting.reveal_vote("voter2", "Bob")
voting.reveal_vote("voter3", "Alice")
voting.reveal_vote("voter4", "Charlie")

# Tally results
results = voting.tally_votes()
print("Voting results:", results)
```

### 3. Secure Multi-Party Computations

Coordinate secret sharing and secure computations across multiple parties.

```python
from commit_reveal import CommitRevealScheme
import statistics

class SecureMultiPartyComputation:
    def __init__(self, parties):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.parties = set(parties)
        self.commitments = {}
        self.revealed_values = {}

    def commit_value(self, party_id, value):
        if party_id not in self.parties:
            raise ValueError("Unknown party")

        commitment, salt = self.cr.commit(value)

        # Create ZKP proof
        public_key, R_compressed, challenge, response = self.cr.create_zkp_proof(
            value, salt, commitment
        )

        self.commitments[party_id] = {
            'commitment': commitment,
            'salt': salt,
            'zkp_proof': (public_key, R_compressed, challenge, response)
        }

        print(f"Party {party_id} committed to their value")

    def all_committed(self):
        return len(self.commitments) == len(self.parties)

    def reveal_value(self, party_id, value):
        if party_id not in self.commitments:
            raise ValueError("No commitment found for party")

        commitment_data = self.commitments[party_id]

        if self.cr.reveal(value, commitment_data['salt'], commitment_data['commitment']):
            self.revealed_values[party_id] = value
            print(f"Party {party_id} revealed their value")
            return True
        return False

    def compute_statistics(self):
        if len(self.revealed_values) != len(self.parties):
            raise ValueError("Not all parties have revealed their values")

        values = list(self.revealed_values.values())
        return {
            'sum': sum(values),
            'average': statistics.mean(values),
            'median': statistics.median(values),
            'min': min(values),
            'max': max(values)
        }

# Usage - Secure salary comparison
mpc = SecureMultiPartyComputation(["alice", "bob", "charlie", "dave"])

# Commitment phase - everyone commits to their salary
mpc.commit_value("alice", 75000)
mpc.commit_value("bob", 82000)
mpc.commit_value("charlie", 69000)
mpc.commit_value("dave", 91000)

# Reveal phase - everyone reveals their salary
mpc.reveal_value("alice", 75000)
mpc.reveal_value("bob", 82000)
mpc.reveal_value("charlie", 69000)
mpc.reveal_value("dave", 91000)

# Compute group statistics
stats = mpc.compute_statistics()
print("Group salary statistics:", stats)
```

### 4. Blockchain and Smart Contract Integration

Integration with blockchain systems for decentralized applications.

```python
from commit_reveal import CommitRevealScheme
import time

class BlockchainCommitReveal:
    def __init__(self):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.blockchain = []  # Simplified blockchain
        self.pending_commitments = {}

    def create_block(self, transactions):
        block = {
            'index': len(self.blockchain),
            'timestamp': time.time(),
            'transactions': transactions,
            'previous_hash': self.get_last_block_hash() if self.blockchain else '0',
        }
        block['hash'] = self.calculate_block_hash(block)
        self.blockchain.append(block)
        return block

    def calculate_block_hash(self, block):
        block_string = str(block['index']) + str(block['timestamp']) + str(block['transactions']) + block['previous_hash']
        return CommitRevealScheme().commit(block_string)[0].hex()[:32]

    def get_last_block_hash(self):
        return self.blockchain[-1]['hash'] if self.blockchain else '0'

    def commit_transaction(self, user_id, transaction_data):
        commitment, salt = self.cr.commit(str(transaction_data))

        # Create ZKP proof
        public_key, R_compressed, challenge, response = self.cr.create_zkp_proof(
            str(transaction_data), salt, commitment
        )

        commit_record = {
            'user_id': user_id,
            'commitment': commitment.hex(),
            'salt': salt.hex(),
            'zkp_proof': {
                'public_key': public_key,
                'R_compressed': R_compressed.hex(),
                'challenge': challenge,
                'response': response
            },
            'timestamp': time.time()
        }

        self.pending_commitments[user_id] = {
            'record': commit_record,
            'salt_bytes': salt,
            'commitment_bytes': commitment,
            'transaction_data': None
        }

        # Add commit to blockchain
        block = self.create_block([{'type': 'commit', 'data': commit_record}])
        print(f"Commitment added to block {block['index']}")

        return commitment.hex()

    def reveal_transaction(self, user_id, transaction_data):
        if user_id not in self.pending_commitments:
            raise ValueError("No pending commitment for user")

        pending = self.pending_commitments[user_id]

        # Verify revelation
        is_valid = self.cr.reveal(
            str(transaction_data),
            pending['salt_bytes'],
            pending['commitment_bytes']
        )

        if is_valid:
            reveal_record = {
                'user_id': user_id,
                'transaction_data': transaction_data,
                'commitment_ref': pending['record']['commitment'],
                'timestamp': time.time()
            }

            # Add reveal to blockchain
            block = self.create_block([{'type': 'reveal', 'data': reveal_record}])
            print(f"Reveal added to block {block['index']}")

            # Mark as completed
            pending['transaction_data'] = transaction_data
            return True

        return False

    def verify_blockchain_integrity(self):
        for i, block in enumerate(self.blockchain):
            if i == 0:
                continue

            if block['previous_hash'] != self.blockchain[i-1]['hash']:
                return False

        return True

# Usage
blockchain_cr = BlockchainCommitReveal()

# Users commit to transactions
blockchain_cr.commit_transaction("alice", {"to": "bob", "amount": 10})
blockchain_cr.commit_transaction("bob", {"to": "charlie", "amount": 5})

# Later, users reveal their transactions
blockchain_cr.reveal_transaction("alice", {"to": "bob", "amount": 10})
blockchain_cr.reveal_transaction("bob", {"to": "charlie", "amount": 5})

# Verify blockchain integrity
print("Blockchain valid:", blockchain_cr.verify_blockchain_integrity())
```

### 5. Secure Gaming and Randomness

Fair random number generation and turn-based gaming with hidden moves.

```python
from commit_reveal import CommitRevealScheme
import random
import hashlib

class SecureRockPaperScissors:
    def __init__(self):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.players = {}
        self.game_state = "waiting"  # waiting, committed, revealed, finished

    def join_game(self, player_id):
        if len(self.players) >= 2:
            raise ValueError("Game is full")

        self.players[player_id] = {
            'move': None,
            'commitment': None,
            'salt': None,
            'zkp_proof': None,
            'revealed': False
        }

        print(f"Player {player_id} joined the game")

    def commit_move(self, player_id, move):
        if player_id not in self.players:
            raise ValueError("Player not in game")

        if move not in ["rock", "paper", "scissors"]:
            raise ValueError("Invalid move")

        if self.game_state != "waiting" and self.game_state != "committed":
            raise ValueError("Cannot commit at this stage")

        commitment, salt = self.cr.commit(move)

        # Create ZKP proof
        public_key, R_compressed, challenge, response = self.cr.create_zkp_proof(
            move, salt, commitment
        )

        self.players[player_id].update({
            'commitment': commitment,
            'salt': salt,
            'zkp_proof': (public_key, R_compressed, challenge, response)
        })

        # Check if both players have committed
        if all(p['commitment'] is not None for p in self.players.values()):
            self.game_state = "committed"
            print("Both players have committed. Reveal phase starting...")

        print(f"Player {player_id} committed their move")

    def reveal_move(self, player_id, move):
        if self.game_state != "committed":
            raise ValueError("Cannot reveal before all commitments")

        if player_id not in self.players:
            raise ValueError("Player not in game")

        player = self.players[player_id]

        # Verify the revealed move
        if self.cr.reveal(move, player['salt'], player['commitment']):
            player['move'] = move
            player['revealed'] = True
            print(f"Player {player_id} revealed: {move}")

            # Check if both players have revealed
            if all(p['revealed'] for p in self.players.values()):
                self.game_state = "revealed"
                self.determine_winner()

            return True

        return False

    def determine_winner(self):
        moves = {pid: player['move'] for pid, player in self.players.items()}
        player_ids = list(moves.keys())

        move1, move2 = moves[player_ids[0]], moves[player_ids[1]]

        if move1 == move2:
            print(f"Tie! Both played {move1}")
            return "tie"

        winning_moves = {
            ("rock", "scissors"): player_ids[0],
            ("scissors", "paper"): player_ids[0],
            ("paper", "rock"): player_ids[0],
            ("scissors", "rock"): player_ids[1],
            ("paper", "scissors"): player_ids[1],
            ("rock", "paper"): player_ids[1]
        }

        winner = winning_moves.get((move1, move2))
        if winner:
            print(f"Winner: {winner}")
            return winner

        self.game_state = "finished"

# Usage
game = SecureRockPaperScissors()

# Players join
game.join_game("alice")
game.join_game("bob")

# Commitment phase
game.commit_move("alice", "rock")
game.commit_move("bob", "scissors")

# Reveal phase
game.reveal_move("alice", "rock")
game.reveal_move("bob", "scissors")
```

## Command Line Interface

### Secure CLI (Recommended)

The secure CLI never stores plaintext values and uses proper security practices.

```bash
# Commit to a value (prompts securely)
commit-reveal-secure commit my-secret

# Reveal a value (prompts securely)
commit-reveal-secure reveal my-secret

# List all commitments
commit-reveal-secure list

# Delete a commitment
commit-reveal-secure delete my-secret

# Zero-knowledge proof operations
commit-reveal-secure --zkp commit my-secret
commit-reveal-secure --zkp verify-proof my-secret

# Clean all commitments
commit-reveal-secure clean
```

### Migration from Legacy CLI

If you have data from the legacy CLI (versions < 1.0), migrate to the secure format:

```bash
# List commitments needing migration
commit-reveal-migrate --list

# Migrate all commitments (creates backups)
commit-reveal-migrate --all

# Migrate specific commitment
commit-reveal-migrate --name my-commitment
```

## API Reference

### CommitRevealScheme

The main class for commit-reveal operations.

```python
class CommitRevealScheme:
    def __init__(
        self,
        hash_algorithm: str = 'sha256',
        use_zkp: bool = False,
        enable_audit: bool = True
    ):
        """
        Initialize the commit-reveal scheme.

        Args:
            hash_algorithm: Hash algorithm to use ('sha256', 'sha512', 'sha3_256', etc.)
            use_zkp: Enable zero-knowledge proof functionality
            enable_audit: Enable audit trail logging
        """
```

#### Core Methods

```python
def commit(self, value: Union[str, int, bytes], salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Commit to a value.

    Args:
        value: The value to commit to
        salt: Optional salt (auto-generated if None)

    Returns:
        (commitment, salt) tuple
    """

def reveal(self, value: Union[str, int, bytes], salt: bytes, commitment: bytes) -> bool:
    """
    Reveal and verify a commitment.

    Args:
        value: The original value
        salt: The salt used in commitment
        commitment: The commitment to verify

    Returns:
        True if valid, False otherwise
    """
```

#### Zero-Knowledge Proof Methods

```python
def create_zkp_proof(
    self,
    value: Union[str, int, bytes],
    salt: bytes,
    commitment: bytes
) -> Tuple[Tuple[int, int], bytes, int, int]:
    """
    Create a zero-knowledge proof.

    Returns:
        (public_key, R_compressed, challenge, response)
    """

def verify_zkp_proof(
    self,
    commitment: bytes,
    public_key: Tuple[int, int],
    R_compressed: bytes,
    challenge: int,
    response: int
) -> bool:
    """
    Verify a zero-knowledge proof.

    Returns:
        True if proof is valid, False otherwise
    """
```

## Security Considerations

### Hash Algorithm Selection

- **Recommended**: SHA-256 (default), SHA-384, SHA-512
- **Supported**: SHA-3 variants, BLAKE2
- **Forbidden**: MD5, SHA-1 (rejected by validation)

### Zero-Knowledge Proof Security

- Uses secp256k1 elliptic curve (same as Bitcoin)
- Implements proper Schnorr signature scheme
- Non-interactive proofs via Fiat-Shamir heuristic
- Each proof should only be used once

### Best Practices

1. **Use the secure CLI** for production applications
2. **Enable audit trails** for compliance requirements
3. **Validate all inputs** using the built-in validation
4. **Handle exceptions** properly (`ValidationError`, `SecurityError`)
5. **Use ZKP proofs** when you need to prove knowledge without revelation

## Error Handling

```python
from commit_reveal import CommitRevealScheme, ValidationError, SecurityError

try:
    cr = CommitRevealScheme(hash_algorithm='sha256')
    commitment, salt = cr.commit("my value")
    result = cr.reveal("my value", salt, commitment)
except ValidationError as e:
    print(f"Validation error: {e}")
except SecurityError as e:
    print(f"Security error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Performance

- **Commit operations**: < 1ms average
- **Reveal operations**: < 1ms average
- **ZKP creation**: < 10ms average
- **ZKP verification**: < 10ms average
- **Memory usage**: Minimal footprint
- **Thread safety**: Full concurrent support

## Testing

Run the comprehensive test suite:

```bash
# Using Poetry (recommended)
poetry install --with dev
poetry run pytest

# Run with coverage
poetry run pytest --cov=commit_reveal

# Run only fast tests
poetry run pytest -m "not slow"

# Run security tests
poetry run pytest -m security

# Run performance benchmarks
poetry run pytest -m performance

# Using pip (alternative)
pip install -e ".[dev]"
pytest
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Install development dependencies: `poetry install --with dev`
4. Run tests: `poetry run pytest`
5. Run security checks: `poetry run bandit -r commit_reveal/`
6. Run linting: `poetry run flake8 commit_reveal/`
7. Format code: `poetry run black commit_reveal/`
8. Run type checking: `poetry run mypy commit_reveal/`
9. Install pre-commit hooks: `poetry run pre-commit install`
10. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Security

For security issues, see our [Security Policy](SECURITY.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and migration guides.