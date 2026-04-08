# Gaming

## Rock-Paper-Scissors

The classic example of why commit-reveal exists -- simultaneous moves in a two-player game:

```python
from commit_reveal import CommitRevealScheme


def play_rps():
    cr = CommitRevealScheme()

    # Both players commit simultaneously
    alice_commitment, alice_salt = cr.commit("rock")
    bob_commitment, bob_salt = cr.commit("scissors")

    # Exchange commitments (neither knows the other's move)
    # ...

    # Both reveal
    assert cr.reveal("rock", alice_salt, alice_commitment)
    assert cr.reveal("scissors", bob_salt, bob_commitment)

    # Alice wins!
```

Neither player can change their move after seeing the other's commitment.

## Fair Card Game

Secure card distribution where no player can predict others' cards. Each player contributes a random seed; the combined seed shuffles the deck.

```python
import random
from commit_reveal import CommitRevealScheme


class SecureCardGame:
    def __init__(self, players, deck_size=52):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.players = players
        self.deck_size = deck_size
        self.player_seeds = {}
        self.shuffled_deck = None
        self.hands = {}

    def commit_seed(self, player_id, seed):
        """Each player commits to a random seed."""
        commitment, salt = self.cr.commit(str(seed))
        proof = self.cr.create_zkp_proof(str(seed), salt, commitment)

        self.player_seeds[player_id] = {
            "commitment": commitment,
            "salt": salt,
            "proof": proof,
            "revealed_seed": None,
        }

    def reveal_seed(self, player_id, seed):
        """Reveal seed and verify it matches the commitment."""
        seed_data = self.player_seeds[player_id]
        if self.cr.reveal(str(seed), seed_data["salt"], seed_data["commitment"]):
            seed_data["revealed_seed"] = seed
            return True
        return False

    def shuffle_and_deal(self, cards_per_player=5):
        """Combine all seeds to shuffle the deck deterministically."""
        # Combine all revealed seeds
        all_seeds = sorted(
            str(data["revealed_seed"])
            for data in self.player_seeds.values()
            if data["revealed_seed"] is not None
        )
        combined = "".join(all_seeds)

        # Hash to create final seed
        final_hash = self.cr._hash_func(combined.encode()).digest()
        final_seed = int.from_bytes(final_hash, "big") % (2**32)

        # Shuffle deck deterministically
        random.seed(final_seed)
        deck = list(range(1, self.deck_size + 1))
        random.shuffle(deck)
        self.shuffled_deck = deck

        # Deal
        idx = 0
        for player_id in self.players:
            self.hands[player_id] = deck[idx : idx + cards_per_player]
            idx += cards_per_player

    def verify_fairness(self):
        """Anyone can reproduce the shuffle from the revealed seeds."""
        all_seeds = sorted(
            str(data["revealed_seed"])
            for data in self.player_seeds.values()
            if data["revealed_seed"] is not None
        )
        combined = "".join(all_seeds)
        final_hash = self.cr._hash_func(combined.encode()).digest()
        final_seed = int.from_bytes(final_hash, "big") % (2**32)

        random.seed(final_seed)
        expected_deck = list(range(1, self.deck_size + 1))
        random.shuffle(expected_deck)

        return expected_deck == self.shuffled_deck
```

### Running the Game

```python
players = ["alice", "bob", "charlie", "dave"]
game = SecureCardGame(players)

seeds = {"alice": 12345, "bob": 67890, "charlie": 24680, "dave": 13579}

# Commit phase
for player_id, seed in seeds.items():
    game.commit_seed(player_id, seed)

# Reveal phase
for player_id, seed in seeds.items():
    game.reveal_seed(player_id, seed)

# Shuffle and deal
game.shuffle_and_deal(cards_per_player=5)

for player_id in players:
    print(f"{player_id}: {game.hands[player_id]}")

# Verify fairness
assert game.verify_fairness()
```

### Why This Works

- No single player controls the randomness (all seeds are combined)
- Each player commits before any seeds are revealed
- The shuffle is deterministic and reproducible from the revealed seeds
- ZKP proofs ensure each player actually committed to a real seed
