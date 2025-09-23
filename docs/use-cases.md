# Use Cases and Applications

This guide explores practical applications of commit-reveal schemes with detailed implementations and real-world scenarios.

## Overview

Commit-reveal schemes are useful whenever you need participants to make simultaneous decisions without influencing each other. The two-phase process ensures fairness and prevents strategic manipulation.

## 1. Auction Systems

### Sealed-Bid Auctions

Perfect for fair auctions where bidders shouldn't see others' bids until everyone has committed.

```python
from commit_reveal import CommitRevealScheme
from datetime import datetime, timedelta
import json

class SecureAuction:
    def __init__(self, item_description, reserve_price=0):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.item = item_description
        self.reserve_price = reserve_price
        self.bids = {}
        self.phase = "setup"  # setup, commit, reveal, ended
        self.commit_deadline = None
        self.reveal_deadline = None

    def start_auction(self, commit_hours=24, reveal_hours=2):
        """Start the auction with specified deadlines."""
        if self.phase != "setup":
            raise ValueError("Auction already started")

        now = datetime.now()
        self.commit_deadline = now + timedelta(hours=commit_hours)
        self.reveal_deadline = self.commit_deadline + timedelta(hours=reveal_hours)
        self.phase = "commit"

        print(f"Auction started for: {self.item}")
        print(f"Commit deadline: {self.commit_deadline}")
        print(f"Reveal deadline: {self.reveal_deadline}")

    def submit_bid(self, bidder_id, bid_amount, max_bid=None):
        """Submit a sealed bid with optional maximum bid for proxy bidding."""
        if self.phase != "commit":
            raise ValueError("Not in commit phase")

        if datetime.now() > self.commit_deadline:
            raise ValueError("Commit deadline has passed")

        if bid_amount < self.reserve_price:
            raise ValueError(f"Bid below reserve price of {self.reserve_price}")

        # Create bid structure
        bid_data = {
            "amount": bid_amount,
            "max_bid": max_bid or bid_amount,
            "timestamp": datetime.now().isoformat()
        }

        # Commit to the bid
        commitment, salt = self.cr.commit(json.dumps(bid_data, sort_keys=True))

        # Create ZKP proof that bidder knows their bid
        public_key, R_compressed, challenge, response = self.cr.create_zkp_proof(
            json.dumps(bid_data, sort_keys=True), salt, commitment
        )

        self.bids[bidder_id] = {
            'commitment': commitment,
            'salt': salt,
            'zkp_proof': (public_key, R_compressed, challenge, response),
            'revealed_bid': None,
            'valid': False
        }

        print(f"Bid received from {bidder_id}")
        return commitment.hex()

    def transition_to_reveal(self):
        """Transition from commit to reveal phase."""
        if self.phase != "commit":
            raise ValueError("Not in commit phase")

        if datetime.now() < self.commit_deadline:
            raise ValueError("Commit phase not yet ended")

        self.phase = "reveal"
        print("Auction now in reveal phase")

    def reveal_bid(self, bidder_id, bid_data):
        """Reveal a previously submitted bid."""
        if self.phase != "reveal":
            raise ValueError("Not in reveal phase")

        if datetime.now() > self.reveal_deadline:
            raise ValueError("Reveal deadline has passed")

        if bidder_id not in self.bids:
            raise ValueError("No bid found for bidder")

        bid_info = self.bids[bidder_id]
        bid_json = json.dumps(bid_data, sort_keys=True)

        # Verify the revealed bid matches the commitment
        if self.cr.reveal(bid_json, bid_info['salt'], bid_info['commitment']):
            bid_info['revealed_bid'] = bid_data
            bid_info['valid'] = True
            print(f"Valid bid revealed from {bidder_id}: ${bid_data['amount']}")
            return True
        else:
            print(f"Invalid bid reveal from {bidder_id}")
            return False

    def end_auction(self):
        """End the auction and determine winner."""
        if self.phase != "reveal":
            raise ValueError("Must be in reveal phase")

        if datetime.now() < self.reveal_deadline:
            raise ValueError("Reveal phase not yet ended")

        self.phase = "ended"

        # Collect valid bids
        valid_bids = {
            bidder: data['revealed_bid']['amount']
            for bidder, data in self.bids.items()
            if data['valid'] and data['revealed_bid']
        }

        if not valid_bids:
            print("No valid bids received")
            return None, 0

        # Determine winner (highest bid)
        winner = max(valid_bids, key=valid_bids.get)
        winning_bid = valid_bids[winner]

        print(f"Auction ended. Winner: {winner} with bid: ${winning_bid}")
        return winner, winning_bid

    def get_auction_summary(self):
        """Get complete auction summary."""
        return {
            'item': self.item,
            'phase': self.phase,
            'total_bids': len(self.bids),
            'valid_reveals': sum(1 for b in self.bids.values() if b['valid']),
            'commit_deadline': self.commit_deadline.isoformat() if self.commit_deadline else None,
            'reveal_deadline': self.reveal_deadline.isoformat() if self.reveal_deadline else None
        }

# Example usage
def run_auction_example():
    # Create auction
    auction = SecureAuction("Vintage 1967 Mustang", reserve_price=15000)
    auction.start_auction(commit_hours=1, reveal_hours=0.5)  # Short for demo

    # Bidders submit sealed bids
    bidders = [
        ("alice", {"amount": 18000, "max_bid": 20000}),
        ("bob", {"amount": 22000, "max_bid": 25000}),
        ("charlie", {"amount": 19500, "max_bid": 19500})
    ]

    for bidder_id, bid_data in bidders:
        auction.submit_bid(bidder_id, bid_data["amount"], bid_data["max_bid"])

    # Transition to reveal phase
    auction.transition_to_reveal()

    # Bidders reveal their bids
    for bidder_id, bid_data in bidders:
        auction.reveal_bid(bidder_id, bid_data)

    # End auction
    winner, winning_bid = auction.end_auction()
    print(f"Final result: {winner} wins with ${winning_bid}")

if __name__ == "__main__":
    run_auction_example()
```

### Dutch Auction with Commitment

For price discovery with commitment to purchase at clearing price:

```python
class DutchCommitmentAuction:
    def __init__(self, item, start_price, min_price, price_decrement):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.item = item
        self.current_price = start_price
        self.min_price = min_price
        self.price_decrement = price_decrement
        self.commitments = {}
        self.clearing_price = None

    def commit_to_buy(self, buyer_id, max_price):
        """Commit to buying at any price up to max_price."""
        commitment_data = {
            "max_price": max_price,
            "timestamp": datetime.now().isoformat()
        }

        commitment, salt = self.cr.commit(json.dumps(commitment_data, sort_keys=True))

        # ZKP proof of valid commitment
        proof = self.cr.create_zkp_proof(
            json.dumps(commitment_data, sort_keys=True), salt, commitment
        )

        self.commitments[buyer_id] = {
            'commitment': commitment,
            'salt': salt,
            'proof': proof,
            'revealed': None
        }

        return commitment.hex()

    def run_price_discovery(self):
        """Run the Dutch auction price discovery."""
        while self.current_price >= self.min_price:
            print(f"Current price: ${self.current_price}")

            # Check if anyone wants to reveal at this price
            revealed_buyers = []
            for buyer_id, data in self.commitments.items():
                if data['revealed'] is None:
                    # Buyer can choose to reveal if price is acceptable
                    # (In practice, this would be automated based on their commitment)
                    pass

            self.current_price -= self.price_decrement

        self.clearing_price = self.current_price + self.price_decrement
        return self.clearing_price
```

## 2. Voting Systems

### Anonymous Voting with Eligibility Proofs

Secure voting where voters prove eligibility without revealing their choice:

```python
from commit_reveal import CommitRevealScheme
import hashlib

class SecureVotingSystem:
    def __init__(self, candidates, voter_registry):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.candidates = set(candidates)
        self.voter_registry = set(voter_registry)  # Eligible voters
        self.votes = {}
        self.phase = "registration"  # registration, voting, reveal, tallied

    def register_voter(self, voter_id, eligibility_proof):
        """Register a voter with eligibility proof."""
        if self.phase != "registration":
            raise ValueError("Registration closed")

        if voter_id not in self.voter_registry:
            raise ValueError("Voter not eligible")

        # Verify eligibility proof (simplified)
        if not self._verify_eligibility(voter_id, eligibility_proof):
            raise ValueError("Invalid eligibility proof")

        print(f"Voter {voter_id} registered successfully")

    def _verify_eligibility(self, voter_id, proof):
        """Verify voter eligibility (simplified implementation)."""
        # In practice, this would verify signatures, certificates, etc.
        return voter_id in self.voter_registry

    def open_voting(self):
        """Open the voting phase."""
        if self.phase != "registration":
            raise ValueError("Must complete registration first")

        self.phase = "voting"
        print("Voting is now open")

    def cast_vote(self, voter_id, candidate):
        """Cast a vote with commitment."""
        if self.phase != "voting":
            raise ValueError("Voting not open")

        if voter_id not in self.voter_registry:
            raise ValueError("Voter not eligible")

        if voter_id in self.votes:
            raise ValueError("Voter has already voted")

        if candidate not in self.candidates:
            raise ValueError("Invalid candidate")

        # Create vote commitment
        vote_data = {
            "candidate": candidate,
            "voter_id": voter_id,
            "timestamp": datetime.now().isoformat()
        }

        commitment, salt = self.cr.commit(json.dumps(vote_data, sort_keys=True))

        # Create ZKP proof of valid vote without revealing choice
        proof = self.cr.create_zkp_proof(
            json.dumps(vote_data, sort_keys=True), salt, commitment
        )

        self.votes[voter_id] = {
            'commitment': commitment,
            'salt': salt,
            'proof': proof,
            'revealed_vote': None
        }

        print(f"Vote cast by {voter_id}")
        return commitment.hex()

    def verify_vote_commitment(self, voter_id):
        """Verify a vote commitment without revealing the vote."""
        if voter_id not in self.votes:
            return False

        vote_data = self.votes[voter_id]
        return self.cr.verify_zkp_proof(
            vote_data['commitment'],
            *vote_data['proof']
        )

    def open_reveal(self):
        """Open the reveal phase."""
        if self.phase != "voting":
            raise ValueError("Must complete voting first")

        self.phase = "reveal"
        print("Reveal phase is now open")

    def reveal_vote(self, voter_id, vote_data):
        """Reveal a vote and verify it matches the commitment."""
        if self.phase != "reveal":
            raise ValueError("Reveal phase not open")

        if voter_id not in self.votes:
            raise ValueError("No vote found for voter")

        vote_info = self.votes[voter_id]
        vote_json = json.dumps(vote_data, sort_keys=True)

        if self.cr.reveal(vote_json, vote_info['salt'], vote_info['commitment']):
            vote_info['revealed_vote'] = vote_data
            print(f"Valid vote revealed from {voter_id}")
            return True
        else:
            print(f"Invalid vote reveal from {voter_id}")
            return False

    def tally_votes(self):
        """Tally all revealed votes."""
        if self.phase != "reveal":
            raise ValueError("Cannot tally before reveal phase")

        self.phase = "tallied"

        # Count valid revealed votes
        results = {candidate: 0 for candidate in self.candidates}
        total_votes = 0

        for voter_id, vote_data in self.votes.items():
            if vote_data['revealed_vote']:
                candidate = vote_data['revealed_vote']['candidate']
                if candidate in self.candidates:
                    results[candidate] += 1
                    total_votes += 1

        print(f"Voting results ({total_votes} total votes):")
        for candidate, count in results.items():
            percentage = (count / total_votes * 100) if total_votes > 0 else 0
            print(f"  {candidate}: {count} votes ({percentage:.1f}%)")

        return results

    def get_election_summary(self):
        """Get complete election summary."""
        return {
            'candidates': list(self.candidates),
            'eligible_voters': len(self.voter_registry),
            'votes_cast': len(self.votes),
            'votes_revealed': sum(1 for v in self.votes.values() if v['revealed_vote']),
            'phase': self.phase
        }

# Example usage
def run_voting_example():
    candidates = ["Alice Johnson", "Bob Smith", "Carol Davis"]
    eligible_voters = ["voter001", "voter002", "voter003", "voter004", "voter005"]

    election = SecureVotingSystem(candidates, eligible_voters)

    # Registration phase
    for voter in eligible_voters:
        election.register_voter(voter, f"proof_{voter}")

    # Voting phase
    election.open_voting()

    votes = [
        ("voter001", "Alice Johnson"),
        ("voter002", "Bob Smith"),
        ("voter003", "Alice Johnson"),
        ("voter004", "Carol Davis"),
        ("voter005", "Alice Johnson")
    ]

    for voter_id, candidate in votes:
        vote_data = {
            "candidate": candidate,
            "voter_id": voter_id,
            "timestamp": datetime.now().isoformat()
        }
        election.cast_vote(voter_id, candidate)

    # Reveal phase
    election.open_reveal()

    for voter_id, candidate in votes:
        vote_data = {
            "candidate": candidate,
            "voter_id": voter_id,
            "timestamp": datetime.now().isoformat()
        }
        election.reveal_vote(voter_id, vote_data)

    # Tally results
    results = election.tally_votes()

    print("\nElection Summary:")
    summary = election.get_election_summary()
    for key, value in summary.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    run_voting_example()
```

## 3. Gaming and Fair Randomness

### Multi-Player Card Game

Secure card distribution where no player can predict others' cards:

```python
import random
from commit_reveal import CommitRevealScheme

class SecureCardGame:
    def __init__(self, players, deck_size=52):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.players = players
        self.deck_size = deck_size
        self.player_seeds = {}
        self.combined_seed = None
        self.shuffled_deck = None
        self.hands = {}
        self.phase = "seed_commit"

    def commit_seed(self, player_id, seed):
        """Each player commits to a random seed."""
        if self.phase != "seed_commit":
            raise ValueError("Not in seed commit phase")

        if player_id not in self.players:
            raise ValueError("Player not in game")

        # Commit to seed
        commitment, salt = self.cr.commit(str(seed))

        # Create ZKP proof of seed knowledge
        proof = self.cr.create_zkp_proof(str(seed), salt, commitment)

        self.player_seeds[player_id] = {
            'commitment': commitment,
            'salt': salt,
            'proof': proof,
            'revealed_seed': None
        }

        print(f"Player {player_id} committed their seed")

        # Check if all players have committed
        if len(self.player_seeds) == len(self.players):
            self.phase = "seed_reveal"
            print("All players committed. Reveal phase starting...")

    def reveal_seed(self, player_id, seed):
        """Reveal the seed and verify it matches the commitment."""
        if self.phase != "seed_reveal":
            raise ValueError("Not in seed reveal phase")

        if player_id not in self.player_seeds:
            raise ValueError("No seed commitment found")

        seed_data = self.player_seeds[player_id]

        if self.cr.reveal(str(seed), seed_data['salt'], seed_data['commitment']):
            seed_data['revealed_seed'] = seed
            print(f"Player {player_id} revealed valid seed")

            # Check if all seeds revealed
            if all(data['revealed_seed'] is not None for data in self.player_seeds.values()):
                self._combine_seeds_and_shuffle()
                self.phase = "game_ready"
                print("All seeds revealed. Game ready to start!")

            return True
        else:
            print(f"Invalid seed reveal from {player_id}")
            return False

    def _combine_seeds_and_shuffle(self):
        """Combine all player seeds to create final randomness."""
        # Combine all revealed seeds
        all_seeds = [str(data['revealed_seed']) for data in self.player_seeds.values()]
        combined_seed_string = ''.join(sorted(all_seeds))  # Sort for determinism

        # Hash to create final seed
        final_seed_bytes = self.cr._hash_func(combined_seed_string.encode()).digest()
        self.combined_seed = int.from_bytes(final_seed_bytes, 'big') % (2**32)

        # Use combined seed to shuffle deck
        random.seed(self.combined_seed)
        deck = list(range(1, self.deck_size + 1))  # Cards 1-52
        random.shuffle(deck)
        self.shuffled_deck = deck

        print(f"Deck shuffled using combined seed: {self.combined_seed}")

    def deal_cards(self, cards_per_player=5):
        """Deal cards to all players."""
        if self.phase != "game_ready":
            raise ValueError("Game not ready")

        if len(self.players) * cards_per_player > self.deck_size:
            raise ValueError("Not enough cards for all players")

        # Deal cards
        card_index = 0
        for player_id in self.players:
            self.hands[player_id] = []
            for _ in range(cards_per_player):
                self.hands[player_id].append(self.shuffled_deck[card_index])
                card_index += 1

        self.phase = "game_active"
        print(f"Dealt {cards_per_player} cards to each player")

    def get_player_hand(self, player_id):
        """Get a player's hand."""
        if player_id not in self.hands:
            return None
        return self.hands[player_id]

    def verify_game_fairness(self):
        """Verify that the game was set up fairly."""
        # Check all seeds were properly committed and revealed
        for player_id, seed_data in self.player_seeds.items():
            if not seed_data['revealed_seed']:
                return False, f"Player {player_id} didn't reveal seed"

            # Verify commitment
            if not self.cr.reveal(
                str(seed_data['revealed_seed']),
                seed_data['salt'],
                seed_data['commitment']
            ):
                return False, f"Player {player_id} seed doesn't match commitment"

        # Verify shuffle is reproducible
        all_seeds = [str(data['revealed_seed']) for data in self.player_seeds.values()]
        combined_seed_string = ''.join(sorted(all_seeds))
        expected_seed_bytes = self.cr._hash_func(combined_seed_string.encode()).digest()
        expected_seed = int.from_bytes(expected_seed_bytes, 'big') % (2**32)

        if expected_seed != self.combined_seed:
            return False, "Combined seed mismatch"

        # Verify shuffle
        random.seed(expected_seed)
        expected_deck = list(range(1, self.deck_size + 1))
        random.shuffle(expected_deck)

        if expected_deck != self.shuffled_deck:
            return False, "Deck shuffle mismatch"

        return True, "Game setup is provably fair"

# Example usage
def run_card_game_example():
    players = ["alice", "bob", "charlie", "dave"]
    game = SecureCardGame(players)

    # Each player generates and commits to a random seed
    player_seeds = {
        "alice": 12345,
        "bob": 67890,
        "charlie": 24680,
        "dave": 13579
    }

    # Commit phase
    for player_id, seed in player_seeds.items():
        game.commit_seed(player_id, seed)

    # Reveal phase
    for player_id, seed in player_seeds.items():
        game.reveal_seed(player_id, seed)

    # Deal cards
    game.deal_cards(cards_per_player=5)

    # Show hands
    for player_id in players:
        hand = game.get_player_hand(player_id)
        print(f"{player_id}'s hand: {hand}")

    # Verify fairness
    is_fair, message = game.verify_game_fairness()
    print(f"Game fairness: {is_fair} - {message}")

if __name__ == "__main__":
    run_card_game_example()
```

## 4. Blockchain and DeFi Applications

### Decentralized Prediction Market

```python
from commit_reveal import CommitRevealScheme
import time

class PredictionMarket:
    def __init__(self, question, options, resolution_time):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.question = question
        self.options = options
        self.resolution_time = resolution_time
        self.predictions = {}
        self.stakes = {}
        self.phase = "prediction"
        self.actual_outcome = None

    def submit_prediction(self, predictor_id, predicted_option, stake_amount):
        """Submit a prediction with stake."""
        if self.phase != "prediction":
            raise ValueError("Prediction phase closed")

        if predicted_option not in self.options:
            raise ValueError("Invalid option")

        prediction_data = {
            "option": predicted_option,
            "stake": stake_amount,
            "timestamp": time.time()
        }

        # Commit to prediction
        commitment, salt = self.cr.commit(json.dumps(prediction_data, sort_keys=True))

        # Create ZKP proof
        proof = self.cr.create_zkp_proof(
            json.dumps(prediction_data, sort_keys=True), salt, commitment
        )

        self.predictions[predictor_id] = {
            'commitment': commitment,
            'salt': salt,
            'proof': proof,
            'revealed_prediction': None
        }

        self.stakes[predictor_id] = stake_amount
        print(f"Prediction submitted by {predictor_id} with stake ${stake_amount}")

    def close_predictions(self):
        """Close prediction phase when resolution time is reached."""
        if time.time() < self.resolution_time:
            raise ValueError("Resolution time not reached")

        self.phase = "reveal"
        print("Prediction phase closed. Reveal phase open.")

    def reveal_prediction(self, predictor_id, prediction_data):
        """Reveal a prediction."""
        if self.phase != "reveal":
            raise ValueError("Not in reveal phase")

        if predictor_id not in self.predictions:
            raise ValueError("No prediction found")

        pred_info = self.predictions[predictor_id]
        pred_json = json.dumps(prediction_data, sort_keys=True)

        if self.cr.reveal(pred_json, pred_info['salt'], pred_info['commitment']):
            pred_info['revealed_prediction'] = prediction_data
            print(f"Valid prediction revealed by {predictor_id}: {prediction_data['option']}")
            return True
        else:
            print(f"Invalid prediction reveal by {predictor_id}")
            return False

    def resolve_market(self, actual_outcome):
        """Resolve the market with the actual outcome."""
        if self.phase != "reveal":
            raise ValueError("Must be in reveal phase")

        if actual_outcome not in self.options:
            raise ValueError("Invalid outcome")

        self.actual_outcome = actual_outcome
        self.phase = "resolved"

        # Calculate payouts
        winners = []
        total_winning_stake = 0
        total_stake = sum(self.stakes.values())

        for predictor_id, pred_data in self.predictions.items():
            if (pred_data['revealed_prediction'] and
                pred_data['revealed_prediction']['option'] == actual_outcome):
                winners.append(predictor_id)
                total_winning_stake += self.stakes[predictor_id]

        # Calculate payouts (proportional to stake)
        payouts = {}
        if total_winning_stake > 0:
            for winner in winners:
                winner_stake = self.stakes[winner]
                payout = (winner_stake / total_winning_stake) * total_stake
                payouts[winner] = payout

        print(f"Market resolved. Outcome: {actual_outcome}")
        print(f"Winners: {winners}")
        print(f"Payouts: {payouts}")

        return payouts

# Example DeFi integration
class DeFiCommitReveal:
    def __init__(self):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.pending_swaps = {}

    def commit_swap(self, user_id, token_in, amount_in, min_amount_out):
        """Commit to a token swap to prevent MEV attacks."""
        swap_data = {
            "token_in": token_in,
            "amount_in": amount_in,
            "min_amount_out": min_amount_out,
            "nonce": time.time()
        }

        commitment, salt = self.cr.commit(json.dumps(swap_data, sort_keys=True))

        # Store for later execution
        self.pending_swaps[user_id] = {
            'commitment': commitment,
            'salt': salt,
            'swap_data': swap_data,
            'block_committed': self._get_current_block()
        }

        return commitment.hex()

    def execute_swap(self, user_id):
        """Execute the swap after reveal phase."""
        if user_id not in self.pending_swaps:
            raise ValueError("No pending swap")

        swap_info = self.pending_swaps[user_id]

        # Verify commitment (in practice, this would be done on-chain)
        swap_json = json.dumps(swap_info['swap_data'], sort_keys=True)
        if not self.cr.reveal(swap_json, swap_info['salt'], swap_info['commitment']):
            raise ValueError("Invalid swap reveal")

        # Execute the actual swap
        print(f"Executing swap for {user_id}: {swap_info['swap_data']}")
        return True

    def _get_current_block(self):
        """Get current block number (simplified)."""
        return int(time.time())  # Simplified for demo
```

## 5. Supply Chain and Logistics

### Sealed Bid Procurement

```python
class SupplyChainProcurement:
    def __init__(self, tender_description, requirements):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.tender = tender_description
        self.requirements = requirements
        self.bids = {}
        self.evaluation_criteria = {}

    def submit_bid(self, supplier_id, bid_details):
        """Submit a bid with pricing and specifications."""
        bid_data = {
            "price": bid_details["price"],
            "delivery_time": bid_details["delivery_time"],
            "specifications": bid_details["specifications"],
            "timestamp": time.time()
        }

        # Commit to bid
        commitment, salt = self.cr.commit(json.dumps(bid_data, sort_keys=True))

        # ZKP proof of valid bid
        proof = self.cr.create_zkp_proof(
            json.dumps(bid_data, sort_keys=True), salt, commitment
        )

        self.bids[supplier_id] = {
            'commitment': commitment,
            'salt': salt,
            'proof': proof,
            'revealed_bid': None
        }

        print(f"Bid submitted by {supplier_id}")
        return commitment.hex()

    def evaluate_bids(self):
        """Evaluate all revealed bids according to criteria."""
        scores = {}

        for supplier_id, bid_data in self.bids.items():
            if not bid_data['revealed_bid']:
                continue

            bid = bid_data['revealed_bid']

            # Multi-criteria evaluation
            price_score = self._score_price(bid['price'])
            delivery_score = self._score_delivery(bid['delivery_time'])
            spec_score = self._score_specifications(bid['specifications'])

            total_score = (price_score * 0.5 +
                          delivery_score * 0.3 +
                          spec_score * 0.2)

            scores[supplier_id] = {
                'total_score': total_score,
                'price_score': price_score,
                'delivery_score': delivery_score,
                'spec_score': spec_score,
                'bid_details': bid
            }

        return scores

    def _score_price(self, price):
        """Score based on price (lower is better)."""
        # Implementation depends on specific requirements
        return max(0, 100 - (price / 1000))  # Simplified

    def _score_delivery(self, delivery_time):
        """Score based on delivery time (faster is better)."""
        return max(0, 100 - delivery_time)  # Simplified

    def _score_specifications(self, specifications):
        """Score based on how well specs match requirements."""
        # Implementation would check specifications against requirements
        return 85  # Simplified
```

These use cases demonstrate the versatility of commit-reveal schemes in creating fair, transparent, and secure protocols across various domains. The key benefits include:

1. **Fairness**: No participant can gain advantage by seeing others' choices first
2. **Transparency**: All commitments are public and verifiable
3. **Security**: Zero-knowledge proofs allow verification without revelation
4. **Auditability**: Complete audit trail of all operations
5. **Flexibility**: Adaptable to many different application domains

Each implementation can be customized further based on specific requirements, regulatory needs, and technical constraints of the target environment.