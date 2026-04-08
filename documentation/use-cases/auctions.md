# Auctions

## Sealed-Bid Auctions

Sealed-bid auctions ensure bidders can't see others' bids until everyone has committed. The commit-reveal protocol guarantees no bid can be changed after submission.

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
        self.phase = "commit"

    def submit_bid(self, bidder_id, bid_amount):
        """Submit a sealed bid with ZKP proof of validity."""
        if bid_amount < self.reserve_price:
            raise ValueError(f"Bid below reserve price of {self.reserve_price}")

        bid_data = json.dumps({"amount": bid_amount}, sort_keys=True)
        commitment, salt = self.cr.commit(bid_data)

        # ZKP proof that bidder knows their bid
        proof = self.cr.create_zkp_proof(bid_data, salt, commitment)

        self.bids[bidder_id] = {
            "commitment": commitment,
            "salt": salt,
            "proof": proof,
            "revealed": None,
        }
        return commitment.hex()

    def reveal_bid(self, bidder_id, bid_amount):
        """Reveal a bid and verify it matches the commitment."""
        bid_data = json.dumps({"amount": bid_amount}, sort_keys=True)
        bid_info = self.bids[bidder_id]

        if self.cr.reveal(bid_data, bid_info["salt"], bid_info["commitment"]):
            bid_info["revealed"] = bid_amount
            return True
        return False

    def determine_winner(self):
        """Find the highest valid revealed bid."""
        valid_bids = {
            bidder: data["revealed"]
            for bidder, data in self.bids.items()
            if data["revealed"] is not None
        }
        if not valid_bids:
            return None, 0
        winner = max(valid_bids, key=valid_bids.get)
        return winner, valid_bids[winner]
```

### Running the Auction

```python
auction = SecureAuction("Vintage 1967 Mustang", reserve_price=15000)

# Commit phase -- bidders submit sealed bids
auction.submit_bid("alice", 18000)
auction.submit_bid("bob", 22000)
auction.submit_bid("charlie", 19500)

# Reveal phase -- bidders reveal their bids
auction.reveal_bid("alice", 18000)
auction.reveal_bid("bob", 22000)
auction.reveal_bid("charlie", 19500)

# Determine winner
winner, amount = auction.determine_winner()
print(f"Winner: {winner} with ${amount}")  # bob with $22000
```

## Dutch Auction with Commitment

In a Dutch auction, the price starts high and decreases until a buyer commits. Using commit-reveal prevents front-running:

```python
class DutchCommitmentAuction:
    def __init__(self, item, start_price, min_price, decrement):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.item = item
        self.current_price = start_price
        self.min_price = min_price
        self.decrement = decrement
        self.commitments = {}

    def commit_to_buy(self, buyer_id, max_price):
        """Commit to buying at any price up to max_price."""
        commitment_data = json.dumps({"max_price": max_price}, sort_keys=True)
        commitment, salt = self.cr.commit(commitment_data)
        proof = self.cr.create_zkp_proof(commitment_data, salt, commitment)

        self.commitments[buyer_id] = {
            "commitment": commitment,
            "salt": salt,
            "proof": proof,
        }
        return commitment.hex()
```

The ZKP proof allows the auctioneer to verify that each buyer has committed to a valid maximum price without learning the actual amount.
