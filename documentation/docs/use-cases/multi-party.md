# Multi-Party Computation

## Secure Multi-Party Protocols

When multiple parties need to contribute inputs without any single party controlling the outcome:

```python
from commit_reveal import CommitRevealScheme
import json


class SecureMultiPartyComputation:
    def __init__(self, participants):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.participants = set(participants)
        self.commitments = {}

    def submit_input(self, participant_id, value):
        """Each participant commits to their input."""
        if participant_id not in self.participants:
            raise ValueError("Not a participant")

        commitment, salt = self.cr.commit(str(value))
        proof = self.cr.create_zkp_proof(str(value), salt, commitment)

        self.commitments[participant_id] = {
            "commitment": commitment,
            "salt": salt,
            "proof": proof,
            "revealed": None,
        }
        return commitment.hex()

    def reveal_input(self, participant_id, value):
        """Reveal an input and verify it matches the commitment."""
        info = self.commitments[participant_id]
        if self.cr.reveal(str(value), info["salt"], info["commitment"]):
            info["revealed"] = value
            return True
        return False

    def compute(self, aggregation_fn):
        """Compute the result from all revealed inputs."""
        values = [
            data["revealed"]
            for data in self.commitments.values()
            if data["revealed"] is not None
        ]
        return aggregation_fn(values)
```

### Example: Fair Average Salary Calculation

```python
mpc = SecureMultiPartyComputation(["alice", "bob", "charlie"])

# Each commits their salary (no one sees others' values)
mpc.submit_input("alice", 95000)
mpc.submit_input("bob", 110000)
mpc.submit_input("charlie", 87000)

# All reveal simultaneously
mpc.reveal_input("alice", 95000)
mpc.reveal_input("bob", 110000)
mpc.reveal_input("charlie", 87000)

# Compute average
average = mpc.compute(lambda values: sum(values) / len(values))
print(f"Average salary: ${average:,.0f}")  # $97,333
```

## Supply Chain Procurement

Sealed-bid procurement where suppliers compete fairly:

```python
class SealedBidProcurement:
    def __init__(self, tender_description):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.tender = tender_description
        self.bids = {}

    def submit_bid(self, supplier_id, price, delivery_days):
        """Submit a sealed bid."""
        bid_data = json.dumps({
            "price": price,
            "delivery_days": delivery_days,
        }, sort_keys=True)

        commitment, salt = self.cr.commit(bid_data)
        proof = self.cr.create_zkp_proof(bid_data, salt, commitment)

        self.bids[supplier_id] = {
            "commitment": commitment,
            "salt": salt,
            "proof": proof,
            "revealed": None,
        }
        return commitment.hex()

    def reveal_bid(self, supplier_id, price, delivery_days):
        """Reveal a bid and verify it."""
        bid_data = json.dumps({
            "price": price,
            "delivery_days": delivery_days,
        }, sort_keys=True)

        bid_info = self.bids[supplier_id]
        if self.cr.reveal(bid_data, bid_info["salt"], bid_info["commitment"]):
            bid_info["revealed"] = {"price": price, "delivery_days": delivery_days}
            return True
        return False

    def evaluate(self, price_weight=0.6, delivery_weight=0.4):
        """Score bids with weighted criteria."""
        revealed = {
            sid: data["revealed"]
            for sid, data in self.bids.items()
            if data["revealed"]
        }
        if not revealed:
            return {}

        min_price = min(b["price"] for b in revealed.values())
        min_days = min(b["delivery_days"] for b in revealed.values())

        scores = {}
        for sid, bid in revealed.items():
            price_score = min_price / bid["price"] * 100
            delivery_score = min_days / bid["delivery_days"] * 100
            scores[sid] = price_score * price_weight + delivery_score * delivery_weight

        return dict(sorted(scores.items(), key=lambda x: -x[1]))
```

### Example

```python
procurement = SealedBidProcurement("Server hardware - 100 units")

procurement.submit_bid("supplier_a", price=250000, delivery_days=14)
procurement.submit_bid("supplier_b", price=230000, delivery_days=21)
procurement.submit_bid("supplier_c", price=275000, delivery_days=10)

# Reveal phase
procurement.reveal_bid("supplier_a", 250000, 14)
procurement.reveal_bid("supplier_b", 230000, 21)
procurement.reveal_bid("supplier_c", 275000, 10)

scores = procurement.evaluate()
# Ranked by weighted score (60% price, 40% delivery)
```
