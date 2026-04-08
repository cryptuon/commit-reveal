# Blockchain & DeFi

## MEV-Protected Token Swaps

Commit-reveal prevents front-running and MEV (Maximal Extractable Value) attacks on decentralized exchanges by hiding swap details until execution:

```python
from commit_reveal import CommitRevealScheme
import json
import time


class DeFiCommitReveal:
    def __init__(self):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.pending_swaps = {}

    def commit_swap(self, user_id, token_in, amount_in, min_amount_out):
        """Commit to a token swap -- hidden from MEV bots."""
        swap_data = json.dumps({
            "token_in": token_in,
            "amount_in": amount_in,
            "min_amount_out": min_amount_out,
            "nonce": int(time.time()),
        }, sort_keys=True)

        commitment, salt = self.cr.commit(swap_data)

        self.pending_swaps[user_id] = {
            "commitment": commitment,
            "salt": salt,
            "swap_data": swap_data,
        }
        return commitment.hex()

    def execute_swap(self, user_id):
        """Reveal and execute the swap after the commit block."""
        swap_info = self.pending_swaps[user_id]

        if not self.cr.reveal(
            swap_info["swap_data"], swap_info["salt"], swap_info["commitment"]
        ):
            raise ValueError("Invalid swap reveal")

        # Execute the actual swap on-chain
        print(f"Executing swap for {user_id}")
        return True
```

### How It Prevents MEV

1. **Commit block** -- user submits only the commitment hash on-chain. MEV bots see the hash but can't extract swap parameters.
2. **Reveal block** -- user reveals swap details. The swap executes at the current price, not the manipulated price.

## Prediction Markets

Decentralized prediction markets where participants commit to predictions before the outcome is known:

```python
class PredictionMarket:
    def __init__(self, question, options):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.question = question
        self.options = options
        self.predictions = {}
        self.stakes = {}

    def submit_prediction(self, predictor_id, predicted_option, stake):
        """Submit a prediction with stake."""
        if predicted_option not in self.options:
            raise ValueError("Invalid option")

        prediction_data = json.dumps({
            "option": predicted_option,
            "stake": stake,
        }, sort_keys=True)

        commitment, salt = self.cr.commit(prediction_data)
        proof = self.cr.create_zkp_proof(prediction_data, salt, commitment)

        self.predictions[predictor_id] = {
            "commitment": commitment,
            "salt": salt,
            "proof": proof,
            "revealed": None,
        }
        self.stakes[predictor_id] = stake

    def reveal_prediction(self, predictor_id, predicted_option, stake):
        """Reveal a prediction."""
        prediction_data = json.dumps({
            "option": predicted_option,
            "stake": stake,
        }, sort_keys=True)

        pred_info = self.predictions[predictor_id]
        if self.cr.reveal(prediction_data, pred_info["salt"], pred_info["commitment"]):
            pred_info["revealed"] = predicted_option
            return True
        return False

    def resolve(self, actual_outcome):
        """Resolve market and calculate payouts."""
        total_stake = sum(self.stakes.values())
        winners = [
            pid for pid, data in self.predictions.items()
            if data["revealed"] == actual_outcome
        ]
        winning_stake = sum(self.stakes[w] for w in winners)

        payouts = {}
        if winning_stake > 0:
            for winner in winners:
                payouts[winner] = (self.stakes[winner] / winning_stake) * total_stake

        return payouts
```

### Example

```python
market = PredictionMarket(
    "Who will win the election?",
    ["Candidate A", "Candidate B", "Candidate C"],
)

market.submit_prediction("alice", "Candidate A", 100)
market.submit_prediction("bob", "Candidate B", 200)
market.submit_prediction("charlie", "Candidate A", 150)

# After outcome is known
market.reveal_prediction("alice", "Candidate A", 100)
market.reveal_prediction("bob", "Candidate B", 200)
market.reveal_prediction("charlie", "Candidate A", 150)

payouts = market.resolve("Candidate A")
# alice: 180.0, charlie: 270.0 (proportional to stake)
```
