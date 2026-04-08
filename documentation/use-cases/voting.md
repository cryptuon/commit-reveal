# Voting

## Anonymous Voting with Eligibility Proofs

Commit-reveal enables secure voting where voters prove eligibility without revealing their choice until the tally.

```python
from commit_reveal import CommitRevealScheme
import json


class SecureVotingSystem:
    def __init__(self, candidates, eligible_voters):
        self.cr = CommitRevealScheme(use_zkp=True)
        self.candidates = set(candidates)
        self.eligible_voters = set(eligible_voters)
        self.votes = {}
        self.phase = "voting"

    def cast_vote(self, voter_id, candidate):
        """Cast a vote with commitment and ZKP proof."""
        if voter_id not in self.eligible_voters:
            raise ValueError("Voter not eligible")
        if voter_id in self.votes:
            raise ValueError("Voter has already voted")
        if candidate not in self.candidates:
            raise ValueError("Invalid candidate")

        vote_data = json.dumps(
            {"candidate": candidate, "voter_id": voter_id}, sort_keys=True
        )
        commitment, salt = self.cr.commit(vote_data)

        # ZKP proof of valid vote without revealing choice
        proof = self.cr.create_zkp_proof(vote_data, salt, commitment)

        self.votes[voter_id] = {
            "commitment": commitment,
            "salt": salt,
            "proof": proof,
            "revealed_vote": None,
        }
        return commitment.hex()

    def verify_vote_commitment(self, voter_id):
        """Verify a vote commitment without revealing the vote."""
        if voter_id not in self.votes:
            return False
        vote_data = self.votes[voter_id]
        return self.cr.verify_zkp_proof(vote_data["commitment"], *vote_data["proof"])

    def reveal_vote(self, voter_id, candidate):
        """Reveal a vote and verify it matches the commitment."""
        vote_data = json.dumps(
            {"candidate": candidate, "voter_id": voter_id}, sort_keys=True
        )
        vote_info = self.votes[voter_id]

        if self.cr.reveal(vote_data, vote_info["salt"], vote_info["commitment"]):
            vote_info["revealed_vote"] = candidate
            return True
        return False

    def tally_votes(self):
        """Count all revealed votes."""
        results = {c: 0 for c in self.candidates}
        for vote_data in self.votes.values():
            if vote_data["revealed_vote"] in self.candidates:
                results[vote_data["revealed_vote"]] += 1
        return results
```

### Running an Election

```python
candidates = ["Alice Johnson", "Bob Smith", "Carol Davis"]
voters = ["voter001", "voter002", "voter003", "voter004", "voter005"]

election = SecureVotingSystem(candidates, voters)

# Voting phase -- each voter commits
votes = {
    "voter001": "Alice Johnson",
    "voter002": "Bob Smith",
    "voter003": "Alice Johnson",
    "voter004": "Carol Davis",
    "voter005": "Alice Johnson",
}

for voter_id, candidate in votes.items():
    election.cast_vote(voter_id, candidate)

# Verify all commitments are valid (without seeing votes)
for voter_id in votes:
    assert election.verify_vote_commitment(voter_id)

# Reveal phase
for voter_id, candidate in votes.items():
    election.reveal_vote(voter_id, candidate)

# Tally
results = election.tally_votes()
# {'Alice Johnson': 3, 'Bob Smith': 1, 'Carol Davis': 1}
```

### Security Properties

- **Ballot secrecy** -- votes are hidden until the reveal phase
- **Eligibility** -- only registered voters can cast votes
- **Uniqueness** -- each voter can only vote once
- **Verifiability** -- ZKP proofs allow anyone to verify vote validity without seeing the choice
- **Integrity** -- commitments are cryptographically binding, preventing vote changes
