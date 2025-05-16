# This file implements the BFT-style consensus mechanism for our validator nodes.
# Each node verifies the signature sent by the proposer and decides to accept or reject it.

from Crypto.Hash import SHA256
import json
import os

# List of all participating validator nodes
VALIDATORS = ["NodeA", "NodeB", "NodeC", "NodeD"]

# Calculate the minimum number of votes needed to reach agreement
# f is the maximum number of faulty nodes tolerated (for BFT: f = (n-1)//3)
f = (len(VALIDATORS) - 1) // 3
QUORUM = 2 * f + 1  # At least 3 of 4 nodes must agree for consensus

# This function runs the BFT consensus steps: prepare and commit
# proposer: node that signed the message
# record_str: original message content to verify
# proposer_signature: the RSA digital signature created by proposer
# verify_fn: function used to verify signatures
def run_consensus_bft(proposer, record_str, proposer_signature, verify_fn):
    prepare_votes = []           # Track nodes who voted yes in prepare phase
    commit_votes = []            # Copy of prepare_votes (we simulate both phases here)
    verification_details = {}    # Explanation of each node's decision

    # Load public key of the proposer node from their JSON file
    key_path = os.path.join(os.path.dirname(__file__), f"{proposer}.json")
    with open(key_path, encoding='utf-8-sig') as f:
        key_data = json.load(f)
    p = int(key_data["p"])
    q = int(key_data["q"])
    e = int(key_data["e"])
    n = p * q  # RSA modulus

    # Generate hash of the original message
    h_bytes = SHA256.new(record_str.encode()).digest()
    h_int = int.from_bytes(h_bytes, 'big')  # Convert to integer for comparison

    # Each validator node attempts to verify the proposer's signature
    for v in VALIDATORS:
        # The proposer does not validate their own signature
        if v == proposer:
            verification_details[v] = {
                "matched": None,
                "note": "Proposer does not verify its own signature."
            }
            continue

        # Decrypt the signature using the proposer's public key (RSA)
        decrypted = pow(proposer_signature, e, n)
        matched = (decrypted == h_int)  # Check if decrypted value matches the hash

        # Save detailed results for review or auditing
        verification_details[v] = {
            "expected_hash": str(h_int),
            "decrypted_signature": str(decrypted),
            "matched": matched,
            "modulus_n": str(n)
        }

        # If signature is valid, add this validator to prepare votes
        if matched:
            prepare_votes.append(v)

    # For this simplified design, commit phase mirrors prepare phase
    commit_votes = prepare_votes.copy()

    # Check if the number of agreeing nodes meets the quorum threshold
    consensus = len(prepare_votes) >= QUORUM and len(commit_votes) >= QUORUM

    return {
        "prepare_votes": prepare_votes,
        "commit_votes": commit_votes,
        "consensus": consensus,
        "verifications": {k: v.get("matched") for k, v in verification_details.items()},
        "details": verification_details
    }
