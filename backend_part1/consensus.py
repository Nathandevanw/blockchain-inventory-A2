VALIDATORS = ["NodeA", "NodeB", "NodeC", "NodeD"]
f = (len(VALIDATORS) - 1) // 3
QUORUM = 2 * f + 1

from Crypto.Hash import SHA256
import json, os

def run_consensus_bft(proposer, record_str, proposer_signature, verify_fn):
    prepare_votes = []
    commit_votes = []
    verification_details = {}

    # Load proposer's public key
    key_path = os.path.join(os.path.dirname(__file__), f"{proposer}.json")
    with open(key_path, encoding='utf-8-sig') as f:
        key_data = json.load(f)
    p, q, e = int(key_data["p"]), int(key_data["q"]), int(key_data["e"])
    n = p * q

    h_bytes = SHA256.new(record_str.encode()).digest()
    h_int = int.from_bytes(h_bytes, 'big')

    for v in VALIDATORS:
        if v == proposer:
            verification_details[v] = {
                "matched": None,
                "note": "Proposer does not verify its own signature."
            }
            continue

        decrypted = pow(proposer_signature, e, n)
        matched = (decrypted == h_int)

        # <<<<< DEBUG PRINT HERE >>>>>
        print(f"Verifier: {v}, decrypted signature: {decrypted}, expected hash: {h_int}, matched: {matched}")

        verification_details[v] = {
            "expected_hash": str(h_int),
            "decrypted_signature": str(decrypted),
            "matched": matched,
            "modulus_n": str(n)
        }

        if matched:
            prepare_votes.append(v)

    commit_votes = prepare_votes.copy()
    consensus = len(prepare_votes) >= QUORUM and len(commit_votes) >= QUORUM

    return {
        "prepare_votes": prepare_votes,
        "commit_votes": commit_votes,
        "consensus": consensus,
        "verifications": {k: v.get("matched") for k, v in verification_details.items()},
        "details": verification_details
    }