# consensus.py
# Two-phase PBFT with vote lists

VALIDATORS = ["Inventory_A", "Inventory_B", "Inventory_C", "Inventory_D"]
f = (len(VALIDATORS) - 1) // 3   # =1 for n=4
QUORUM = 2 * f + 1               # =3

def run_consensus_bft(proposer, record_str, signature, verify_fn):
    """
    Returns a dict:
      {
        "prepare_votes": [ ... ],
        "commit_votes":  [ ... ],
        "consensus":     bool
      }
    """
    # Phase 1: Prepare
    prepare_votes = []
    for v in VALIDATORS:
        if verify_fn(proposer, record_str, signature):
            prepare_votes.append(v)

    # Phase 2: Commit (only those who prepared)
    commit_votes = prepare_votes.copy()

    success = (len(prepare_votes) >= QUORUM and
               len(commit_votes)  >= QUORUM)
    return {
        "prepare_votes": prepare_votes,
        "commit_votes":  commit_votes,
        "consensus":     success
    }
