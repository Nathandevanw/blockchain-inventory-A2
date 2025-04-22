# consensus.py
def run_consensus(node, record, signature):
    """
    Simulate: broadcast to peers, verify sig, collect votes.
    Return True if ≥3/4 approvals.
    """
    approvals = 1  # include self
    for peer in ['A','B','C','D']:
        if peer == node: continue
        # peer-side: verify signature (reuse verify_signature)
        if verify_signature(peer, record, signature):
            approvals += 1
    return approvals >= 3

from rsa_utils import verify_signature