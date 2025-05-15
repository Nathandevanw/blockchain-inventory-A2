import os, json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from Crypto.Hash import SHA256
from consensus import run_consensus_bft, VALIDATORS

app = Flask(
    __name__,
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend'),
    static_url_path=''
)
CORS(app)

# === Load RSA key for a given node ===
def derive_keys(node):
    path = os.path.join(os.path.dirname(__file__), f"{node}.json")
    with open(path, encoding='utf-8-sig') as f:
        key = json.load(f)

    p = int(key["p"])
    q = int(key["q"])
    e = int(key["e"])
    n = int(key["n"])
    phi = int(key["phi(n)"])
    d = int(key["d"])

    return n, e, d, p, q, phi

# === RSA Sign ===
def sign_record(node, rec_str):
    n, e, d, p, q, phi = derive_keys(node)
    h_bytes = SHA256.new(rec_str.encode()).digest()
    h_int = int.from_bytes(h_bytes, 'big')
    sig = pow(h_int, d, n)
    return sig, h_int, n, d, e, p, q, phi

# === RSA Verify ===
def verify_signature(node, rec_str, sig):
    n, e, *_ = derive_keys(node)
    h = SHA256.new(rec_str.encode()).digest()
    return pow(sig, e, n) == int.from_bytes(h, 'big')

# === Ensure inventory data dir & files ===
DATA_DIR = os.path.join(os.path.dirname(__file__), 'inventory_data')
os.makedirs(DATA_DIR, exist_ok=True)
for n in VALIDATORS:
    p = os.path.join(DATA_DIR, f"{n}.json")
    if not os.path.exists(p):
        with open(p, 'w') as f:
            json.dump([], f)

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'add_record.html')

@app.route('/add_record', methods=['POST'])
def add_record():
    data = request.json
    node = data.get('node')
    record = data.get('record')

    if node not in VALIDATORS or not record \
       or any(k not in record for k in ('id', 'qty', 'price')):
        return jsonify(error="Invalid input"), 400

    rec_str = f"{record['id']}{record['qty']}{record['price']}{node}"
    print("✅ rec_str used for hashing:", rec_str)

    sig, h_int, n, d, e, p, q, phi = sign_record(node, rec_str)

    if not verify_signature(node, rec_str, sig):
        return jsonify(error="Signature failed"), 500

    result = run_consensus_bft(node, rec_str, sig, verify_signature)
    if not result["consensus"]:
        return jsonify(
            error="Consensus not reached",
            prepare_votes=result["prepare_votes"],
            commit_votes=result["commit_votes"],
            consensus=False
        ), 403

    # Append record to each validator's inventory file
    for peer in VALIDATORS:
        dbf = os.path.join(DATA_DIR, f"{peer}.json")
        ledger = json.load(open(dbf))
        ledger.append({
            "id": record["id"],
            "qty": record["qty"],
            "price": record["price"],
            "location": node,
            "signature": sig
        })
        with open(dbf, 'w') as f:
            json.dump(ledger, f, indent=2)

    # Append signature verification result to each node's file
    for peer in VALIDATORS:
        log_entry = {
            "record_id": record["id"],
            "signed_from": node,
            "sign_value": str(sig),
            "verified": result["verifications"][peer]
        }
        peer_file = os.path.join(os.path.dirname(__file__), f"{peer}.json")
        if os.path.exists(peer_file):
            with open(peer_file, 'r+', encoding='utf-8') as f:
                try:
                    peer_data = json.load(f)
                    if isinstance(peer_data, dict):
                        peer_data.setdefault("verifications", []).append(log_entry)
                    elif isinstance(peer_data, list):
                        peer_data = {"records": peer_data, "verifications": [log_entry]}
                except json.JSONDecodeError:
                    peer_data = {"verifications": [log_entry]}
                f.seek(0)
                json.dump(peer_data, f, indent=2)
                f.truncate()

    return jsonify({
        "status": "accepted",
        "record_string": rec_str,
        "consensus": True,
        "prepare_votes": result["prepare_votes"],
        "commit_votes": result["commit_votes"],
        "verifications": result["verifications"],
        "details": result["details"],
        "signature": str(sig),
        "hash_int": str(h_int),
        "modulus_n": str(n),
        "private_d": str(d),
        "public_e": str(e),
        "p": str(p),
        "q": str(q),
        "phi": str(phi),
        "node": node,
        "record": record
    })

if __name__ == '__main__':
    print(" Server running at: http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
