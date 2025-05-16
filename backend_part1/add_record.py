import os
import json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from Crypto.Hash import SHA256
from consensus import run_consensus_bft, VALIDATORS

# This web application handles record signing and consensus for inventory management.
# It loads node keys, signs records, verifies signatures, and stores agreed data.
app = Flask(
    __name__,
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend'),
    static_url_path=''
)
CORS(app)

# Reads RSA key parameters from the given node's JSON file.
def loadkeys(node):
    path = os.path.join(os.path.dirname(__file__), f"{node}.json")
    with open(path, encoding='utf-8-sig') as file:
        keys = json.load(file)
    p = int(keys["p"])
    q = int(keys["q"])
    n = int(keys["n"])
    e = int(keys["e"])
    d = int(keys["d"])
    phi = int(keys["phi(n)"])
    return n, e, d, p, q, phi

# Signs a record string using SHA256 and RSA with the node’s private key.
def signrecord(node, record_str):
    n, e, d, p, q, phi = loadkeys(node)
    hashed = SHA256.new(record_str.encode()).digest()
    hashed_int = int.from_bytes(hashed, byteorder='big')
    signature = pow(hashed_int, d, n)
    return signature, hashed_int, n, d, e, p, q, phi

# Verifies a given signature using the node's RSA public key.
def verifysignature(node, record_str, signature):
    n, e, *_ = loadkeys(node)
    expected_hash = SHA256.new(record_str.encode()).digest()
    return pow(signature, e, n) == int.from_bytes(expected_hash, 'big')

# Ensure inventory_data folder and individual node files exist
inventory_path = os.path.join(os.path.dirname(__file__), 'inventory_data')
os.makedirs(inventory_path, exist_ok=True)

for node in VALIDATORS:
    file_path = os.path.join(inventory_path, f"{node}.json")
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            json.dump([], f)

# Serves the form-based frontend for manual record submission
@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'add_record.html')

# Receives a record from the frontend, signs it, runs consensus, and stores it
@app.route('/add_record', methods=['POST'])
def add_record():
    data = request.get_json()
    node = data.get('node')
    record = data.get('record')

    # Validate the input data
    if node not in VALIDATORS or not record or not all(k in record for k in ['id', 'qty', 'price']):
        return jsonify(error="Missing or incorrect record details"), 400

    # Prepare a string representation of the record for hashing and signing
    record_str = f"{record['id']}{record['qty']}{record['price']}{node}"

    # Create a digital signature for the record
    signature, hash_int, n, d, e, p, q, phi = signrecord(node, record_str)

    # Check the signature before sending to consensus
    if not verifysignature(node, record_str, signature):
        return jsonify(error="Failed to verify signature"), 500

    # Run the consensus protocol across all validator nodes
    result = run_consensus_bft(node, record_str, signature, verifysignature)

    if not result["consensus"]:
        return jsonify({
            "status": "rejected",
            "error": "Consensus failed",
            "prepare_votes": result["prepare_votes"],
            "commit_votes": result["commit_votes"],
            "consensus": False
        }), 403

    # Append the record to each node's local inventory
    for peer in VALIDATORS:
        file_path = os.path.join(inventory_path, f"{peer}.json")
        with open(file_path, 'r') as f:
            records = json.load(f)

        records.append({
            "id": record["id"],
            "qty": record["qty"],
            "price": record["price"],
            "location": node,
            "signature": signature
        })

        with open(file_path, 'w') as f:
            json.dump(records, f, indent=2)

    # Log the verification results for transparency
    for peer in VALIDATORS:
        log = {
            "record_id": record["id"],
            "signed_by": node,
            "signature": str(signature),
            "verified": result["verifications"][peer]
        }

        log_file = os.path.join(os.path.dirname(__file__), f"{peer}.json")
        if os.path.exists(log_file):
            with open(log_file, 'r+', encoding='utf-8') as f:
                try:
                    content = json.load(f)
                    if isinstance(content, dict):
                        content.setdefault("verifications", []).append(log)
                    else:
                        content = {"records": content, "verifications": [log]}
                except json.JSONDecodeError:
                    content = {"verifications": [log]}
                f.seek(0)
                json.dump(content, f, indent=2)
                f.truncate()

    # Return the complete result to the frontend
    return jsonify({
        "status": "accepted" if result["consensus"] else "rejected",
        "record_string": record_str,
        "consensus": True,
        "prepare_votes": result["prepare_votes"],
        "commit_votes": result["commit_votes"],
        "verifications": result["verifications"],
        "details": result["details"],
        "signature": str(signature),
        "hash_int": str(hash_int),
        "modulus_n": str(n),
        "private_d": str(d),
        "public_e": str(e),
        "p": str(p),
        "q": str(q),
        "phi": str(phi),
        "node": node,
        "record": record
    })

# Start the Flask app locally
if __name__ == '__main__':
    print("Flask server started at http://127.0.0.1:5000")
    app.run(debug=True, port=5000)