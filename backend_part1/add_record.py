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

# Load RSA keys
KEYS_PATH = os.path.join(os.path.dirname(__file__), 'keys.json')
with open(KEYS_PATH, encoding='utf-8-sig') as f:
    KEY_DATA = json.load(f)

def derive_keys(node):
    p,q,e = (int(KEY_DATA[node][k]) for k in ('p','q','e'))
    n = p*q; phi=(p-1)*(q-1); d = pow(e, -1, phi)
    return n, e, d

def sign_record(node, rec_str):
    n,e,d = derive_keys(node)
    h = SHA256.new(rec_str.encode()).digest()
    return pow(int.from_bytes(h,'big'), d, n)

def verify_signature(node, rec_str, sig):
    n,e,d = derive_keys(node)
    h = SHA256.new(rec_str.encode()).digest()
    return pow(sig, e, n) == int.from_bytes(h,'big')


DATA_DIR = os.path.join(os.path.dirname(__file__), 'inventory_data')
os.makedirs(DATA_DIR, exist_ok=True)
for n in VALIDATORS:
    p = os.path.join(DATA_DIR, f"{n}.json")
    if not os.path.exists(p):
        with open(p,'w') as f:
            json.dump([], f)

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'add_record.html')

@app.route('/add_record', methods=['POST'])
def add_record():
    data   = request.json
    node   = data.get('node')
    record = data.get('record')  # {"id","qty","price"}

    # 1) Validate
    if node not in VALIDATORS or not record \
       or any(k not in record for k in ('id','qty','price')):
        return jsonify(error="Invalid input"), 400

    # 2) Sign & self-verify
    rec_str = json.dumps(record, sort_keys=True)
    sig     = sign_record(node, rec_str)
    if not verify_signature(node, rec_str, sig):
        return jsonify(error="Signature failed"), 500

    # 3) Consensus
    result = run_consensus_bft(node, rec_str, sig, verify_signature)
    if not result["consensus"]:
        return jsonify(
            error="Consensus not reached",
            prepare_votes=result["prepare_votes"],
            commit_votes=result["commit_votes"],
            consensus=False
        ), 403

    # 4) Append to each node’s DB
    for peer in VALIDATORS:
        dbf = os.path.join(DATA_DIR, f"{peer}.json")
        ledger = json.load(open(dbf))
        ledger.append({
            "id":       record["id"],
            "qty":      record["qty"],
            "price":    record["price"],
            "location": node,
            "sig":      sig
        })
        with open(dbf,'w') as f:
            json.dump(ledger, f, indent=2)

    # 5) Log to records.txt
    rec_line = f"{node},{record['qty']},{record['price']},{node}\n"
    with open(os.path.join(os.path.dirname(__file__),'records.txt'),'a') as rf:
        rf.write(rec_line)

    # 6) Return info
    return jsonify({
        "status":        "accepted",
        "consensus":     True,
        "prepare_votes": result["prepare_votes"],
        "commit_votes":  result["commit_votes"],
        "signature":     str(sig),
        "node":          node,
        "record":        record
    })

if __name__ == '__main__':
    print("Server at http://127.0.0.1:5000")
    app.run(debug=True)
