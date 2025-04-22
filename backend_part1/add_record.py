# add_record.py
# Author: Part 1 Owner
#
# This script:
#  - Hard‑codes each Inventory’s RSA keys
#  - Exposes a POST /add_record to sign & verify a record
#  - Returns JSON { node, record, signature, valid }

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
from Crypto.Hash import SHA256
import os

RECORDS_FILE = os.path.join(os.path.dirname(__file__), 'records.txt')
app = Flask(
    __name__,
    static_folder='static',    # ← serve files from backend/static/
    static_url_path=''         # ← so '/' and '/add_record.html' map here
)
CORS(app)

# -- RSA parameters (p, q, e) for Inventories A–D from ListOfKeys.docx --
InvParams = {
    "Inventory_A": {
        "p": 1210613765735147311106936311866593978079938707,
        "q": 1247842850282035753615951347964437248190231863,
        "e": 815459040813953176289801
    },
    "Inventory_B": {
        "p": 787435686772982288169641922308628444877260947,
        "q": 1325305233886096053310340418467385397239375379,
        "e": 692450682143089563609787
    },
    "Inventory_C": {
        "p": 1014247300991039444864201518275018240361205111,
        "q": 904030450302158058469475048755214591704639633,
        "e": 1158749422015035388438057
    },
    "Inventory_D": {
        "p": 1287737200891425621338551020762858710281638317,
        "q": 1330909125725073469794953234151525201084537607,
        "e": 33981230465225879849295979
    }
}

def derive_keys(params):
    """Given p,q,e => return (n, e, d)."""
    p, q, e = params['p'], params['q'], params['e']
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return n, e, d

def sign_record(node, record_str):
    """Hash the JSON string and RSA‑sign with the node’s private key."""
    n, e, d = derive_keys(InvParams[node])
    h = SHA256.new(record_str.encode()).digest()
    m = int.from_bytes(h, 'big')
    return pow(m, d, n)

def verify_signature(node, record_str, signature):
    """Recompute the hash and check sig^e mod n == m."""
    n, e, d = derive_keys(InvParams[node])
    h = SHA256.new(record_str.encode()).digest()
    m = int.from_bytes(h, 'big')
    return pow(signature, e, n) == m

@app.route('/add_record', methods=['POST'])
def add_record():
    """
    Expects JSON:
      { "node": "Inventory_A", 
        "record": { "id":"001", "qty":32, "price":12 } 
      }
    Returns:
      { node, record, signature, valid }
    """
    data   = request.json
    node   = data.get('node')
    record = data.get('record')

    if node not in InvParams or not record:
        return jsonify({"error":"Invalid input"}), 400

    # 1) Canonical JSON string
    rec_str = json.dumps(record, sort_keys=True)

    # 2) Sign + verify
    sig   = sign_record(node, rec_str)
    valid = verify_signature(node, rec_str, sig)

    line = f"{node},{record['id']},{record['qty']},{record['price']},{sig}\n"
    with open(RECORDS_FILE, 'a') as f:
        f.write(line)
    # ----------------------------------


    return jsonify({
        "node":      node,
        "record":    record,
        "signature": str(sig),
        "valid":     valid
    })
@app.route('/')
def index():
    # returns backend/static/add_record.html
    return app.send_static_file('add_record.html')

if __name__ == '__main__':
    app.run(debug=True)

