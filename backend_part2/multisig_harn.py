from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import hashlib

app = Flask(__name__)
CORS(app)

# Load key data from file
with open("C:\\Users\\thaiv\\Downloads\\blockchain_inventory_final_with_keys\\backend_part2\\all_keys.json") as f:
    keys = json.load(f)

inventories = keys["Inventories"]
harn = keys["HarnKeys"]
IDs = harn["IDs"]
Randoms = harn["Randoms"]

# Simulated database of inventory records
inventory_db = {
    "Inventory_A": {"001": 32, "002": 20, "003": 22, "004": 12},
    "Inventory_B": {"001": 32, "002": 20,  "003": 22, "004": 12},
    "Inventory_C": {"001": 32, "002": 20,  "003": 22,  "004": 12},
    "Inventory_D": {"001": 32, "002": 20,  "003": 22,  "004": 12}
}

# Helper Functions
def generate_secret_key(ID, d, n):
    return pow(ID, d, n)

def generate_commitment(r, e, n):
    return pow(r, e, n)

def combine_commitments(t_list, n):
    t = 1
    for ti in t_list:
        t = (t * ti) % n
    return t

def compute_hash(t, message):
    digest = hashlib.md5((str(t) + str(message)).encode()).hexdigest()
    return int(digest, 16)

def generate_partial_signature(g, r, h, n):
    return (g * pow(r, h, n)) % n

def aggregate_signature(s_list, n):
    s = 1
    for si in s_list:
        s = (s * si) % n
    return s

def rsa_encrypt(message, e, n):
    m = int.from_bytes(str(message).encode(), 'big')
    return pow(m, e, n)

def rsa_decrypt(cipher, d, n):
    m = pow(cipher, d, n)
    return int.from_bytes(m.to_bytes((m.bit_length() + 7) // 8, 'big'), 'big')

def verify_signature(s, e, n, ids, t, h):
    lhs = pow(s, e, n)
    id_product = 1
    for ID in ids:
        id_product = (id_product * ID) % n
    rhs = (id_product * pow(t, h, n)) % n
    return lhs == rhs

@app.route("/query_item", methods=["POST"])
def query_item():
    item_id = request.json.get("item_id")
    quantities = {inv: inventory_db[inv].get(item_id, 0) for inv in inventory_db}
    total_quantity = sum(quantities.values())

    e_pkg = harn["PKG"]["e"]
    n_pkg = harn["PKG"]["n"]
    ids = list(IDs.values())

    t_list, s_list, details = [], [], []

    for name in inventories:
        ID = IDs[name]
        d = inventories[name]["d"]
        n = inventories[name]["n"]
        r = Randoms[name]
        g = generate_secret_key(ID, d, n)
        t_i = generate_commitment(r, e_pkg, n)
        t_list.append(t_i)

    t = combine_commitments(t_list, n_pkg)
    h = compute_hash(t, total_quantity)

    for i, name in enumerate(inventories):
        ID = IDs[name]
        d = inventories[name]["d"]
        n = inventories[name]["n"]
        r = Randoms[name]
        g = generate_secret_key(ID, d, n)
        s_i = generate_partial_signature(g, r, h, n)
        s_list.append(s_i)
        details.append({
            "inventory": name,
            "ID": ID,
            "r": r,
            "quantity": quantities[name],
            "t_i": t_list[i],
            "s_i": s_i
        })

    signature = aggregate_signature(s_list, n_pkg)

    po_e = harn["ProcurementOfficer"]["e"]
    po_n = harn["ProcurementOfficer"]["n"]
    po_d = harn["ProcurementOfficer"]["d"]

    ciphertext = rsa_encrypt(total_quantity, po_e, po_n)
    decrypted = rsa_decrypt(ciphertext, po_d, po_n)

    is_valid = verify_signature(signature, e_pkg, n_pkg, ids, t, h)

    return jsonify({
        "itemId": item_id,
        "total_quantity": total_quantity,
        "multi_signature": str(signature),
        "t": str(t),
        "hash": str(h),
        "encrypted_quantity": str(ciphertext),
        "decrypted_quantity": str(decrypted),
        "verification": is_valid,
        "details": details
    })

if __name__ == '__main__':
    app.run(debug=True)