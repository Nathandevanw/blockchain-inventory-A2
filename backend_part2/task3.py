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

# PKG Key Setup: using values of p, q, and e from the key list
# These values are already precomputed in 'all_keys.json' and include RSA n and d
# Example: n = p * q, d = e^-1 mod (p-1)(q-1)
# They are hardcoded for all identities to match assignment requirements

# Inventory item data: same quantity, price, location across all inventory nodes
inventory_items = {
    "001": {"qty": 32, "price": 12, "location": "D"},
    "002": {"qty": 20, "price": 14, "location": "C"},
    "003": {"qty": 22, "price": 16, "location": "B"},
    "004": {"qty": 12, "price": 18, "location": "A"}
}

def powmod(x, y, z):
    return pow(x, y, z)

def generate_g(ID, d, n):
    return powmod(ID, d, n)

def generate_t(r, e, n):
    return powmod(r, e, n)

def compute_t(t_list, n):
    t = 1
    for val in t_list:
        t = (t * val) % n
    return t

def hash_tm(t, message):
    h = hashlib.md5((str(t) + str(message)).encode()).hexdigest()
    return int(h, 16)

def generate_s(g, r, h, n):
    return (g * powmod(r, h, n)) % n

def aggregate_s(s_list, n):
    s = 1
    for si in s_list:
        s = (s * si) % n
    return s

def verify_signature(s, e, n, ids, t, h):
    lhs = powmod(s, e, n)
    id_product = 1
    for ID in ids:
        id_product = (id_product * ID) % n
    rhs = (id_product * powmod(t, h, n)) % n
    return lhs == rhs

def rsa_encrypt(message, e, n):
    m = int.from_bytes(str(message).encode(), 'big')
    return powmod(m, e, n)

def rsa_decrypt(cipher, d, n):
    m = powmod(cipher, d, n)
    return int.from_bytes(m.to_bytes((m.bit_length() + 7) // 8, 'big'), 'big')

@app.route("/query_item", methods=["POST"])
def query_item():
    item_id = request.json.get("item_id")
    item_info = inventory_items.get(item_id)
    if not item_info:
        return jsonify({"error": "Item ID not found."}), 404

    qty = item_info["qty"]
    e_pkg = harn["PKG"]["e"]  # RSA public key
    n_pkg = harn["PKG"]["n"]  # RSA modulus (n = p * q)
    t_list, s_list, inventory_data = [], [], []

    # Generate signature components for each inventory node
    for name in inventories:
        ID = IDs[name]
        d = inventories[name]["d"]
        n = inventories[name]["n"]
        r = Randoms[name]

        g = generate_g(ID, d, n)
        t = generate_t(r, e_pkg, n)
        t_list.append(t)

        inventory_data.append({
            "inventory": name,
            "ID": ID,
            "r": r,
            "g": g,
            "t_i": t,
            "quantity": qty,
            "price": item_info["price"],
            "location": item_info["location"]
        })

    # Compute combined t and hash
    t = compute_t(t_list, n_pkg)
    h = hash_tm(t, qty)

    for idx, name in enumerate(inventories):
        r = Randoms[name]
        g = inventory_data[idx]["g"]
        n = inventories[name]["n"]
        s_i = generate_s(g, r, h, n)
        s_list.append(s_i)
        inventory_data[idx]["s_i"] = s_i

    sig = aggregate_s(s_list, n_pkg)
    ids = list(IDs.values())
    verified = verify_signature(sig, e_pkg, n_pkg, ids, t, h)

    # Encrypt total using PKG's RSA public key
    enc = rsa_encrypt(qty, e_pkg, n_pkg)
    dec = rsa_decrypt(enc, harn["PKG"]["d"], n_pkg)  # For verification simulation only

    return jsonify({
        "itemId": item_id,
        "item": item_info,
        "multi_signature": str(sig),
        "t": str(t),
        "hash": str(h),
        "encrypted_quantity": str(enc),
        "decrypted_quantity": str(dec),
        "verification": verified,
        "inventory_nodes": inventory_data
    })

if __name__ == "__main__":
    app.run(debug=True)
