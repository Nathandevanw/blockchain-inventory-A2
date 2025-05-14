from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import json

app = Flask(__name__)
CORS(app)

# === Step 1: Load data from external files ===

with open("backend_part2/pkg_keys.json") as f:
    pkg_data = json.load(f)

with open("backend_part2/procurement_officer_keys.json") as f:
    po_data = json.load(f)

with open("backend_part2/ids_randoms.json") as f:
    id_random_data = json.load(f)

# Warehouse inventory data
with open("backend_part1/inventory_data/NodeA.json") as f:
    inventory_A = json.load(f)
with open("backend_part1/inventory_data/NodeB.json") as f:
    inventory_B = json.load(f)
with open("backend_part1/inventory_data/NodeC.json") as f:
    inventory_C = json.load(f)
with open("backend_part1/inventory_data/NodeD.json") as f:
    inventory_D = json.load(f)

warehouse_inventories = {
    "Inventory_A": inventory_A,
    "Inventory_B": inventory_B,
    "Inventory_C": inventory_C,
    "Inventory_D": inventory_D
}

# === Step 2: Assign key variables ===

# PKG
p_pkg = pkg_data["p"]
q_pkg = pkg_data["q"]
e_pkg = pkg_data["e"]
n_pkg = p_pkg * q_pkg
phi_pkg = (p_pkg - 1) * (q_pkg - 1)
d_pkg = pow(e_pkg, -1, phi_pkg)

# Procurement Officer
po_p = po_data["p"]
po_q = po_data["q"]
po_e = po_data["e"]
po_n = po_p * po_q
po_phi = (po_p - 1) * (po_q - 1)
po_d = pow(po_e, -1, po_phi)

IDs = id_random_data["IDs"]
Randoms = id_random_data["Randoms"]
warehouse_list = list(IDs.keys())

# === Step 3: Helper functions ===

def md5_hash(value):
    return int(hashlib.md5(str(value).encode()).hexdigest(), 16)

def rsa_encrypt(msg, e, n):
    m = int.from_bytes(str(msg).encode(), 'big')
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    m = pow(c, d, n)
    return int.from_bytes(m.to_bytes((m.bit_length() + 7) // 8, 'big'), 'big')

def powmod(x, y, z):
    return pow(x, y, z)

def generate_g(ID):
    return powmod(ID, d_pkg, n_pkg)

def generate_t(r):
    return powmod(r, e_pkg, n_pkg)

def compute_aggregate_t(t_list):
    result = 1
    for t in t_list:
        result = (result * t) % n_pkg
    return result

def compute_aggregate_s(s_list):
    result = 1
    for s in s_list:
        result = (result * s) % n_pkg
    return result

def verify_signature(s, t, h):
    lhs = powmod(s, e_pkg, n_pkg)
    id_product = 1
    for ID in IDs.values():
        id_product = (id_product * ID) % n_pkg
    rhs = (id_product * powmod(t, h, n_pkg)) % n_pkg
    return lhs == rhs, lhs, rhs

# === Step 4: PoA consensus ===

REQUIRED_APPROVALS = 3

def validate_record(record, node_name):
    return int(record["qty"]) <= 1000

def simulate_consensus(record):
    votes = {}
    for node in warehouse_list:
        votes[node] = validate_record(record, node)
    approvals = sum(votes.values())
    return approvals >= REQUIRED_APPROVALS, votes

# === Step 5: Flask route ===

@app.route("/query_item", methods=["POST"])
def query():
    item_id = request.json.get("item_id")
    nodeA_items = warehouse_inventories["Inventory_A"]
    item = next((i for i in nodeA_items if i["id"] == item_id), None)

    if not item:
        return jsonify({"error": "Item ID not found"}), 404

    consensus_reached, votes = simulate_consensus(item)
    if not consensus_reached:
        return jsonify({"error": "Consensus failed."}), 403

    g_list, t_list, s_list = [], [], []
    result_details = []

    for name in warehouse_list:
        node_inventory = warehouse_inventories[name]
        node_item = next((i for i in node_inventory if i["id"] == item_id), None)
        if not node_item:
            return jsonify({"error": f"Item {item_id} not found in {name}."}), 404

        ID = IDs[name]
        r = Randoms[name]
        g = generate_g(ID)
        t = generate_t(r)
        g_list.append(g)
        t_list.append(t)

        result_details.append({
            "warehouse": name,
            "ID": ID,
            "r": r,
            "g": g,
            "t_i": t,
            "location": node_item["location"]
        })

    t = compute_aggregate_t(t_list)
    h = md5_hash(str(t) + str(item["qty"]))

    for i, name in enumerate(warehouse_list):
        r = Randoms[name]
        s_i = (g_list[i] * powmod(r, h, n_pkg)) % n_pkg
        s_list.append(s_i)
        result_details[i]["s_i"] = s_i

    s = compute_aggregate_s(s_list)
    valid, lhs, rhs = verify_signature(s, t, h)

    encrypted = rsa_encrypt(item["qty"], po_e, po_n)
    decrypted = rsa_decrypt(encrypted, po_d, po_n)

    return jsonify({
        "itemId": item_id,
        "item": {"qty": item["qty"], "price": item["price"], "location": item["location"]},
        "signature": str(s),
        "t": str(t),
        "hash": str(h),
        "valid": valid,
        "encrypted_quantity": str(encrypted),
        "decrypted_quantity": str(decrypted),
        "lhs": str(lhs),
        "rhs": str(rhs),
        "warehouses": result_details,
        "consensus_votes": votes,
        "consensus_result": consensus_reached
    })

if __name__ == "__main__":
    app.run(debug=True)
