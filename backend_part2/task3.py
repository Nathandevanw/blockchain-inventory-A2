import json
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ------------------- Helper File I/O -------------------
def read_json(filepath):
    with open(filepath, 'r') as file:
        return json.load(file)

def write_json(filepath, data):
    with open(filepath, 'w') as file:
        json.dump(data, file, indent=4)

# ------------------- Key Setup -------------------
pkg_keys = read_json("backend_part2/pkg_keys.json")
po_keys = read_json("backend_part2/procurement_officer_keys.json")

p_pkg = pkg_keys["p"]
q_pkg = pkg_keys["q"]
e_pkg = pkg_keys["e"]
n_pkg = p_pkg * q_pkg
phi_pkg = (p_pkg - 1) * (q_pkg - 1)
d_pkg = pow(e_pkg, -1, phi_pkg)

po_p = po_keys["p"]
po_q = po_keys["q"]
po_e = po_keys["e"]
po_n = po_p * po_q
po_phi = (po_p - 1) * (po_q - 1)
po_d = pow(po_e, -1, po_phi)

# ------------------- Global Values -------------------
warehouse_files = {
    "Inventory_A": "backend_part2/Inventory_A_ID.json",
    "Inventory_B": "backend_part2/Inventory_B_ID.json",
    "Inventory_C": "backend_part2/Inventory_C_ID.json",
    "Inventory_D": "backend_part2/Inventory_D_ID.json"
}
warehouses = list(warehouse_files.keys())

# NEW: use inventory files not hardcoded data
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

# Crypto Functions
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

#  Warehouse Signature Simulation
def get_all_ids():
    """ Read IDs from warehouse JSON files. """
    ids = {}
    for name, file in warehouse_files.items():
        data = read_json(file)
        ids[name] = data["ID"]
    return ids

def pkg_generate_g():
    """ PKG calculates g for each warehouse and updates warehouse JSON file """
    ids = get_all_ids()
    for name in warehouses:
        file = warehouse_files[name]
        data = read_json(file)
        ID = ids[name]
        g = generate_g(ID)
        data["g"] = g
        write_json(file, data)

def warehouse_partial_signature(h, ids):
    """ Each warehouse calculates s_i and shares it to all warehouse files """
    for signer in warehouses:
        file = warehouse_files[signer]
        data = read_json(file)
        g = data["g"]
        r = data["random"]
        s_i = (g * powmod(r, h, n_pkg)) % n_pkg
        data["s_i"] = s_i
        write_json(file, data)

    # simulate writing s_i to all other warehouse files
    s_values = {}
    for signer in warehouses:
        s_values[signer] = read_json(warehouse_files[signer])["s_i"]

    for receiver in warehouses:
        file = warehouse_files[receiver]
        data = read_json(file)
        data["all_s_i"] = s_values
        write_json(file, data)

def calculate_aggregate_signature(data):
    
    s_total = 1
    for val in data["all_s_i"].values():
        s_total = (s_total * val) % n_pkg
    return s_total

# ------------------- Flask Route -------------------
@app.route("/query_item", methods=["POST"])
def query():
    item_id = request.json.get("item_id")
    # Step 1: Find item from any warehouse
    found_item = None
    for inventory in warehouse_inventories.values():
        for record in inventory:
            if record["id"] == item_id:
                found_item = record
                break
        if found_item:
            break

    if not found_item:
        return jsonify({"error": "Item ID not found"}), 404

    # Step 2: PKG calculates g for each warehouse
    pkg_generate_g()

    # Step 3: Calculate t values for each warehouse
    ids = get_all_ids()
    t_values = {}
    for name in warehouses:
        file = warehouse_files[name]
        data = read_json(file)
        r = data["random"]
        t_i = powmod(r, e_pkg, n_pkg)
        t_values[name] = t_i

    # Step 4: Warehouses calculate t_total
    t_total = 1
    for val in t_values.values():
        t_total = (t_total * val) % n_pkg

    # Step 5: PKG generates h
    h = md5_hash(str(t_total) + str(found_item["qty"]))

    # Step 6: Warehouses calculate partial signatures s_i and distribute
    warehouse_partial_signature(h, ids)

    # Step 7: Warehouses calculate s_total and send to PKG
    warehouse_results = []
    pkg_s = None
    for name in warehouses:
        file = warehouse_files[name]
        data = read_json(file)
        s_total = calculate_aggregate_signature(data)
        data["s_total"] = s_total
        write_json(file, data)
        warehouse_results.append({
            "warehouse": name,
            "ID": data["ID"],
            "random": data["random"],
            "g": data["g"],
            "t_i": t_values[name],
            "s_i": data["s_i"],
            "s_total": s_total
        })

    # Step 8: PKG calculates official s
    pkg_s = 1
    for name in warehouses:
        pkg_s = (pkg_s * read_json(warehouse_files[name])["s_i"]) % n_pkg

    # Step 9: PKG verifies all warehouse s_total match
    consensus_result = all([w["s_total"] == pkg_s for w in warehouse_results])

    # Step 10: PKG encrypts message and sends to Officer
    encrypted_qty = rsa_encrypt(found_item["qty"], po_e, po_n)
    decrypted_qty = rsa_decrypt(encrypted_qty, po_d, po_n)

    # Step 11: Officer verifies signature
    lhs = powmod(pkg_s, e_pkg, n_pkg)
    id_product = 1
    for val in ids.values():
        id_product = (id_product * val) % n_pkg
    rhs = (id_product * powmod(t_total, h, n_pkg)) % n_pkg
    valid = lhs == rhs

    return jsonify({
        "p": p_pkg,
        "q": q_pkg,
        "e": e_pkg,
        "n": n_pkg,
        "phi_n": phi_pkg,
        "d": d_pkg,
        "pkg_public_key": [e_pkg, n_pkg],
        "pkg_private_key": [d_pkg, n_pkg],
        "itemId": item_id,
        "item": found_item,
        "encrypted_quantity": str(encrypted_qty),
        "decrypted_quantity": str(decrypted_qty),
        "t_total": str(t_total),
        "hash": str(h),
        "signature": str(pkg_s),
        "lhs": str(lhs),
        "rhs": str(rhs),
        "valid": valid,
        "warehouses": warehouse_results,
        "consensus_result": consensus_result,
        "n_pkg": n_pkg
    })

if __name__ == "__main__":
    app.run(debug=False)
