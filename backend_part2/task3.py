import json
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = False
CORS(app)

def read_json(filepath):
    try:
        with open(filepath, 'r') as file:
            return json.load(file)
    except Exception as e:
        print(f"❌ Error reading {filepath}: {e}")
        return {}

def write_json(filepath, data):
    try:
        with open(filepath, 'w') as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print(f"❌ Error writing {filepath}: {e}")

pkg_keys = read_json("backend_part2/pkg_keys.json")
po_keys = read_json("backend_part2/procurement_officer_keys.json")

p_pkg, q_pkg, e_pkg = pkg_keys.get("p", 1), pkg_keys.get("q", 1), pkg_keys.get("e", 1)
n_pkg = p_pkg * q_pkg
phi_pkg = (p_pkg - 1) * (q_pkg - 1)
d_pkg = pow(e_pkg, -1, phi_pkg)

# ✅ NEW: store d into pkg_keys.json
pkg_keys["d"] = d_pkg
write_json("backend_part2/pkg_keys.json", pkg_keys)

po_p, po_q, po_e = po_keys.get("p", 1), po_keys.get("q", 1), po_keys.get("e", 1)
po_n = po_p * po_q
po_phi = (po_p - 1) * (po_q - 1)
po_d = pow(po_e, -1, po_phi)

warehouse_files = {
    "Inventory_A": "backend_part2/Inventory_A_ID.json",
    "Inventory_B": "backend_part2/Inventory_B_ID.json",
    "Inventory_C": "backend_part2/Inventory_C_ID.json",
    "Inventory_D": "backend_part2/Inventory_D_ID.json"
}
warehouses = list(warehouse_files.keys())

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

def get_all_ids():
    ids = {}
    for name, file in warehouse_files.items():
        data = read_json(file)
        ids[name] = data.get("ID", 0)
    return ids

def pkg_generate_g():
    pkg_g_record = {}
    for name in warehouses:
        file = warehouse_files[name]
        data = read_json(file)
        ID = data.get("ID", 0)
        g = generate_g(ID)
        data["g"] = g
        write_json(file, data)
        pkg_g_record[f"g_{name[-1]}"] = g
    write_json("backend_part2/pkg_calculated_g.json", pkg_g_record)

def warehouse_partial_signature(h):
    for signer in warehouses:
        file = warehouse_files[signer]
        data = read_json(file)
        g = data.get("g", 0)
        r = data.get("random", 0)
        s_i = (g * powmod(r, h, n_pkg)) % n_pkg
        data["s_i"] = s_i
        write_json(file, data)

    s_values = {signer: read_json(warehouse_files[signer]).get("s_i", 0) for signer in warehouses}
    for receiver in warehouses:
        file = warehouse_files[receiver]
        data = read_json(file)
        data["all_s_i"] = s_values
        write_json(file, data)

def calculate_aggregate_signature(data):
    s_total = 1
    for val in data.get("all_s_i", {}).values():
        s_total = (s_total * val) % n_pkg
    return s_total
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

    # Step 2: PKG calculates g values and stores pkg_calculated_g.json
    pkg_generate_g()

    # Step 3: Calculate t_i for each warehouse
    ids = get_all_ids()
    t_values = {}
    for name in warehouses:
        file = warehouse_files[name]
        data = read_json(file)
        r = data.get("random", 0)
        t_i = powmod(r, e_pkg, n_pkg)
        t_values[name] = t_i

    # Step 4: Aggregate t_total
    t_total = 1
    for t in t_values.values():
        t_total = (t_total * t) % n_pkg

    # Step 5: PKG calculates h = md5(t_total + qty)
    h = md5_hash(str(t_total) + str(found_item["qty"]))

    # Step 6: Warehouses calculate partial signatures
    warehouse_partial_signature(h)

    # Step 7: Warehouses calculate s_total and send to PKG
    warehouse_results = []
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

    # Step 8: PKG verifies consensus
    pkg_expected_s = None
    consensus_results = []
    for w in warehouse_results:
        if pkg_expected_s is None:
            pkg_expected_s = w["s_total"]
        consensus_results.append({
            "warehouse": w["warehouse"],
            "s_total": str(w["s_total"]),
            "matches_pkg": w["s_total"] == pkg_expected_s
        })

    overall_consensus = all(w["matches_pkg"] for w in consensus_results)

    # Step 9: PKG encrypts message for Procurement Officer
    encrypted_qty = rsa_encrypt(found_item["qty"], po_e, po_n)
    decrypted_qty = rsa_decrypt(encrypted_qty, po_d, po_n)

    # Step 10: Procurement Officer verifies signature
    lhs = powmod(pkg_expected_s, e_pkg, n_pkg)
    id_product = 1
    for val in ids.values():
        id_product = (id_product * val) % n_pkg
    rhs = (id_product * powmod(t_total, h, n_pkg)) % n_pkg
    valid = lhs == rhs

    pkg_g_values = read_json("backend_part2/pkg_calculated_g.json")

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
        "signature": str(pkg_expected_s),
        "lhs": str(lhs),
        "rhs": str(rhs),
        "valid": valid,
        "warehouses": warehouse_results,
        "consensus_result": overall_consensus,
        "consensus_details": consensus_results,
        "pkg_g_values": pkg_g_values
    })

if __name__ == "__main__":
    app.run(debug=True)
