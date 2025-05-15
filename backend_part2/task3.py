import json
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def read_json(path):
    with open(path, 'r') as f:
        return json.load(f)

def write_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

# ----- Load Keys -----
pkg_keys = read_json("backend_part2/pkg_keys.json")
po_keys = read_json("backend_part2/procurement_officer_keys.json")

p_pkg = int(pkg_keys["p"])
q_pkg = int(pkg_keys["q"])
e_pkg = int(pkg_keys["e"])
n_pkg = p_pkg * q_pkg
phi_pkg = (p_pkg - 1) * (q_pkg - 1)
d_pkg = pow(e_pkg, -1, phi_pkg)
pkg_keys["phi_n"] = phi_pkg
pkg_keys["d"] = d_pkg
pkg_keys["n"] = n_pkg
write_json("backend_part2/pkg_keys.json", pkg_keys)

p_po = int(po_keys["p"])
q_po = int(po_keys["q"])
e_po = int(po_keys["e"])
n_po = p_po * q_po
phi_po = (p_po - 1) * (q_po - 1)
d_po = pow(e_po, -1, phi_po)
po_keys["d"] = d_po
po_keys["n"] = n_po
write_json("backend_part2/procurement_officer_keys.json", po_keys)

warehouses = ["Inventory_A", "Inventory_B", "Inventory_C", "Inventory_D"]
warehouse_files = {
    "Inventory_A": "backend_part2/Inventory_A_ID.json",
    "Inventory_B": "backend_part2/Inventory_B_ID.json",
    "Inventory_C": "backend_part2/Inventory_C_ID.json",
    "Inventory_D": "backend_part2/Inventory_D_ID.json"
}
inventories = {
    "Inventory_A": read_json("backend_part1/inventory_data/NodeA.json"),
    "Inventory_B": read_json("backend_part1/inventory_data/NodeB.json"),
    "Inventory_C": read_json("backend_part1/inventory_data/NodeC.json"),
    "Inventory_D": read_json("backend_part1/inventory_data/NodeD.json")
}

# ✅ Force all qty values to be integers
for inv_data in inventories.values():
    for item in inv_data:
        item["qty"] = int(item["qty"])

# ----- Crypto -----
def md5_hash(value):
    return int(hashlib.md5(str(value).encode()).hexdigest(), 16)

def rsa_encrypt(m, e, n):
    return pow(int(m), int(e), int(n))

def rsa_decrypt(c, d, n):
    return pow(int(c), int(d), int(n))

def powmod(a, b, mod):
    return pow(int(a), int(b), int(mod))

def generate_g(ID):
    return powmod(ID, d_pkg, n_pkg)

# ----- Protocol -----
def get_all_ids():
    return {w: int(read_json(warehouse_files[w])["ID"]) for w in warehouses}

def pkg_generate_g():
    ids = get_all_ids()
    for w in warehouses:
        file = warehouse_files[w]
        data = read_json(file)
        data["g"] = generate_g(ids[w])
        write_json(file, data)

def warehouse_t_sharing():
    t_values = {}
    for w in warehouses:
        file = warehouse_files[w]
        data = read_json(file)
        r = int(data["random"])
        t_i = powmod(r, e_pkg, n_pkg)
        data["t_i"] = t_i
        write_json(file, data)
        t_values[w] = t_i
    return t_values

def warehouse_partial_signature(h, t_values):
    for w in warehouses:
        file = warehouse_files[w]
        data = read_json(file)
        g = int(data["g"])
        r = int(data["random"])
        s_i = (g * powmod(r, h, n_pkg)) % n_pkg
        data["s_i"] = s_i
        write_json(file, data)

    s_values = {w: int(read_json(warehouse_files[w])["s_i"]) for w in warehouses}
    for w in warehouses:
        file = warehouse_files[w]
        data = read_json(file)
        data["all_s_i"] = s_values
        write_json(file, data)

def calculate_aggregate_signature(data):
    s_total = 1
    for val in data["all_s_i"].values():
        s_total = (s_total * int(val)) % n_pkg
    return s_total

# ----- API -----
@app.route('/query_item', methods=['POST'])
def query_item():
    item_id = request.json.get('item_id')
    found = None
    for inv in inventories.values():
        for item in inv:
            if item["id"] == item_id:
                found = item
                break
        if found: break
    if not found:
        return jsonify({"error": "Item not found"}), 404

    pkg_generate_g()
    t_values = warehouse_t_sharing()

    t_total = 1
    for t in t_values.values():
        t_total = (t_total * t) % n_pkg

    quantity = int(found["qty"])   
    h = md5_hash(str(t_total) + str(quantity))
    warehouse_partial_signature(h, t_values)

    warehouse_results = []
    for w in warehouses:
        data = read_json(warehouse_files[w])
        s_total = calculate_aggregate_signature(data)
        data["s_total"] = s_total
        write_json(warehouse_files[w], data)
        warehouse_results.append({
            "warehouse": w,
            "ID": data["ID"],
            "random": data["random"],
            "g": data["g"],
            "t_i": data["t_i"],
            "s_i": data["s_i"],
            "s_total": s_total
        })

    all_s_totals = [w["s_total"] for w in warehouse_results]
    consensus = all(x == all_s_totals[0] for x in all_s_totals)

    # PKG creates response message
    response_msg = {"m": quantity, "t_total": t_total, "s_total": all_s_totals[0]}
    write_json("backend_part2/response_message.json", response_msg)

    # ✅ Encryption & file storage for assignment
    encrypted_m = rsa_encrypt(quantity, e_po, n_po)
    decrypted_m = rsa_decrypt(encrypted_m, d_po, n_po)
    encryption_result = {
        "Qty": quantity,
        "encrypted_quantity": encrypted_m,
        "decrypted_quantity": decrypted_m
    }
    write_json("backend_part2/encryption_result.json", encryption_result)

    ids = get_all_ids()
    lhs = powmod(all_s_totals[0], e_pkg, n_pkg)
    id_product = 1
    for v in ids.values():
        id_product = (id_product * v) % n_pkg
    rhs = (id_product * powmod(t_total, h, n_pkg)) % n_pkg
    valid = lhs == rhs

    return jsonify({
        "pkg_keys": {
            "p": p_pkg,
            "q": q_pkg,
            "e": e_pkg,
            "d": d_pkg,
            "n": n_pkg,
            "phi_n": phi_pkg
        },
        "po_keys": {
            "e": e_po,
            "d": d_po,
            "n": n_po
        },
        "phi_n": phi_pkg,
        "item": found,
        "itemId": item_id,
        "encrypted_quantity": encrypted_m,
        "decrypted_quantity": decrypted_m,
        "consensus": consensus,
        "lhs": str(lhs),
        "rhs": str(rhs),
        "valid": valid,
        "warehouses": warehouse_results
    })

if __name__ == '__main__':
    app.run(debug=True)
