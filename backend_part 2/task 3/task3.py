
from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib, json, os

p_pkg = 1004162036461488639338597000466705179253226703
q_pkg = 950133741151267522116252385927940618264103623
e_pkg = 973028207197278907211
n_pkg = p_pkg * q_pkg
phi_pkg = (p_pkg - 1) * (q_pkg - 1)
d_pkg = pow(e_pkg, -1, phi_pkg)

po_p = 1080954735722463992988394149602856332100628417
po_q = 1158106283320086444890911863299879973542293243
po_e = 106506253943651610547613
po_n = po_p * po_q
po_phi = (po_p - 1) * (po_q - 1)
po_d = pow(po_e, -1, po_phi)

IDs = {
    "Inventory_A": 126,
    "Inventory_B": 127,
    "Inventory_C": 128,
    "Inventory_D": 129
}
Randoms = {
    "Inventory_A": 621,
    "Inventory_B": 721,
    "Inventory_C": 821,
    "Inventory_D": 921
}
NodeKeys = {
    "Inventory_A": {"p": 953, "q": 1031, "e": 17},
    "Inventory_B": {"p": 941, "q": 1091, "e": 17},
    "Inventory_C": {"p": 967, "q": 1061, "e": 17},
    "Inventory_D": {"p": 971, "q": 1049, "e": 17}
}
WAREHOUSES = list(IDs.keys())

app = Flask(__name__)
CORS(app)

def md5_hash(val): return int(hashlib.md5(str(val).encode()).hexdigest(), 16)
def powmod(a, b, mod): return pow(a, b, mod)
def rsa_encrypt(msg, e, n): return pow(int.from_bytes(str(msg).encode(), 'big'), e, n)
def rsa_decrypt(cipher, d, n):
    m = pow(cipher, d, n)
    return int.from_bytes(m.to_bytes((m.bit_length() + 7) // 8, 'big'), 'big')
def generate_g(ID): return powmod(ID, d_pkg, n_pkg)
def generate_t(r): return powmod(r, e_pkg, n_pkg)
def compute_aggregate(vals): 
    result = 1
    for v in vals: result = (result * v) % n_pkg
    return result
def verify_signature(s, t, h): 
    lhs = powmod(s, e_pkg, n_pkg)
    rhs = (compute_aggregate(IDs.values()) * powmod(t, h, n_pkg)) % n_pkg
    return lhs == rhs, lhs, rhs

@app.route("/query_item", methods=["POST"])
def query_item():
    try:
        req = request.get_json()
        item_id = str(req.get("item_id")).strip()
        matched_records = []

        inventory_folder = "inventory_data"
        files = ["Inventory_A.json", "Inventory_B.json", "Inventory_C.json", "Inventory_D.json"]

        for fname in files:
            path = os.path.join(inventory_folder, fname)
            warehouse = fname.replace(".json", "")
            with open(path) as f:
                records = json.load(f)
                for r in records:
                    if str(r.get("id")).strip() == item_id:
                        r["location"] = warehouse
                        matched_records.append((warehouse, r))

        if not matched_records:
            return jsonify({"error": "Item not found in any warehouse"}), 404

        selected_node, item = matched_records[0]
        g_list, t_list, s_list, warehouse_details = [], [], [], []

        for node in WAREHOUSES:
            ID = IDs[node]
            r = Randoms[node]
            g = generate_g(ID)
            t = generate_t(r)
            g_list.append(g)
            t_list.append(t)
            warehouse_details.append({
                "warehouse": node, "ID": ID, "r": r, "g": g, "t_i": t
            })

        t_agg = compute_aggregate(t_list)
        h = md5_hash(str(t_agg) + str(item["qty"]))

        for i, node in enumerate(WAREHOUSES):
            r = Randoms[node]
            s_i = (g_list[i] * powmod(r, h, n_pkg)) % n_pkg
            s_list.append(s_i)
            warehouse_details[i]["s_i"] = s_i

        s = compute_aggregate(s_list)
        valid, lhs, rhs = verify_signature(s, t_agg, h)

        encrypted_qty = rsa_encrypt(item["qty"], po_e, po_n)
        decrypted_qty = rsa_decrypt(encrypted_qty, po_d, po_n)

        return jsonify({
            "item": item,
            "encrypted_quantity": str(encrypted_qty),
            "decrypted_quantity": decrypted_qty,
            "signature_valid": valid,
            "multi_signature": str(s),
            "h": str(h),
            "lhs": str(lhs),
            "rhs": str(rhs),
            "warehouse_details": warehouse_details
        })

    except Exception as e:
        return jsonify({ "error": str(e) }), 500

if __name__ == "__main__":
    app.run(debug=True)
