from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib, json, os

# === Load keys from file ===
with open("backend_part 2/task 3/task3_key_parameters.json") as f:
    keys = json.load(f)

PKG = keys["PKG"]
PO = keys["ProcurementOfficer"]
INVENTORIES = keys["Inventories"]

p_pkg, q_pkg, e_pkg = PKG["p"], PKG["q"], PKG["e"]
n_pkg = p_pkg * q_pkg
phi_pkg = (p_pkg - 1) * (q_pkg - 1)
d_pkg = pow(e_pkg, -1, phi_pkg)

po_p, po_q, po_e = PO["p"], PO["q"], PO["e"]
po_n = po_p * po_q
po_phi = (po_p - 1) * (po_q - 1)
po_d = pow(po_e, -1, po_phi)

app = Flask(__name__)
CORS(app)

def md5_hash(val):
    return int(hashlib.md5(str(val).encode()).hexdigest(), 16)

def powmod(a, b, mod):
    return pow(a, b, mod)

def rsa_encrypt(msg, e, n):
    return pow(int.from_bytes(str(msg).encode(), 'big'), e, n)

def rsa_decrypt(cipher, d, n):
    m = pow(cipher, d, n)
    return int.from_bytes(m.to_bytes((m.bit_length() + 7) // 8, 'big'), 'big')

def generate_g(ID):
    return powmod(ID, d_pkg, n_pkg)

def generate_t(r):
    return powmod(r, e_pkg, n_pkg)

def compute_aggregate(values):
    result = 1
    for v in values:
        result = (result * v) % n_pkg
    return result

@app.route("/query_item", methods=["POST"])
def query_item():
    try:
        req = request.get_json()
        item_id = str(req.get("item_id")).strip()
        votes = []
        signed_nodes = []
        warehouse_details = []
        g_list, s_list = [], []

        inventory_folder = "inventory_data"
        files = [f"{w}.json" for w in INVENTORIES.keys()]
        inventory_data = {}

        for fname in files:
            warehouse = fname.replace(".json", "")
            path = os.path.join(inventory_folder, fname)
            with open(path) as f:
                inventory_data[warehouse] = json.load(f)

        quantities = []
        for warehouse, records in inventory_data.items():
            for record in records:
                if str(record["id"]) == item_id:
                    quantities.append(record["qty"])
        if not quantities:
            return jsonify({"error": "Item not found"}), 404
        majority_qty = max(set(quantities), key=quantities.count)

        for warehouse in INVENTORIES.keys():
            records = inventory_data[warehouse]
            match = next((r for r in records if str(r["id"]) == item_id), None)
            local_qty = match["qty"] if match else None
            vote = "Approve" if local_qty == majority_qty else "Reject"
            votes.append({"warehouse": warehouse, "vote": vote})

            ID = INVENTORIES[warehouse]["ID"]
            r = INVENTORIES[warehouse]["r"]
            g = generate_g(ID)
            t = generate_t(r)
            h = md5_hash(str(t) + str(majority_qty))

            if vote == "Approve":
                s = (g * powmod(r, h, n_pkg)) % n_pkg
                g_list.append(g)
                s_list.append(s)
                signed_nodes.append(warehouse)

            warehouse_details.append({
                "warehouse": warehouse,
                "ID": ID,
                "r": r,
                "g": g,
                "t": t,
                "h": h,
                "vote": vote,
                "s_partial": s if vote == "Approve" else None
            })

        if not s_list:
            return jsonify({"error": "No valid signatures, consensus failed"}), 400

        s_agg = compute_aggregate(s_list)
        g_agg = compute_aggregate(g_list)
        t_total = compute_aggregate([generate_t(INVENTORIES[w]["r"]) for w in signed_nodes])
        h_total = md5_hash(str(t_total) + str(majority_qty))

        lhs = powmod(s_agg, e_pkg, n_pkg)
        rhs = (g_agg * powmod(t_total, h_total, n_pkg)) % n_pkg
        valid = lhs == rhs

        encrypted_qty = rsa_encrypt(majority_qty, po_e, po_n)
        decrypted_qty = rsa_decrypt(encrypted_qty, po_d, po_n)

        return jsonify({
            "item_id": item_id,
            "majority_qty": majority_qty,
            "signed_nodes": signed_nodes,
            "votes": votes,
            "warehouse_details": warehouse_details,
            "multi_signature": s_agg,
            "verification": {"lhs": lhs, "rhs": rhs, "valid": valid},
            "encrypted_quantity": str(encrypted_qty),
            "decrypted_quantity": decrypted_qty
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
