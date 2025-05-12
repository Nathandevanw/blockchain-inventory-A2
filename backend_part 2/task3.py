from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib, json, os

app = Flask(__name__)
CORS(app)

def load_keys():
    with open("PKG.json") as f:
        PKG = json.load(f)
    with open("Officer.json") as f:
        PO = json.load(f)
    with open("Inventory_Identity.json") as f:
        INVENTORIES = json.load(f)
    return {"PKG": PKG, "ProcurementOfficer": PO, "Inventories": INVENTORIES}

def load_pkg_keys(PKG):
    p, q, e = PKG["p"], PKG["q"], PKG["e"]
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return p, q, e, n, d

def load_po_keys(PO):
    p, q, e = PO["p"], PO["q"], PO["e"]
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return p, q, e, n, d

def sha256_hash(val):
    return int(hashlib.sha256(str(val).encode()).hexdigest(), 16)

def powmod(a, b, mod):
    return pow(a, b, mod)

def rsa_encrypt(msg, e, n):
    return pow(int.from_bytes(str(msg).encode(), 'big'), e, n)

def rsa_decrypt(cipher, d, n):
    m = pow(cipher, d, n)
    return int.from_bytes(m.to_bytes((m.bit_length() + 7) // 8, 'big'), 'big')

def generate_g(ID, d_pkg, n_pkg):
    return powmod(ID, d_pkg, n_pkg)

def generate_t(r, e_pkg, n_pkg):
    return powmod(r, e_pkg, n_pkg)

def compute_aggregate(values, n_pkg):
    result = 1
    for v in values:
        result = (result * v) % n_pkg
    return result

def get_local_quantity(warehouse, item_id, inventory_data):
    for record in inventory_data[warehouse]:
        if str(record["id"]) == item_id:
            return record["qty"]
    return None

def most_common_value(values):
    return max(set(values), key=values.count)

@app.route("/query_item", methods=["POST"])
def query_item():
    try:
        keys = load_keys()
        PKG = keys["PKG"]
        PO = keys["ProcurementOfficer"]
        INVENTORIES = keys["Inventories"]

        p_pkg, q_pkg, e_pkg, n_pkg, d_pkg = load_pkg_keys(PKG)
        po_p, po_q, po_e, po_n, po_d = load_po_keys(PO)

        req = request.get_json()
        item_id = str(req.get("item_id")).strip()
        votes = []
        signed_nodes = []
        warehouse_details = []
        g_list, s_list = [], []

        inventory_folder = "backend_part1/inventory_data"
        files = [f"{w}.json" for w in INVENTORIES.keys()]
        inventory_data = {}
        for fname in files:
            warehouse = fname.replace(".json", "")
            path = os.path.join(inventory_folder, fname)
            with open(path) as f:
                inventory_data[warehouse] = json.load(f)

        quantities = []
        for warehouse in INVENTORIES.keys():
            qty = get_local_quantity(warehouse, item_id, inventory_data)
            if qty is not None:
                quantities.append(qty)

        if not quantities:
            return jsonify({"error": "Item not found"}), 404

        majority_qty = most_common_value(quantities)

        for warehouse in INVENTORIES.keys():
            local_qty = get_local_quantity(warehouse, item_id, inventory_data)
            vote = "Approve" if local_qty == majority_qty else "Reject"
            votes.append({"warehouse": warehouse, "vote": vote})

            ID = INVENTORIES[warehouse]["ID"]
            r = INVENTORIES[warehouse]["r"]
            g = generate_g(ID, d_pkg, n_pkg)
            t = generate_t(r, e_pkg, n_pkg)
            h = sha256_hash(str(t) + str(majority_qty))

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

        approves = sum(1 for v in votes if v["vote"] == "Approve")
        if approves < 3:
            return jsonify({"error": "Consensus failed"}), 400

        s_agg = compute_aggregate(s_list, n_pkg)
        g_agg = compute_aggregate(g_list, n_pkg)
        t_total = compute_aggregate([generate_t(INVENTORIES[w]["r"], e_pkg, n_pkg) for w in signed_nodes], n_pkg)
        h_total = sha256_hash(str(t_total) + str(majority_qty))

        lhs = powmod(s_agg, e_pkg, n_pkg)
        rhs = (g_agg * powmod(t_total, h_total, n_pkg)) % n_pkg
        valid = lhs == rhs

        encrypted_qty = rsa_encrypt(majority_qty, po_e, po_n)
        decrypted_qty = rsa_decrypt(encrypted_qty, po_d, po_n)

        debug_data = {
            "PKG": {"p": p_pkg, "q": q_pkg, "e": e_pkg, "n": n_pkg, "d": d_pkg},
            "Officer": {"p": po_p, "q": po_q, "e": po_e, "n": po_n, "d": po_d},
            "signed_nodes": signed_nodes,
            "g_list": g_list,
            "s_list": s_list,
            "s_agg": s_agg,
            "g_agg": g_agg,
            "t_total": t_total,
            "h_total": h_total,
            "lhs": lhs,
            "rhs": rhs
        }

        return jsonify({
            "item_id": item_id,
            "majority_qty": majority_qty,
            "signed_nodes": signed_nodes,
            "votes": votes,
            "warehouse_details": warehouse_details,
            "multi_signature": s_agg,
            "verification": {"lhs": lhs, "rhs": rhs, "valid": valid},
            "encrypted_quantity": str(encrypted_qty),
            "decrypted_quantity": decrypted_qty,
            "debug_data": debug_data
        })

    except Exception:
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=True)
