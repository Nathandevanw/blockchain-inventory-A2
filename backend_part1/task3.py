from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib, json
from consensus import run_consensus_bft
from task3_key_params.json import (
    p_pkg, q_pkg, e_pkg, n_pkg, d_pkg,
    po_p, po_q, po_e, po_n, po_d,
    IDs, Randoms, NodeKeys, WAREHOUSES
)

app = Flask(__name__)
CORS(app)

# === Helper Functions ===

def md5_hash(val):
    return int(hashlib.md5(str(val).encode()).hexdigest(), 16)

def powmod(a, b, mod): return pow(a, b, mod)

def rsa_encrypt(msg, e, n):
    return pow(int.from_bytes(str(msg).encode(), 'big'), e, n)

def rsa_decrypt(cipher, d, n):
    m = pow(cipher, d, n)
    return int.from_bytes(m.to_bytes((m.bit_length() + 7) // 8, 'big'), 'big')

def generate_g(ID): return powmod(ID, d_pkg, n_pkg)
def generate_t(r): return powmod(r, e_pkg, n_pkg)

def compute_aggregate(vals):
    result = 1
    for v in vals:
        result = (result * v) % n_pkg
    return result

def verify_signature(s, t, h):
    lhs = powmod(s, e_pkg, n_pkg)
    id_prod = 1
    for ID in IDs.values():
        id_prod = (id_prod * ID) % n_pkg
    rhs = (id_prod * powmod(t, h, n_pkg)) % n_pkg
    return lhs == rhs, lhs, rhs

@app.route("/query_item", methods=["POST"])
def query_item():
    try:
        req = request.get_json()
        item_id = req.get("item_id")

        # Load all records from the single combined inventory file
        with open("inventory_records.json") as f:
            all_records = json.load(f)

        matched_records = []
        for record in all_records:
            if record.get("id") == item_id:
                matched_records.append((record["location"], record))

        if not matched_records:
            return jsonify({"error": "Item not found in any warehouse"}), 404

        # PBFT phase
        selected_node, item = matched_records[0]
        record_str = f"{item['id']}-{item['qty']}-{item['price']}-{item['location']}"
        signature = int(item.get("sig", 0))

        def verify_signature_fn(proposer, message, sig):
            k = NodeKeys[proposer]
            n = k["p"] * k["q"]
            e = k["e"]
            m = int.from_bytes(message.encode(), "big")
            return pow(sig, e, n) == m

        pbft_result = run_consensus_bft(selected_node, record_str, signature, verify_signature_fn)

        if not pbft_result["consensus"]:
            return jsonify({"error": "PBFT consensus failed", "pbft_votes": pbft_result}), 403

        g_list, t_list, s_list = [], [], []
        warehouse_details = []

        for node in WAREHOUSES:
            ID = IDs[node]
            r = Randoms[node]
            g = generate_g(ID)
            t = generate_t(r)
            g_list.append(g)
            t_list.append(t)
            warehouse_details.append({
                "warehouse": node,
                "ID": ID,
                "r": r,
                "g": g,
                "t_i": t
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
            "pbft_votes": pbft_result,
            "warehouse_details": warehouse_details
        })

    except Exception as e:
        return jsonify({ "error": str(e) }), 500

if __name__ == "__main__":
    app.run(debug=True)
