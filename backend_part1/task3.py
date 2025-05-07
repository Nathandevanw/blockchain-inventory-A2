from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib, json, os
from consensus import run_consensus_bft  # 🔁 PBFT integration here

app = Flask(__name__)
CORS(app)

# === RSA Key Setup ===

# PKG Keys
p_pkg = 1004162036461488639338597000466705179253226703
q_pkg = 950133741151267522116252385927940618264103623
e_pkg = 973028207197278907211
n_pkg = p_pkg * q_pkg
phi_pkg = (p_pkg - 1) * (q_pkg - 1)
d_pkg = pow(e_pkg, -1, phi_pkg)

# Procurement Officer Keys
po_p = 1080954735722463992988394149602856332100628417
po_q = 1158106283320086444890911863299879973542293243
po_e = 106506253943651610547613
po_n = po_p * po_q
po_phi = (po_p - 1) * (po_q - 1)
po_d = pow(po_e, -1, po_phi)

# Identity & Random Values
IDs = {"Inventory_A": 126, "Inventory_B": 127, "Inventory_C": 128, "Inventory_D": 129}
Randoms = {"Inventory_A": 621, "Inventory_B": 721, "Inventory_C": 821, "Inventory_D": 921}
WAREHOUSES = list(IDs.keys())

# === Helper Functions ===

def md5_hash(val):
    return int(hashlib.md5(str(val).encode()).hexdigest(), 16)

def powmod(a, b, mod): return pow(a, b, mod)

def rsa_encrypt(msg, e, n): return pow(int.from_bytes(str(msg).encode(), 'big'), e, n)

def rsa_decrypt(cipher, d, n):
    m = pow(cipher, d, n)
    return int.from_bytes(m.to_bytes((m.bit_length() + 7) // 8, 'big'), 'big')

def generate_g(ID): return powmod(ID, d_pkg, n_pkg)
def generate_t(r): return powmod(r, e_pkg, n_pkg)

def compute_aggregate(lst): 
    result = 1
    for val in lst: result = (result * val) % n_pkg
    return result

def verify_signature(s, t, h):
    lhs = powmod(s, e_pkg, n_pkg)
    id_prod = 1
    for ID in IDs.values(): id_prod = (id_prod * ID) % n_pkg
    rhs = (id_prod * powmod(t, h, n_pkg)) % n_pkg
    return lhs == rhs, lhs, rhs

# === Flask Route ===

@app.route("/query_item", methods=["POST"])
def query_item():
    req = request.get_json()
    item_id = req.get("item_id")
    matched_records = []

    for node in WAREHOUSES:
        try:
            with open(f"{node}.json") as f:
                records = json.load(f)
                for record in records:
                    if record["id"] == item_id:
                        matched_records.append((node, record))
                        break
        except:
            continue

    if not matched_records:
        return jsonify({"error": "Item not found in any warehouse"}), 404

    # --- PBFT Consensus Start ---
    selected_node, item = matched_records[0]
    record_str = f"{item['id']}-{item['qty']}-{item['price']}-{item['location']}"
    signature = int(item.get("sig", 0))

    def verify_signature_fn(proposer, message, sig):
        with open("keys.json") as f:
            keys = json.load(f)
        e = int(keys[proposer]["e"])
        n = int(keys[proposer]["p"]) * int(keys[proposer]["q"])
        m = int.from_bytes(message.encode(), "big")
        return pow(sig, e, n) == m

    result = run_consensus_bft(selected_node, record_str, signature, verify_signature_fn)

    if not result["consensus"]:
        return jsonify({"error": "PBFT consensus failed", "votes": result}), 403
    # --- PBFT Consensus End ---

    # === Signature Generation ===
    g_list, t_list, s_list = [], [], []
    warehouse_details = []

    for node in WAREHOUSES:
        ID = IDs[node]
        r = Randoms[node]
        g = generate_g(ID)
        t = generate_t(r)
        g_list.append(g)
        t_list.append(t)
        warehouse_details.append({"warehouse": node, "ID": ID, "r": r, "g": g, "t_i": t})

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
        "item_id": item_id,
        "item": item,
        "signature_valid": valid,
        "multi_signature": str(s),
        "t": str(t_agg),
        "h": str(h),
        "lhs": str(lhs),
        "rhs": str(rhs),
        "encrypted_quantity": str(encrypted_qty),
        "decrypted_quantity": str(decrypted_qty),
        "pbft_votes": result,
        "warehouse_details": warehouse_details
    })

if __name__ == "__main__":
    app.run(debug=True)
