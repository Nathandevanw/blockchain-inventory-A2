from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib

app = Flask(__name__)
CORS(app)

# -- PKG key generation (used to simulate signing + verification) --
p_pkg = 1004162036461488639338597000466705179253226703
q_pkg = 950133741151267522116252385927940618264103623
e_pkg = 973028207197278907211
n_pkg = p_pkg * q_pkg
phi_pkg = (p_pkg - 1) * (q_pkg - 1)
d_pkg = pow(e_pkg, -1, phi_pkg)

# -- Procurement Officer’s RSA keys (used for final encryption) --
po_p = 1080954735722463992988394149602856332100628417
po_q = 1158106283320086444890911863299879973542293243
po_e = 106506253943651610547613
po_n = po_p * po_q
po_phi = (po_p - 1) * (po_q - 1)
po_d = pow(po_e, -1, po_phi)

# -- Warehouses and their values --
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
warehouse_list = list(IDs.keys())

# -- Static inventory data (shared across all nodes) --
item_db = {
    "001": {"qty": 32, "price": 12, "location": "D"},
    "002": {"qty": 20, "price": 14, "location": "C"},
    "003": {"qty": 22, "price": 16, "location": "B"},
    "004": {"qty": 12, "price": 18, "location": "A"}
}

# -- Just a helper to do MD5 + convert to int --
def hash_md5(val):
    return int(hashlib.md5(str(val).encode()).hexdigest(), 16)

# -- RSA-style encryption --
def encrypt_rsa(msg, e, n):
    m = int.from_bytes(str(msg).encode(), 'big')
    return pow(m, e, n)

def decrypt_rsa(ciphertext, d, n):
    m = pow(ciphertext, d, n)
    return int.from_bytes(m.to_bytes((m.bit_length() + 7) // 8, 'big'), 'big')

# -- Simple power mod wrapper for clarity --
def modpow(x, y, mod):
    return pow(x, y, mod)

# -- Generate g = ID^d mod n for each warehouse --
def get_g(ID):
    return modpow(ID, d_pkg, n_pkg)

def get_t(r):
    return modpow(r, e_pkg, n_pkg)

def aggregate_product(values):
    result = 1
    for val in values:
        result = (result * val) % n_pkg
    return result

def verify_multi_sig(s, t, h):
    lhs = modpow(s, e_pkg, n_pkg)
    id_product = 1
    for val in IDs.values():
        id_product = (id_product * val) % n_pkg
    rhs = (id_product * modpow(t, h, n_pkg)) % n_pkg
    return lhs == rhs, lhs, rhs

@app.route("/query_item", methods=["POST"])
def handle_query():
    item_id = request.json.get("item_id")
    item = item_db.get(item_id)

    if not item:
        return jsonify({"error": f"Item ID {item_id} not found"}), 404

    # -- Lists to hold pieces from each warehouse --
    g_values, t_values, s_values = [], [], []
    breakdown = []

    # Step 1: Create gᵢ and tᵢ
    for w in warehouse_list:
        ID = IDs[w]
        r = Randoms[w]

        g_i = get_g(ID)
        t_i = get_t(r)

        g_values.append(g_i)
        t_values.append(t_i)

        breakdown.append({
            "warehouse": w,
            "ID": ID,
            "r": r,
            "g": g_i,
            "t_i": t_i
        })

    # Step 2: Combine all tᵢ to compute t, then hash(t || msg)
    t = aggregate_product(t_values)
    h = hash_md5(str(t) + str(item["qty"]))

    # Step 3: Generate sᵢ = gᵢ * rᵢ^h, then combine to full signature
    for idx, w in enumerate(warehouse_list):
        r = Randoms[w]
        s_i = (g_values[idx] * modpow(r, h, n_pkg)) % n_pkg
        s_values.append(s_i)
        breakdown[idx]["s_i"] = s_i

    # Final signature s = product of all sᵢ
    s = aggregate_product(s_values)

    # Step 4: Encrypt quantity using PO key
    encrypted_msg = encrypt_rsa(item["qty"], po_e, po_n)
    decrypted_msg = decrypt_rsa(encrypted_msg, po_d, po_n)

    # Step 5: Verify signature
    is_valid, lhs, rhs = verify_multi_sig(s, t, h)

    return jsonify({
        "itemId": item_id,
        "item": item,
        "signature": str(s),
        "t": str(t),
        "hash": str(h),
        "valid": is_valid,
        "encrypted_quantity": str(encrypted_msg),
        "decrypted_quantity": str(decrypted_msg),
        "lhs": str(lhs),
        "rhs": str(rhs),
        "warehouses": breakdown
    })

if __name__ == "__main__":
    app.run(debug=True)
