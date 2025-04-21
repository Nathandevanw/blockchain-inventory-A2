from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib

app = Flask(__name__)
CORS(app)

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

# Inventory IDs and Randoms
IDs = {"Inventory_A": 126, "Inventory_B": 127, "Inventory_C": 128, "Inventory_D": 129}
Randoms = {"Inventory_A": 621, "Inventory_B": 721, "Inventory_C": 821, "Inventory_D": 921}
warehouses = ["Inventory_A", "Inventory_B", "Inventory_C", "Inventory_D"]

# Inventory Data
item_db = {
    "001": {"qty": 32, "price": 12, "location": "D"},
    "002": {"qty": 20, "price": 14, "location": "C"},
    "003": {"qty": 22, "price": 16, "location": "B"},
    "004": {"qty": 12, "price": 18, "location": "A"}
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

@app.route("/query_item", methods=["POST"])
def query():
    item_id = request.json.get("item_id")
    item = item_db.get(item_id)
    if not item:
        return jsonify({"error": "Item ID not found"}), 404

    g_list, t_list, s_list = [], [], []
    result_details = []

    for name in warehouses:
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
            "t_i": t
        })

    t = compute_aggregate_t(t_list)
    h = md5_hash(str(t) + str(item["qty"]))

    for i, name in enumerate(warehouses):
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
        "item": item,
        "signature": str(s),
        "t": str(t),
        "hash": str(h),
        "valid": valid,
        "encrypted_quantity": str(encrypted),
        "decrypted_quantity": str(decrypted),
        "lhs": str(lhs),
        "rhs": str(rhs),
        "warehouses": result_details
    })

if __name__ == "__main__":
    app.run(debug=True)