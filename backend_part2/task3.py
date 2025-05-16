# Import Python modules for web server, JSON handling, hashing, and CORS policy
import json #  JSON file handling
import hashlib # Cryptographic operations
from flask import Flask, request, jsonify # Web API development using Flask
from flask_cors import CORS # Cross-origin requests from the frontend interface

# Initialize a new Flask web application instance
app = Flask(__name__)
# This allows frontend JavaScript (like from localhost) to send/receive requests to this backend
CORS(app)
# This function opens a file from the provided path, reads it, and returns its JSON content as a dictionary.
# We use it throughout the program to fetch saved keys, warehouse info, and protocol results.
def read_json(path):
    with open(path, 'r') as f:
        return json.load(f)
# This function saves any given dictionary into a file in readable JSON format using 4-space indentation.
# It's used often to write updated keys, warehouse data, and encryption/signature results.
def write_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

# Load pre-generated values of p, q, and e for PKG and compute the RSA private key (d),
# the modulus n = p * q, and phi = (p - 1)(q - 1). These are saved for later use in signing.
pkg_keys = read_json("backend_part2/pkg_keys.json")
po_keys = read_json("backend_part2/procurement_officer_keys.json")

# Add the computed fields back to the JSON object and save it to the file
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
# Load the Officer's public key components (p, q, e) and derive private key d
p_po = int(po_keys["p"])
q_po = int(po_keys["q"])
e_po = int(po_keys["e"])
n_po = p_po * q_po
phi_po = (p_po - 1) * (q_po - 1)
d_po = pow(e_po, -1, phi_po)
po_keys["d"] = d_po
po_keys["n"] = n_po
write_json("backend_part2/procurement_officer_keys.json", po_keys)
# List of all inventory node labels used in our distributed ledger system.
# Each warehouse has its own ID, random value, and will participate in signing.
warehouses = ["Inventory_A", "Inventory_B", "Inventory_C", "Inventory_D"]
# Mapping each warehouse name to its data file containing cryptographic values (ID, g, tᵢ, sᵢ)
warehouse_files = {
    "Inventory_A": "backend_part2/Inventory_A_ID.json",
    "Inventory_B": "backend_part2/Inventory_B_ID.json",
    "Inventory_C": "backend_part2/Inventory_C_ID.json",
    "Inventory_D": "backend_part2/Inventory_D_ID.json"
}
# This is to read the quantity input from task 1 and 2
inventories = {
    "Inventory_A": read_json("backend_part1/inventory_data/NodeA.json"),
    "Inventory_B": read_json("backend_part1/inventory_data/NodeB.json"),
    "Inventory_C": read_json("backend_part1/inventory_data/NodeC.json"),
    "Inventory_D": read_json("backend_part1/inventory_data/NodeD.json")
}


# Converts a string into an MD5 hash, then converts it into an integer
# This hash is used as the exponent during the partial signature computation
def md5_hash(value):
    return int(hashlib.md5(str(value).encode()).hexdigest(), 16)
# RSA encryption: used by PKG to encrypt quantity with Officer's public key
def rsa_encrypt(m, e, n):
    return pow(int(m), int(e), int(n))
# RSA decryption: used by Officer to recover the message from ciphertext
def rsa_decrypt(c, d, n):
    return pow(int(c), int(d), int(n))
# Performs modular exponentiation — a core operation in RSA and digital signature math
def powmod(a, b, mod):
    return pow(int(a), int(b), int(mod))

# This function is for the step flow of the query
# Step 1: Collect all IDs from warehouse files
def get_all_ids():
    return {w: int(read_json(warehouse_files[w])["ID"]) for w in warehouses}

# Step 2: PKG computes g = ID^d mod n for each warehouse
def pkg_generate_g():
    ids = get_all_ids()
    g_output = {}  # Collect g values here

    for w in warehouses:
        data = read_json(warehouse_files[w])
        g_val = powmod(ids[w], d_pkg, n_pkg)
        data["g"] = g_val
        write_json(warehouse_files[w], data)
        g_output[w] = g_val  # Store for central file

    # Save all g values to pkg_calculated_g.json
    write_json("backend_part2/pkg_calculated_g.json", g_output)

# Step 3: Each warehouse calculates tᵢ = r^e mod n
def warehouse_t_sharing():
    t_values = {}
    for w in warehouses:
        data = read_json(warehouse_files[w])
        r = int(data["random"])
        t_i = powmod(r, e_pkg, n_pkg)
        data["t_i"] = t_i
        write_json(warehouse_files[w], data)
        t_values[w] = t_i
    return t_values

# Step 4: Each warehouse calculates sᵢ = g × r^h mod n
def warehouse_partial_signature(h, t_values):
    for w in warehouses:
        data = read_json(warehouse_files[w])
        g = int(data["g"])
        r = int(data["random"])
        s_i = (g * powmod(r, h, n_pkg)) % n_pkg
        data["s_i"] = s_i
        write_json(warehouse_files[w], data)

    # Save all sᵢ into each warehouse file
    s_values = {w: int(read_json(warehouse_files[w])["s_i"]) for w in warehouses}
    for w in warehouses:
        data = read_json(warehouse_files[w])
        data["all_s_i"] = s_values
        write_json(warehouse_files[w], data)

# Step 5: PKG calculates the aggregate signature s_total = product(sᵢ) mod n
def calculate_aggregate_signature(data):
    s_total = 1
    for val in data["all_s_i"].values():
        s_total = (s_total * int(val)) % n_pkg
    return s_total


# This route handles a POST request to securely query an inventory item
@app.route('/query_item', methods=['POST'])
def query_item():
    # Step 1: Extract item ID from request JSON
    item_id = request.json.get("item_id")
    found = None        #  store the matched item

    # Step 2: Search for the item across all inventory nodes
    for w in warehouses:
        node = read_json(f"backend_part1/inventory_data/Node{w[-1]}.json")
        for item in node:
            if item["id"] == item_id:
                found = item
                break
        if found:
            break

    # Step 3: Run Step 1 of Harn Protocol – generate g values from warehouse IDs
    pkg_generate_g()

    # Step 4: Run Step 2 – generate tᵢ values for each warehouse (tᵢ = r^e mod n)
    t_values = warehouse_t_sharing()

    # Step 5: Compute the total t value as a product of all tᵢ mod n
    t_total = 1
    for t in t_values.values():
        t_total = (t_total * t) % n_pkg

    # Step 6: Extract quantity of the item and calculate hash
    quantity = int(found["qty"])
    h = md5_hash(str(t_total) + str(quantity))  # Hash = MD5(t_total || qty)

    # Step 7: Compute sᵢ = g * r^h mod n for each warehouse
    warehouse_partial_signature(h, t_values)

    # Step 8: Re-load warehouse data and compute s_total (product of all sᵢ)
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

    # Step 9: Check that all s_total values are identical across warehouses
    all_s_totals = [w["s_total"] for w in warehouse_results]
    consensus = all(x == all_s_totals[0] for x in all_s_totals)

    # Step 10: Save the response message (used for signature verification)
    response_msg = {
        "m": quantity,
        "t_total": t_total,
        "s_total": all_s_totals[0]
    }
    write_json("backend_part2/response_message.json", response_msg)

    # Step 11: PKG encrypts the message (quantity) for Officer using RSA
    encrypted_m = str(rsa_encrypt(quantity, e_po, n_po))
    decrypted_m = str(rsa_decrypt(encrypted_m, d_po, n_po))
    encryption_result = {
        "Qty": quantity,
        "encrypted_quantity": encrypted_m,
        "decrypted_quantity": decrypted_m
    }
    write_json("backend_part2/encryption_result.json", encryption_result)

    # Step 12: Signature verification (LHS = s_total^e, RHS = ∏ID * t_total^h)
    ids = get_all_ids()
    lhs = powmod(all_s_totals[0], e_pkg, n_pkg)
    id_product = 1
    for v in ids.values():
        id_product = (id_product * v) % n_pkg
    rhs = (id_product * powmod(t_total, h, n_pkg)) % n_pkg
    valid = lhs == rhs

    # Save lhs, rhs, and validity to Officer key file
    po_keys["lhs"] = str(lhs)
    po_keys["rhs"] = str(rhs)
    po_keys["valid"] = valid
    write_json("backend_part2/procurement_officer_keys.json", po_keys)

    # Step 13: Save all s_total values to pkg_s_total.json
    s_total_dict = {w["warehouse"]: w["s_total"] for w in warehouse_results}
    write_json("backend_part2/pkg_s_total.json", s_total_dict)

    # Step 14: Return the full response back to frontend
    return jsonify({
        "pkg_keys": {
            "p": pkg_keys["p"],
            "q": pkg_keys["q"],
            "e": pkg_keys["e"],
            "d": pkg_keys["d"],
            "n": pkg_keys["n"]
        },
        "po_keys": {
            "e": po_keys["e"],
            "d": po_keys["d"],
            "n": po_keys["n"]
        },
        "phi_n": pkg_keys["phi_n"],
        "item": {
            "qty": encryption_result["Qty"],          # From saved encryption file
        },
        "itemId": item_id,
        "encrypted_quantity":  encryption_result["encrypted_quantity"],
        "decrypted_quantity": encryption_result["decrypted_quantity"],
        "consensus": consensus,    #  True if all warehouses agree on s_total
        "lhs": str(lhs),           # Left-hand side of signature verification
        "rhs": str(rhs),           # Right-hand side of signature verification
        "valid": valid,            # True if lhs == rhs
        "warehouses": warehouse_results  # All warehouse signatures and values
    })

if __name__ == '__main__':
    app.run(debug=True)
