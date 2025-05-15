import json, os
from collections import OrderedDict

# Update this if your key files are somewhere else
BASE_DIR = os.path.dirname(__file__)

VALIDATORS = ["NodeA", "NodeB", "NodeC", "NodeD"]

for name in VALIDATORS:
    path = os.path.join(BASE_DIR, f"{name}.json")

    with open(path, 'r', encoding='utf-8') as f:
        key = json.load(f)

    p = int(key["p"])
    q = int(key["q"])
    e = int(key["e"])
    n = p * q
    phin = (p - 1) * (q - 1)
    d = pow(e, -1, phin)

    # Put n, phi, d first
    new_key = OrderedDict()
    new_key["p"] = key["p"]
    new_key["q"] = key["q"]
    new_key["e"] = key["e"]
    new_key["n"] = str(n)
    new_key["phi(n)"] = str(phin)
    new_key["d"] = str(d)

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(new_key, f, indent=2)

    print(f" Updated {name}.json with n, phi, d at the top")