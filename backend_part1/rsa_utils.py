"""
rsa_utils.py
Author: Part 1 Owner (RSA & Consensus)

This file handles RSA key generation, signing, and verification.
"""

def generate_keys(p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return {"public": (e, n), "private": (d, n)}

def sign_record(message, private_key):
    d, n = private_key
    return pow(int.from_bytes(message.encode(), 'big'), d, n)

def verify_signature(message, signature, public_key):
    e, n = public_key
    m2 = pow(signature, e, n)
    return m2 == int.from_bytes(message.encode(), 'big')
