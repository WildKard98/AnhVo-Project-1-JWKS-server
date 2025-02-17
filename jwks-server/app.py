from flask import Flask, jsonify, request
import jwt
import time
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# In-memory storage for keys
keys = {}

# Generate RSA key pair with kid and expiry
def generate_key_pair(kid, expiry):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Extract modulus (n) and exponent (e) from public key
    public_numbers = public_key.public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    # Base64URL-encode n and e
    n_b64 = base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")).decode("utf-8").rstrip("=")
    e_b64 = base64.urlsafe_b64encode(e.to_bytes((e.bit_length() + 7) // 8, byteorder="big")).decode("utf-8").rstrip("=")

    keys[kid] = {
        "private_key": private_pem,
        "public_key": public_pem,
        "n": n_b64,
        "e": e_b64,
        "expiry": expiry
    }

# JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    jwks_keys = []
    for kid, key_info in keys.items():
        if key_info["expiry"] > time.time():  # Only include unexpired keys
            jwks_keys.append({
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": key_info["n"],  # Base64URL-encoded modulus
                "e": key_info["e"]   # Base64URL-encoded exponent
            })
    return jsonify({"keys": jwks_keys})

# Auth endpoint
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired', '').lower() == 'true'
    kid = "expired_kid" if expired else "current_kid"

    if kid not in keys:
        return jsonify({"error": "Key not found"}), 404

    private_key = keys[kid]["private_key"]
    expiry = keys[kid]["expiry"]

    # Create JWT
    payload = {
        "sub": "fake_user",
        "iat": int(time.time()),
        "exp": expiry
    }
    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": kid}  # Include the kid in the JWT header
    )
    return jsonify({"token": token})

# Generate initial keys
generate_key_pair("current_kid", time.time() + 3600)  # Expires in 1 hour
generate_key_pair("expired_kid", time.time() - 3600)  # Already expired

if __name__ == '__main__':
    app.run(port=8080)
