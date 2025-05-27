from flask import Flask, request, jsonify
import psycopg2
import json
from urllib.parse import urlparse
from collections import OrderedDict
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from functools import wraps
from jose import jwt
import requests

app = Flask(__name__)

# AWS Cognito Config
COGNITO_REGION = "ap-south-1"
USER_POOL_ID = "ap-south-1_s6Ewf67Mp"
APP_CLIENT_ID = "7vt5a6u8hvsgsg6h2bvh0kbpuf"

JWKS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json"

# Cache JWKS keys
jwks = requests.get(JWKS_URL).json()

def get_public_key(token):
    headers = jwt.get_unverified_headers(token)
    kid = headers.get("kid")
    key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
    if not key:
        raise Exception("Public key not found in JWKS")
    return key

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", None)
        if not auth_header:
            return jsonify({"error": "Authorization header missing"}), 401

        parts = auth_header.split()
        if len(parts) != 2 or parts[0] != "Bearer":
            return jsonify({"error": "Invalid authorization header"}), 401

        token = parts[1]

        try:
            key = get_public_key(token)
            public_key = jwt.construct_rsa_key(key)
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=APP_CLIENT_ID,
                issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{USER_POOL_ID}",
            )
            # You can access claims if needed, e.g., print(claims)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.JWTClaimsError:
            return jsonify({"error": "Invalid claims"}), 401
        except Exception as e:
            return jsonify({"error": "Token validation error", "message": str(e)}), 401

        return f(*args, **kwargs)
    return decorated

def decrypt(encrypted_text, encryption_key="your-32-byte-secret-key"):
    secret_key = hashlib.sha256(encryption_key.encode()).digest()
    iv_hex, encrypted_hex = encrypted_text.split(':')
    iv = bytes.fromhex(iv_hex)
    encrypted_data = bytes.fromhex(encrypted_hex)
    cipher = Cipher(algorithms.AES(secret_key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(encrypted_data) + decryptor.finalize()).decode('utf-8')

def get_organization_credentials(org_id):
    conn = psycopg2.connect(
        dbname="users",
        user="nis_admin",
        password="12345678",
        host="nisdb.craiyoggkbd6.ap-south-1.rds.amazonaws.com",
        port="5432"
    )
    cur = conn.cursor()
    cur.execute("""SELECT "rdsUrl" FROM "OrganizationDatabase" WHERE id = %s""", (org_id,))
    result = cur.fetchone()
    cur.close()
    conn.close()

    decrypted = decrypt(result[0])
    parsed = urlparse(decrypted)
    return {
        "db_name": parsed.path.lstrip("/"),
        "db_user": parsed.username,
        "db_password": parsed.password,
        "db_host": parsed.hostname,
        "db_port": parsed.port
    }

def get_db_connection(org_id):
    config = get_organization_credentials(org_id)
    if not config:
        raise Exception("Invalid org_id or credentials")
    return psycopg2.connect(
        dbname=config['db_name'],
        user=config['db_user'],
        password=config['db_password'],
        host=config['db_host'],
        port=config['db_port']
    )

@app.route("/api/normalized-totals", methods=["GET"])
@token_required
def get_normalized_totals():
    org_id = request.args.get("org_id")
    company = request.args.get("company_name")
    start_year = request.args.get("start_year")

    if not org_id or not company or not start_year:
        return jsonify({"error": "Missing org_id, company_name, or start_year"}), 400

    try:
        conn = get_db_connection(org_id)
        cur = conn.cursor()
        cur.execute("""
            SELECT id, brsr_esg_data, startyear, endyear, filename
            FROM brsr_esg_score
            WHERE filename ILIKE %s AND startyear = %s
        """, (f"%{company}%", int(start_year)))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        result = []
        for row in rows:
            id, esg_json, startyear, endyear, filename = row
            normalized = esg_json.get("Normalized Total", {})

            entry = OrderedDict()
            entry["company"] = company
            entry["endyear"] = endyear
            entry["filename"] = filename
            entry["id"] = id
            entry["startyear"] = startyear
            entry["year"] = startyear
            entry["Normalized Total"] = normalized

            result.append(entry)

        return jsonify({"count": len(result), "data": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"message": "pong"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
