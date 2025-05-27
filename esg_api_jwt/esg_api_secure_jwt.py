from flask import Flask, request, Response, jsonify
import psycopg2
import hashlib
import json
from urllib.parse import urlparse
from collections import OrderedDict
import jwt
from functools import wraps
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import traceback

app = Flask(__name__)

# JWT Setup
JWT_SECRET = "secret981"
JWT_ALGORITHM = "HS256"

# Static AES key provided by team
STATIC_AES_KEY = "your-32-byte-secret-key"

# JWT Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]

        if not token:
            return jsonify({'error': 'Token is missing!'}), 401

        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token!'}), 401

        return f(*args, **kwargs)
    return decorated

# Decrypt encrypted DB connection URL
def decrypt(encrypted_text, encryption_key=STATIC_AES_KEY):
    try:
        secret_key = hashlib.sha256(encryption_key.encode()).digest()
        iv_hex, encrypted_hex = encrypted_text.split(':')
        iv = bytes.fromhex(iv_hex)
        encrypted_data = bytes.fromhex(encrypted_hex)
        cipher = Cipher(algorithms.AES(secret_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(encrypted_data) + decryptor.finalize()).decode('utf-8')
    except Exception as e:
        traceback.print_exc()
        return None

# Fetch org credentials from master DB
def get_organization_credentials(org_id):
    try:
        conn = psycopg2.connect(
            dbname="users",
            user="nis_admin",
            password="12345678",
            host="nisdb.craiyoggkbd6.ap-south-1.rds.amazonaws.com",
            port="5432"
        )
    except Exception as e:
        traceback.print_exc()
        return None

    try:
        with conn.cursor() as cur:
            cur.execute('SELECT "rdsUrl" FROM "OrganizationDatabase" WHERE id = %s', (org_id.strip(),))
            result = cur.fetchone()

            if not result:
                return None

            decrypted = decrypt(result[0])
            if not decrypted:
                return None

            parsed = urlparse(decrypted)

            return {
                "db_host": parsed.hostname,
                "db_port": parsed.port or 5432,
                "db_name": parsed.path.lstrip('/'),
                "db_user": parsed.username,
                "db_password": parsed.password
            }

    except Exception as e:
        traceback.print_exc()
        return None
    finally:
        conn.close()

# Connect to org DB
def get_db_connection(org_id):
    config = get_organization_credentials(org_id)
    if not config:
        raise Exception("Invalid or missing organization ID")
    return psycopg2.connect(
        dbname=config['db_name'],
        user=config['db_user'],
        password=config['db_password'],
        host=config['db_host'],
        port=config['db_port']
    )

# Prioritize ESG scores
def prioritize_scores(esg_data):
    ordered = OrderedDict()
    if "Normalized Total" in esg_data:
        ordered["Normalized Total"] = esg_data["Normalized Total"]
    if "Total" in esg_data:
        ordered["Total"] = esg_data["Total"]
    for key in esg_data:
        if key not in ("Normalized Total", "Total"):
            ordered[key] = esg_data[key]
    return ordered

# ESG API Endpoint
@app.route("/api/brsr-esg-data", methods=["GET"])
@token_required
def get_brsr_esg_data():
    company_name = request.args.get("company_name")
    start_year = request.args.get("start_year")
    org_id = request.args.get("org_id").strip()

    if not all([company_name, start_year, org_id]):
        return Response(json.dumps({"error": "Missing query parameters"}), status=400, mimetype="application/json")

    try:
        conn = get_db_connection(org_id)
        cur = conn.cursor()

        cur.execute("""
            SELECT brsr_esg_data, id, startyear, endyear, filename
            FROM brsr_esg_score
            WHERE filename ILIKE %s AND startyear = %s
        """, (f"%{company_name}%", int(start_year)))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        if not rows:
            return Response(json.dumps({"error": "No data found"}), status=404, mimetype="application/json")

        results = []
        for row in rows:
            esg_data = prioritize_scores(row[0])
            results.append(OrderedDict([
                ("id", row[1]),
                ("filename", row[4]),
                ("startyear", row[2]),
                ("endyear", row[3]),
                ("brsr_esg_data", esg_data)
            ]))

        return Response(json.dumps({"count": len(results), "data": results}, indent=2), mimetype="application/json")

    except Exception as e:
        traceback.print_exc()
        return Response(json.dumps({"error": str(e)}), status=500, mimetype="application/json")

# Health check endpoint
@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"message": "pong"})

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
