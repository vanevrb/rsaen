from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from datetime import datetime

app = Flask(__name__)

def encrypt_with_rsa(public_key_str, plain_text):
    formatted_public_key = f"-----BEGIN PUBLIC KEY-----\n{public_key_str}\n-----END PUBLIC KEY-----"

    public_key = RSA.import_key(formatted_public_key)

    cipher = PKCS1_OAEP.new(public_key)

    encrypted_text = cipher.encrypt(plain_text.encode('utf-8'))

    encrypted_text_base64 = base64.b64encode(encrypted_text).decode('utf-8')

    formatted_output = {"encrypted_text": encrypted_text_base64}
    return formatted_output

@app.route('/encrypt', methods=['POST'])
def encrypt_text():
    request_data = request.json

    public_key = request_data.get('public_key')
    extra_key = request_data.get('extrakey')

    formatted_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    plain_text = f"{extra_key}~{formatted_date}.734"

    encrypted_text = encrypt_with_rsa(public_key, plain_text)

    return jsonify(encrypted_text)

if __name__ == '__main__':
    app.run(debug=True)
