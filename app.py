from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from datetime import datetime

app = Flask(__name__)

def encrypt_with_rsa(public_key_str, plain_text):
    # Formatear la clave pública para agregar los saltos necesarios
    formatted_public_key = f"-----BEGIN PUBLIC KEY-----\n{public_key_str}\n-----END PUBLIC KEY-----"

    # Cargar la clave pública desde la cadena
    public_key = RSA.import_key(formatted_public_key)

    # Crear el cifrador utilizando RSA/ECB/OAEP con SHA-1 para el hash y MGF1 para la generación de máscaras
    cipher = PKCS1_OAEP.new(public_key)

    # Encriptar el texto plano
    encrypted_text = cipher.encrypt(plain_text.encode('utf-8'))

    # Codificar el texto encriptado en base64
    encrypted_text_base64 = base64.b64encode(encrypted_text).decode('utf-8')

    # Formatear la salida en un formato compatible con la autorización
    formatted_output = {"encrypted_text": encrypted_text_base64}
    return formatted_output

@app.route('/encrypt', methods=['POST'])
def encrypt_text():
    # Obtener los datos del cuerpo de la solicitud como JSON
    request_data = request.json

    # Obtener la clave pública y el valor adicional de los datos JSON
    public_key = request_data.get('public_key')
    extra_key = request_data.get('extrakey')

    # Obtener la fecha y hora actual
    formatted_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # Texto plano que vamos a encriptar
    plain_text = f"{extra_key}~{formatted_date}.734"

    # Encriptar el texto con la clave pública proporcionada
    encrypted_text = encrypt_with_rsa(public_key, plain_text)

    # Devolver el texto encriptado como respuesta JSON
    return jsonify(encrypted_text)

if __name__ == '__main__':
    app.run(debug=True)
# from flask import Flask, request, jsonify
# import os
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# import base64
# from datetime import datetime

# app = Flask(__name__)

# def encrypt_with_rsa(public_key_str, plain_text):
#     # Formatear la clave pública para agregar los saltos necesarios
#     formatted_public_key = f"-----BEGIN PUBLIC KEY-----\n{public_key_str}\n-----END PUBLIC KEY-----"

#     # Cargar la clave pública desde la cadena
#     public_key = RSA.import_key(formatted_public_key)

#     # Crear el cifrador utilizando RSA/ECB/OAEP con SHA-1 para el hash y MGF1 para la generación de máscaras
#     cipher = PKCS1_OAEP.new(public_key)

#     # Encriptar el texto plano
#     encrypted_text = cipher.encrypt(plain_text.encode('utf-8'))

#     # Codificar el texto encriptado en base64
#     encrypted_text_base64 = base64.b64encode(encrypted_text).decode('utf-8')

#     # Formatear la salida en un formato compatible con la autorización
#     formatted_output = {"encrypted_text": encrypted_text_base64}
#     return formatted_output

# @app.route('/encrypt', methods=['POST'])
# def encrypt_text():
#     # Obtener los datos del cuerpo de la solicitud como JSON
#     request_data = request.json

#     # Obtener la clave pública y el valor adicional de los datos JSON
#     public_key = request_data.get('public_key')
#     extra_key = request_data.get('extrakey')

#     # Obtener la fecha y hora actual
#     formatted_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

#     # Texto plano que vamos a encriptar
#     plain_text = f"{extra_key}~{formatted_date}.734"

#     # Encriptar el texto con la clave pública proporcionada
#     encrypted_text = encrypt_with_rsa(public_key, plain_text)

#     # Devolver el texto encriptado como respuesta JSON
#     return jsonify(encrypted_text)

# if __name__ == '__main__':
#     # Configuración para Heroku
#     port = int(os.environ.get('PORT', 5000))
#     app.run(host='0.0.0.0', port=port)
