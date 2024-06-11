from flask import Flask, request, jsonify
from lib import cbc_decrypt, cbc_encrypt, ctr_encrypt, ctr_decrypt, ecb_encrypt, ecb_decrypt

app = Flask(__name__)

def validate_request_data(data, required_keys):
    missing_keys = [key for key in required_keys if key not in data]
    if missing_keys:
        response = {"error": f"Missing keys in request: {', '.join(missing_keys)}"}
        return response, False
    return {}, True

@app.route('/encrypt/CBC', methods=['POST'])
def encrypt_cbc():
    data = request.json
    response, valid = validate_request_data(data, ['name', 'key', 'plaintext'])
    if not valid:
        return jsonify(response), 400

    name = data['name']
    key = data['key'].encode()
    plaintext = data['plaintext'].encode()
    iv = b"JEODB34DOlgSHuRP"
    ciphertext = cbc_encrypt(plaintext, key, iv)
    return jsonify({'res': ciphertext.hex(), "name": name}), 200

@app.route('/decrypt/CBC', methods=['POST'])
def decrypt_cbc():
    data = request.json
    response, valid = validate_request_data(data, ['name', 'key', 'ciphertext'])
    if not valid:
        return jsonify(response), 400

    name = data['name']
    key = data['key'].encode()
    ciphertext = bytes.fromhex(data['ciphertext'])
    iv = b"JEODB34DOlgSHuRP"
    decrypted_plaintext = cbc_decrypt(ciphertext, key, iv)
    return jsonify({'res': decrypted_plaintext.decode(), "name": name}), 200

@app.route('/encrypt/CTR', methods=['POST'])
def encrypt_ctr():
    data = request.json
    response, valid = validate_request_data(data, ['name', 'key', 'plaintext'])
    if not valid:
        return jsonify(response), 400

    name = data['name']
    key = data['key'].encode()
    plaintext = data['plaintext'].encode()
    nonce = b"ABJ3k6lq"
    ciphertext = ctr_encrypt(plaintext, key, nonce)
    return jsonify({'res': ciphertext.hex(), "name": name}), 200

@app.route('/decrypt/CTR', methods=['POST'])
def decrypt_ctr():
    data = request.json
    response, valid = validate_request_data(data, ['name', 'key', 'ciphertext'])
    if not valid:
        return jsonify(response), 400

    name = data['name']
    key = data['key'].encode()
    ciphertext = bytes.fromhex(data['ciphertext'])
    nonce = b"ABJ3k6lq"
    decrypted_plaintext = ctr_decrypt(ciphertext, key, nonce)
    return jsonify({'res': decrypted_plaintext.decode(), "name": name}), 200

@app.route('/encrypt/ECB', methods=['POST'])
def encrypt_ecb():
    data = request.json
    response, valid = validate_request_data(data, ['name', 'key', 'plaintext'])
    if not valid:
        return jsonify(response), 400

    name = data['name']
    key = data['key'].encode()
    plaintext = data['plaintext'].encode()
    ciphertext = ecb_encrypt(plaintext, key)
    return jsonify({'res': ciphertext.hex(), "name": name}), 200

@app.route('/decrypt/ECB', methods=['POST'])
def decrypt_ecb():
    data = request.json
    response, valid = validate_request_data(data, ['name', 'key', 'ciphertext'])
    if not valid:
        return jsonify(response), 400

    name = data['name']
    key = data['key'].encode()
    ciphertext = bytes.fromhex(data['ciphertext'])
    decrypted_plaintext = ecb_decrypt(ciphertext, key)
    return jsonify({'res': decrypted_plaintext.decode(), "name": name}), 200

if __name__ == "__main__":
    app.run(debug=True)
