from flask import Flask, request, jsonify, render_template
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

# Caesar Cipher
def caesar_cipher(text, shift, action='encrypt'):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + (shift if action == 'encrypt' else -shift)) % 26 + shift_base)
        else:
            result += char
    return result

# Vigenère Cipher
def vigenere_cipher(text, key, action='encrypt'):
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)].upper()) - 65
            if action == 'decrypt':
                shift = -shift
            if char.isupper():
                result.append(chr((ord(char) - 65 + shift) % 26 + 65))
            else:
                result.append(chr((ord(char) - 97 + shift) % 26 + 97))
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)

# AES Encryption/Decryption
def aes_cipher(text, action='encrypt'):
    key = b'Sixteen byte key'  # 16-byte key for AES
    cipher = AES.new(key, AES.MODE_EAX)
    if action == 'encrypt':
        ciphertext, tag = cipher.encrypt_and_digest(text.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
    else:
        data = base64.b64decode(text)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# RSA Encryption/Decryption
private_key = RSA.generate(2048)
public_key = private_key.publickey()

def rsa_cipher(text, action='encrypt'):
    if action == 'encrypt':
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_text = cipher_rsa.encrypt(text.encode())
        return base64.b64encode(encrypted_text).decode('utf-8')
    else:
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_text = cipher_rsa.decrypt(base64.b64decode(text))
        return decrypted_text.decode('utf-8')

# XOR Cipher
def xor_cipher(text, key):
    result = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))
    return result

# Route to fetch cipher details
@app.route('/cipher-details', methods=['GET'])
def cipher_details():
    cipher_type = request.args.get('cipher')

    if cipher_type == 'caesar':
        return jsonify({'key': 'Default key is required from user (e.g., 3 for Caesar Cipher)'})
    elif cipher_type == 'vigenere':
        return jsonify({'key': 'Default key is required from user (e.g., "KEY" for Vigenère Cipher)'})
    elif cipher_type == 'aes':
        key = b'Sixteen byte key'  # Hardcoded AES key
        return jsonify({'key': key.decode('utf-8'), 'note': 'AES key is hardcoded in the backend'})
    elif cipher_type == 'rsa':
        public_key_pem = public_key.export_key().decode('utf-8')
        private_key_pem = private_key.export_key().decode('utf-8')
        return jsonify({'public_key': public_key_pem, 'private_key': private_key_pem})
    elif cipher_type == 'xor':
        return jsonify({'key': 'Default key is required from user (e.g., "KEY" for XOR Cipher)'})
    else:
        return jsonify({'error': 'Invalid cipher type'}), 400

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    text = data['text']
    cipher_type = data['cipher']
    key = data.get('key', 'KEY')  # Default key if not provided
    
    if cipher_type == 'caesar':
        result = caesar_cipher(text, int(key), 'encrypt')  # Convert key to int for Caesar Cipher
    elif cipher_type == 'vigenere':
        result = vigenere_cipher(text, key, 'encrypt')
    elif cipher_type == 'aes':
        result = aes_cipher(text, 'encrypt')
    elif cipher_type == 'rsa':
        result = rsa_cipher(text, 'encrypt')
    elif cipher_type == 'xor':
        result = base64.b64encode(xor_cipher(text, key).encode()).decode('utf-8')
    else:
        return jsonify({'error': 'Invalid cipher type'}), 400
    
    return jsonify({'result': result})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    text = data['text']
    cipher_type = data['cipher']
    key = data.get('key', 'KEY')  # Default key if not provided
    
    if cipher_type == 'caesar':
        result = caesar_cipher(text, int(key), 'decrypt')  # Convert key to int for Caesar Cipher
    elif cipher_type == 'vigenere':
        result = vigenere_cipher(text, key, 'decrypt')
    elif cipher_type == 'aes':
        result = aes_cipher(text, 'decrypt')
    elif cipher_type == 'rsa':
        result = rsa_cipher(text, 'decrypt')
    elif cipher_type == 'xor':
        result = xor_cipher(base64.b64decode(text).decode(), key)
    else:
        return jsonify({'error': 'Invalid cipher type'}), 400
    
    return jsonify({'result': result})

if __name__ == "__main__":
    app.run(debug=True)