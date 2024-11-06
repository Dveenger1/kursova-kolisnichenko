from flask import Flask, request, send_file, render_template, after_this_request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# Generate RSA keys (for demonstration, these should be stored securely in production)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

# Temporary directory to store encrypted/decrypted files
TEMP_DIR = os.getenv("TEMP_DIR", './temp_files')
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    
    # Read file content for encryption
    plaintext = file.read()

    # Encrypt the file content
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Save encrypted content to a file
    encrypted_file_path = os.path.join(TEMP_DIR, 'encrypted_' + file.filename)
    with open(encrypted_file_path, 'wb') as f:
        f.write(ciphertext)

    @after_this_request
    def remove_file(response):
        try:
            os.remove(encrypted_file_path)
        except Exception as e:
            print(f"Error removing file: {e}")
        return response

    # Send the encrypted file back to the user
    return send_file(encrypted_file_path, as_attachment=True, download_name='encrypted_' + file.filename)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    
    # Read encrypted content
    ciphertext = file.read()
    
    try:
        # Decrypt the file content
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Save decrypted content to a file
        decrypted_file_path = os.path.join(TEMP_DIR, 'decrypted_' + file.filename)
        with open(decrypted_file_path, 'wb') as f:
            f.write(plaintext)

        @after_this_request
        def remove_file(response):
            try:
                os.remove(decrypted_file_path)
            except Exception as e:
                print(f"Error removing file: {e}")
            return response

        # Send the decrypted file back to the user
        return send_file(decrypted_file_path, as_attachment=True, download_name='decrypted_' + file.filename)

    except Exception as e:
        return f'Decryption failed: {str(e)}', 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
