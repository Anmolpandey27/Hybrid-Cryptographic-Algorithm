from flask import Flask, request, render_template
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
import boto3

app = Flask(__name__)

# AWS S3 configurations
S3_BUCKET_NAME = 'flaskcryptoapp'
S3_OBJECT_KEY = 'encrypted_message.txt'
AWS_REGION = 'us-east-1'
AWS_ACCESS_KEY_ID = 'AKIA4VOQKTVMD3WNOZVA'
AWS_SECRET_ACCESS_KEY = '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'

# Initialize boto3 client for S3
s3 = boto3.client(
    's3',
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

class HybridCryptosystem:
    def __init__(self):
        self.backend = default_backend()
        self.curve = ec.SECP256R1()

    def generate_keys(self):
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    def aes_encrypt(self, plaintext, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def aes_decrypt(self, ciphertext, key):
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        try:
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
            return plaintext.decode()
        except Exception as e:
            return "Integrity Breached"

    def ecdh_key_exchange(self, private_key, peer_public_key):
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_key

    def hybrid_encrypt(self, plaintext, peer_public_key):
        private_key, own_public_key = self.generate_keys()
        shared_key = self.ecdh_key_exchange(private_key, peer_public_key)
        ciphertext = self.aes_encrypt(plaintext, shared_key)
        return own_public_key, ciphertext, private_key

    def hybrid_decrypt(self, own_private_key, sender_public_key, ciphertext):
        shared_key = self.ecdh_key_exchange(own_private_key, sender_public_key)
        plaintext = self.aes_decrypt(ciphertext, shared_key)
        return plaintext

cryptosystem = HybridCryptosystem()
recipient_private_key = None
sender_public_key = None

@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    global recipient_private_key, sender_public_key
    if request.method == 'POST':
        plaintext = request.form['plaintext'].encode()
        recipient_private_key, recipient_public_key = cryptosystem.generate_keys()
        sender_public_key, ciphertext, _ = cryptosystem.hybrid_encrypt(plaintext, recipient_public_key)
        encrypted_text = ciphertext.hex()
        s3.put_object(Body=encrypted_text, Bucket=S3_BUCKET_NAME, Key=S3_OBJECT_KEY)
        priv=recipient_private_key.private_bytes( encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption()).decode()
        pub=sender_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        with open('keys.txt', 'w') as file:
            # Write the private key to the file
            file.write(priv)
            # Write a separator or newline to separate the private and public keys
            file.write('\n')
            # Write the public key to the file
            file.write(pub)
        return render_template('encrypt.html', encrypted_text=encrypted_text,recipient_private_key=priv,sender_public_key=pub)
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    global recipient_private_key, sender_public_key
    if request.method == 'POST':
        try:
            response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=S3_OBJECT_KEY)
            encrypted_text_hex = response['Body'].read().decode('utf-8')
            encrypted_text = bytes.fromhex(encrypted_text_hex)
            # encrypted_text = bytes.fromhex(request.form['encrypted_text'])
            decrypted_plaintext = cryptosystem.hybrid_decrypt(recipient_private_key, sender_public_key, encrypted_text)
            return render_template('decrypt.html', decrypted_plaintext=decrypted_plaintext,encrypted_text_hex=encrypted_text_hex)
        except ValueError:
            return render_template('decrypt.html', decrypted_plaintext="Integrity Breached")
        except Exception as e:
            return render_template('decrypt.html', decrypted_plaintext="Error occurred: There is no Message to Retreive")
    return render_template('decrypt.html')


if __name__ == '__main__':
    app.run(debug=True)
