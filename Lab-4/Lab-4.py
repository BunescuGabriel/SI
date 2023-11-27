from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.exceptions import InvalidSignature
import base64
import hashlib

def generate_symmetric_key(key_size):
    if key_size == 128:
        return Fernet.generate_key(), 128
    elif key_size == 192:
        return Fernet.generate_key(), 192
    elif key_size == 256:
        return Fernet.generate_key(), 256
    else:
        raise ValueError("Dimensiunea cheii nu este validă. Alegeți una dintre: 128, 192 sau 256.")

def symmetric_encrypt(key, plaintext):
    f = Fernet(key)
    encrypted_message = f.encrypt(plaintext.encode())
    return encrypted_message

def symmetric_decrypt(key, encrypted_message):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem.decode(), public_pem.decode()

def asymmetric_encrypt(public_key, plaintext):
    public_key = serialization.load_pem_public_key(public_key.encode(), backend=default_backend())
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def asymmetric_decrypt(private_key, ciphertext):
    private_key = serialization.load_pem_private_key(private_key.encode(), password=None, backend=default_backend())
    decoded_ciphertext = base64.b64decode(ciphertext.encode())
    decrypted_message = private_key.decrypt(
        decoded_ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return decrypted_message.decode()

def generate_dsa_keys():
    private_key = dsa.generate_private_key(key_size=1024, backend=default_backend())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key_pem.decode(), public_key_pem.decode()

def sign_message(private_key, message):
    private_key = serialization.load_pem_private_key(private_key.encode(), password=None, backend=default_backend())
    message_hash = hashlib.sha256(message.encode()).digest()
    signature = private_key.sign(
        message_hash,
        algorithm=hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(public_key, message, signature):
    public_key = serialization.load_pem_public_key(public_key.encode(), backend=default_backend())
    message_hash = hashlib.sha256(message.encode()).digest()
    signature = base64.b64decode(signature.encode())
    try:
        public_key.verify(
            signature,
            message_hash,
            algorithm=hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# Meniu
while True:
    print("\nMeniu:")
    print("1. Criptare și decriptare simetrică (AES)")
    print("2. Criptare și decriptare asimetrică (RSA)")
    print("3. Semnare și verificare semnătură digitală (DSA)")
    print("0. Ieșire")

    choice = input("Selectați o opțiune: ")

    if choice == "1":
        try:
            key_size = int(input("Introduceți dimensiunea cheii (128, 192 sau 256): "))
            if key_size not in [128, 192, 256]:
                raise ValueError("Dimensiunea cheii nu este validă. Alegeți una dintre: 128, 192 sau 256.")
            key, key_size_in_bits = generate_symmetric_key(key_size)
            print(f"Cheia secretă generată ({key_size_in_bits} biți):", key.decode())
            plaintext = input("Introduceți textul pe care doriți să-l criptați: ")
            encrypted_message = symmetric_encrypt(key, plaintext)
            print("Mesaj criptat:", encrypted_message)
            decrypted_message = symmetric_decrypt(key, encrypted_message)
            print("Mesaj decriptat:", decrypted_message)
        except ValueError as e:
            print(e)
    
    elif choice == "2":
        try:
            private_key, public_key = generate_rsa_keys()
            print("Cheia privată RSA:")
            print(private_key)
            print("\nCheia publică RSA:")
            print(public_key)
            plaintext = input("Introduceți textul pe care doriți să-l criptați: ")
            ciphertext = asymmetric_encrypt(public_key, plaintext)
            print("Mesaj criptat RSA (Base64):")
            print(ciphertext)
            decrypted_message = asymmetric_decrypt(private_key, ciphertext)
            print("Mesaj decriptat RSA:")
            print(decrypted_message)
        except Exception as e:
            print("A apărut o eroare:", e)

    elif choice == "3":
        try:
            private_key, public_key = generate_dsa_keys()
            print("Cheia privată DSA:")
            print(private_key)
            print("\nCheia publică DSA:")
            print(public_key)
            message = input("Introduceți mesajul pentru semnare digitală: ")
            
            message_hash = hashlib.sha256(message.encode()).hexdigest()
            print("\nMesajul original:")
            print(message)
            print(f"\nHash-ul mesajului original (SHA-256): {message_hash}")
        
            signature = sign_message(private_key, message)
            print("Semnătura digitală (Base64):")
            print(signature)
            verified = verify_signature(public_key, message, signature)
            if verified:
                print("Semnătura este validă.")
            else:
                print("Semnătura nu este validă.")
        except Exception as e:
            print("A apărut o eroare:", e)

    elif choice == "0":
        print("La revedere!")
        break

    else:
        print("Opțiune invalidă. Vă rugăm să introduceți o opțiune validă.")