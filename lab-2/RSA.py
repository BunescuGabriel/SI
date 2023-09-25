from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

# Generăm o pereche de chei RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Serializăm cheia privată pentru a o putea stoca sau partaja
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Obținem și cheia publică asociată cu cheia privată
public_key = private_key.public_key()

# Serializăm cheia publică pentru a o putea partaja
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Afișăm cheile
print("Cheia privată:")
print(private_pem.decode())
print("\nCheia publică:")
print(public_pem.decode())

# Citim textul de la tastatură pentru criptare
plaintext_message = input("Introduceți textul pe care doriți să-l criptați: ").encode()

# Criptăm mesajul folosind cheia publică
ciphertext = public_key.encrypt(
    plaintext_message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),  # Folosim SHA-1 aici pentru MGF1
        algorithm=hashes.SHA1(),  # Folosim SHA-1 pentru padding
        label=None
    )
)

# Convertim mesajul criptat în șir Base64
ciphertext_base64 = base64.b64encode(ciphertext).decode()

# Afișăm mesajul criptat în format Base64
print("\nMesaj criptat (Base64):")
print(ciphertext_base64)

# Decriptăm mesajul folosind cheia privată
decoded_ciphertext = base64.b64decode(ciphertext_base64)
decrypted_message = private_key.decrypt(
    decoded_ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),  # Folosim SHA-1 aici pentru MGF1
        algorithm=hashes.SHA1(),  # Folosim SHA-1 pentru padding
        label=None
    )
)

# Afișăm mesajul decriptat
print("\nMesaj decriptat:")
print(decrypted_message.decode())
