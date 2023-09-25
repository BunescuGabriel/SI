import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization  # Importăm serialization
from cryptography.exceptions import InvalidSignature
 
# Generăm o pereche de chei DSA (cheie privată și cheie publică)
private_key = dsa.generate_private_key(key_size=1024, backend=default_backend())
public_key = private_key.public_key()
 
# Afișăm cheia privată
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
print("Cheia Privată:")
print(private_key_pem.decode())
 
# Afișăm cheia publică
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print("\nCheia Publică:")
print(public_key_pem.decode())
 
# Citim mesajul de la tastatură
message = input("Introduceți mesajul pentru semnare digitală: ").encode()
 
# Calculează hash-ul mesajului original (SHA-256)
message_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
message_hash.update(message)
message_digest = message_hash.finalize()
 
# Semnăm mesajul folosind cheia privată
signature = private_key.sign(
    message_digest,
    hashes.SHA256()
)
 
# Verificăm semnătura folosind cheia publică
try:
    public_key.verify(
        signature,
        message_digest,
        hashes.SHA256()
    )
    print("\nSemnatura este valida.")
except InvalidSignature:
    print("\nSemnatura nu este valida.")
 
# Afișăm hash-urile mesajului și ale semnăturii
print(f"\nHash-ul mesajului original (SHA-256): {message_digest.hex()}")
print(f"Hash-ul semnăturii digitale (SHA-256): {hashlib.sha256(signature).hexdigest()}")
