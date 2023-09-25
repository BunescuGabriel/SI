from cryptography.fernet import Fernet

def generate_key(key_size):
    if key_size == 128:
        key = Fernet.generate_key()
        key_size_in_bits = 128
    elif key_size == 192:
        key = Fernet.generate_key()
        key_size_in_bits = 192
    elif key_size == 256:
        key = Fernet.generate_key()
        key_size_in_bits = 256
    else:
        raise ValueError("Dimensiunea cheii nu este validă. Alegeți una dintre: 128, 192 sau 256.")
    return key, key_size_in_bits

def encrypt_message(key, plaintext):
    f = Fernet(key)
    encrypted_message = f.encrypt(plaintext.encode())
    return encrypted_message

def decrypt_message(key, encrypted_message):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

try:
    key_size = int(input("Introduceți dimensiunea cheii (128, 192 sau 256): "))

    if key_size not in [128, 192, 256]:
        raise ValueError("Dimensiunea cheii nu este validă. Alegeți una dintre: 128, 192 sau 256.")

    key, key_size_in_bits = generate_key(key_size)
    print(f"Cheia secretă generată ({key_size_in_bits} biți):", key.decode())

    plaintext = input("Introduceți textul pe care doriți să-l criptați: ")

    encrypted_message = encrypt_message(key, plaintext)
    print("Mesaj criptat:", encrypted_message)

    decrypted_message = decrypt_message(key, encrypted_message)
    print("Mesaj decriptat:", decrypted_message)
except ValueError as e:
    print(e)
