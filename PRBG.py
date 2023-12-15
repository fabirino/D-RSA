from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.padding import PKCS7 

import hashlib

SEED_LEN = 16
OUTPUT_BYTES = 32
KEY_LENGTH = 2048

def generate_seed(password, confusion_string, iteration_count):
    # 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        salt=confusion_string.encode('utf-8'),
        length=SEED_LEN,
        iterations=iteration_count,
        backend=default_backend()
    )
    bootstrap_seed = bytearray(kdf.derive(password.encode('utf-8')))

    # Adicione a string de confusão ao seed
    for i in range(SEED_LEN):
        bootstrap_seed[i] ^= confusion_string.encode('utf-8')[i % len(confusion_string)]

    return bootstrap_seed


def create_bytes(password, iv, input_data):
    key_size = 32
    key = password[:key_size].ljust(key_size, b'\0')  # Preenche com zeros se a senha for menor que 32 bytes

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Adiciona padding aos dados de entrada
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(input_data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext

def generate_bytes(seed, password, confusion_string, iteration_count):
    
    bytes_generated = bytearray(SEED_LEN)
    output = bytearray()
    new_seed = seed
    new_pass = bytearray(password.encode('utf-8'))
    new_cf = bytearray(confusion_string.encode('utf-8'))

    while(iteration_count):
        # Find the confusion pattern
        found = False
        while (not found):
            # Generate the bytes
            output = create_bytes(new_pass, new_seed, bytes_generated)
            
            # for i in range(len(output)):
            #     print(hex(output[i]), end=" ")
            # print()

            # Check if the confusion pattern is present
            if new_cf in bytes_generated:
                found = True
                print("Confusion pattern found!")
            # Prepare the bytes for the next iteration
            bytes_generated = output
        # Reinicialize the PRBG with the new seed
        new_seed = create_bytes(new_pass, new_seed, bytes_generated)[:SEED_LEN]
        iteration_count -= 1

    output = create_bytes(new_pass, new_seed, bytes_generated)

    return output



def generate_RSA_key_pai():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_LENGTH,
        backend=default_backend()
    )
    return private_key

def write_private_key_to_pem(filename, key):
    with open(filename, 'wb') as f:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        f.write(pem)

def write_public_key_to_pem(filename, key):
    with open(filename, 'wb') as f:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        f.write(pem)

