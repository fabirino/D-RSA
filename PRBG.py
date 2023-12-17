from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.padding import PKCS7
from sympy import isprime, mod_inverse
import sys

import hashlib

SEED_LEN = 16
OUTPUT_BYTES = 32
KEY_LENGTH = 2048

# ============================================================
# ======================== RANDGEN ===========================
# ============================================================


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

    #
    for i in range(SEED_LEN):
        bootstrap_seed[i] ^= confusion_string.encode(
            'utf-8')[i % len(confusion_string)]

    return bootstrap_seed


def create_bytes(password, iv, input_data):
    key_size = 32
    # Preenche com zeros se a senha for menor que 32 bytes
    key = password[:key_size].ljust(key_size, b'\0')

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()

    # Adiciona padding aos dados de entrada
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(input_data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return bytearray(ciphertext)


def generate_bytes(seed, password, confusion_string, iteration_count):

    bytes_generated = bytearray(OUTPUT_BYTES)
    output = bytearray()
    new_seed = seed
    new_pass = bytearray(password.encode('utf-8'))
    new_cf = bytearray(confusion_string.encode('utf-8'))

    while (iteration_count):
        # Find the confusion pattern
        found = False
        while (not found):
            # Generate the bytes
            output = create_bytes(new_pass, new_seed, bytes_generated)[
                :OUTPUT_BYTES]
            # for i in range(len(output)):
            #     print(hex(output[i]), end=" ")
            # print()

            # Check if the confusion pattern is present
            if new_cf in bytes_generated:
                found = True
                # DEBUG:
                # print("Confusion pattern found!")
            # Prepare the bytes for the next iteration
            bytes_generated = output
        # Reinicialize the PRBG with the new seed
        new_seed = create_bytes(new_pass, new_seed, bytes_generated)[:SEED_LEN]
        iteration_count -= 1

    output = create_bytes(new_pass, new_seed, bytes_generated)[:OUTPUT_BYTES]

    # Generate the pseudo random number because the output is not 4096 bits yet
    pseudo_rand_num = output.copy()
    for _ in range(15):     # 16 = 512 / 32; 15 = 16 - 1 because the array is already 32 bytes
        bytes_generated = output
        output = create_bytes(new_pass, new_seed, bytes_generated)[
            :OUTPUT_BYTES]
        pseudo_rand_num.extend(output)

    return pseudo_rand_num


# ============================================================
# ======================== RSAGEN ============================
# ============================================================

def read_to_bytearray():
    '''!
    @brief This function reads the input from stdin into a bytearray.
    @return The bytearray containing the input and the number of bytes read.
    '''

    try:
        # Read input from stdin into a bytearray
        # data = bytearray(sys.stdin.buffer.read())
        data = bytearray(sys.stdin.buffer.read())
        bytes_read = len(data)

        return data, bytes_read
    except Exception as e:
        print("An error occurred:", e)
        return None, 0


def generate_RSA_key_pair(seed, password, confusion_string, iteration_count):

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_LENGTH,
        backend=default_backend(),
    )

    return private_key


def write_private_key_to_pem(filename, key):
    with open(filename, 'wb') as f:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        f.write(pem)


def write_public_key_to_pem(filename, key):
    with open(filename, 'wb') as f:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        f.write(pem)


def find_prime(num):
    while not isprime(num):
        if (num % 2 == 0):
            num += 1
        else:
            num += 2
    return num


def generate_primes(pseudo_rand_num):

    p_bytes = pseudo_rand_num[:256]
    q_bytes = pseudo_rand_num[256:]

    p = int.from_bytes(p_bytes, byteorder='big')
    q = int.from_bytes(q_bytes, byteorder='big')

    p = find_prime(p)
    q = find_prime(q)

    return p, q


def generate_key(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    d = mod_inverse(e, phi)

    dpm1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = mod_inverse(q, p)

    # private_numbers = rsa.RSAPrivateNumbers(
    #     p=p, q=q, d=d, dmp1=None, dmq1=None, iqmp=None).private_key(default_backend())

    private_key_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dpm1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(
            e=e,
            n=n
        )
    )

    private_key = private_key_numbers.private_key(default_backend())
    public_key = private_key.public_key()

    return private_key, public_key
