"""!
@file DRSA.py
@brief This file contains the implementation of the DRSA algorithm.
@author Fábio Santos 118351
@author Rodrigo Marques 118587
@date 23/12/2023
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.padding import PKCS7
from sympy import isprime, mod_inverse
import sys
import base64

SEED_LEN = 16
OUTPUT_BYTES = 32
KEY_LENGTH = 2048

# ============================================================
# ======================== RANDGEN ===========================
# ============================================================


def generate_seed(password, confusion_string, iteration_count):
    '''!
    @brief Generates a seed from the provided password, confusion string, and iteration count.
    @param password The password to use.
    @param confusion_string The confusion string to use.
    @param iteration_count The number of iterations to use.
    @param seed The buffer to store the generated seed in.
    '''
    # Use the PBKDF2 function to generate the seed
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        salt=confusion_string.encode('utf-8'),
        length=SEED_LEN,
        iterations=iteration_count,
        backend=default_backend()
    )
    bootstrap_seed = bytearray(kdf.derive(password.encode('utf-8')))

    # Add the confusion string to the seed
    for i in range(SEED_LEN):
        bootstrap_seed[i] ^= confusion_string.encode(
            'utf-8')[i % len(confusion_string)]

    return bootstrap_seed


def create_bytes(password, iv, input_data):

    '''!
    @brief Auxiliar function to create the bytes using AES
    @param password The key to use
    @param iv The initialize vector to use
    @param input_data The input to use
    @return The output bytes produced
    '''

    key_size = 32
    # Preenche com zeros se a senha for menor que 32 bytes
    key = password[:key_size].ljust(key_size, b'\0')

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()

    # Adiciona padding aos dados de entrada
    # padder = PKCS7(algorithms.AES.block_size).padder()
    # padded_data = padder.update(input_data) + padder.finalize()

    ciphertext = encryptor.update(input_data) + encryptor.finalize()
    return bytearray(ciphertext)


def generate_bytes(seed, password, confusion_string, iteration_count):

    '''!
    @brief Uses a PRBG to produce a stream of random bytes
    @param seed The seed to initialize the PRBG.
    @param password The password to use.
    @param confusion_string The confusion string to find.
    @param iteration_count The number of iterations to use.
    @return Pseudo-random stream of bytes.
    '''

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
            output = create_bytes(new_pass, new_seed, bytes_generated)[:OUTPUT_BYTES]
            
            # DEBUG:
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
        output = create_bytes(new_pass, new_seed, bytes_generated)[:OUTPUT_BYTES]
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


def write_private_key_to_pem(filename, key):

    '''!
    @brief Writes the private key to a PEM file
    @param filename The name of the file to write to
    @param key The private key to write.
    '''

    with open(filename, 'w') as f:
        f.write("-----BEGIN RSA PRIVATE KEY-----\n")
        for i in range(0, len(key), 64):
            f.write(key[i:i+64] + '\n')
        f.write("-----END RSA PRIVATE KEY-----\n")


def write_public_key_to_pem(filename, key):

    '''!
    @brief Writes the public key to a PEM file
    @param filename The name of the file to write to
    @param key The public key to write.
    '''

    with open(filename, 'w') as f:
        f.write("-----BEGIN RSA PUBLIC KEY-----\n")
        for i in range(0, len(key), 64):
            f.write(key[i:i+64] + '\n')
        f.write("-----END RSA PUBLIC KEY-----\n")


def int_to_base64(num):

    '''!
    @brief Converts an integer to a base64 string
    @param num The integer to convert
    @return The base64 string
    '''

    byte_representation = num.to_bytes(
        (num.bit_length() + 7) // 8, byteorder='big')
    base64_representation = base64.b64encode(byte_representation)
    return base64_representation.decode('utf-8')


def find_prime(num):

    '''!
    @brief Finds the next prime number
    @param num The number to start from
    @return The next prime number
    '''

    while not isprime(num):
        if (num % 2 == 0):
            num += 1
        else:
            num += 2
    return num


def generate_primes(pseudo_rand_num):

    '''!
    @brief Generates two prime numbers from the pseudo random number
    @param pseudo_rand_num The pseudo random number
    @return The two prime numbers
    '''

    p_bytes = pseudo_rand_num[0:256]
    q_bytes = pseudo_rand_num[256:512]

    p = int.from_bytes(p_bytes, byteorder='big')
    q = int.from_bytes(q_bytes, byteorder='big')

    # print("p = ", p)
    # print("q = ", q)

    p = find_prime(p)
    q = find_prime(q)

    # print(p.bit_length())
    # print(q.bit_length())

    return p, q


def generate_key(p, q):

    '''!
    @brief Generates the public and private key
    @param p The first prime number
    @param q The second prime number
    @return The private and public key
    '''

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    d = mod_inverse(e, phi)

    public = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big') + e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')
    private = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big') + d.to_bytes((d.bit_length() + 7) // 8, byteorder='big')

    private_key = base64.b64encode(private).decode('utf-8')
    public_key = base64.b64encode(public).decode('utf-8')

    return private_key, public_key
