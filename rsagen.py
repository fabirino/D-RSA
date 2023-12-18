import PRBG
import sys

if __name__ == '__main__':

    pseudo_rand_bytes, bytes_read = PRBG.read_to_bytearray()

    # DEBUG: 
    # print(len(pseudo_rand_bytes))
    # print("Pseudo Rand Bytes: ", end="")
    # for i in range(len(pseudo_rand_bytes)):
    #     if(i % 32 ==0):
    #         print()
    #     print(hex(pseudo_rand_bytes[i]), end=" ")
    # print()

    p , q = PRBG.generate_primes(pseudo_rand_bytes)
    # print("p = ", p)
    # print("q = ", q)

    private_key, public_key = PRBG.generate_key(p, q)

    PRBG.write_private_key_to_pem("private_key1.pem", private_key)
    PRBG.write_public_key_to_pem("public_key1.pem", public_key)

