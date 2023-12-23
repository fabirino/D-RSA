"""!
@author Fábio Santos 118351
@author Rodrigo Marques 118587
@date 23/12/2023
"""

import DRSA
import sys

if __name__ == '__main__':

    pseudo_rand_bytes, bytes_read = DRSA.read_to_bytearray()

    # DEBUG: 
    # print(len(pseudo_rand_bytes))
    # print("Pseudo Rand Bytes: ", end="")
    # for i in range(len(pseudo_rand_bytes)):
    #     if(i % 32 ==0):
    #         print()
    #     print(hex(pseudo_rand_bytes[i]), end=" ")
    # print()

    p , q = DRSA.generate_primes(pseudo_rand_bytes)
    # print("p = ", p)
    # print("q = ", q)

    private_key, public_key = DRSA.generate_key(p, q)

    DRSA.write_private_key_to_pem("private_key.pem", private_key)
    DRSA.write_public_key_to_pem("public_key.pem", public_key)

