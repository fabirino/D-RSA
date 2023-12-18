import PRBG
import sys

if __name__ == '__main__':
    
    if sys.argv[1] == "-f" and len(sys.argv) == 2:
        # Flag -f
        pseudo_rand_bytes, bytes_read = PRBG.read_to_bytearray()
        # print(pseudo_rand_bytes)
    elif sys.argv[1] == "-c" and len(sys.argv) != 5:
        # Flag -c
        password = sys.argv[1]
        confusion_string = sys.argv[2]
        iteration_count = int(sys.argv[3])

        bootstrap_seed = PRBG.generate_seed(password, confusion_string, iteration_count)

        pseudo_rand_bytes = PRBG.generate_bytes(bootstrap_seed, password, confusion_string, iteration_count)
    else:
        print('Usages:\npython3 rsagen.py -c <password> <confusion_string> <iteration_count>\npython3 rsagen.py -f < <pseudo_rand_bytes>')
        sys.exit(1)
    
    # DEBUG: 
    # print(len(pseudo_rand_bytes))
    # print("Pseudo Rand Bytes: ", end="")
    # for i in range(len(pseudo_rand_bytes)):
    #     if(i % 32 ==0):
    #         print()
    #     print(hex(pseudo_rand_bytes[i]), end=" ")
    # print()

    # rsa_key = PRBG.generate_RSA_key_pair(bootstrap_seed, password, confusion_string, iteration_count)
    # PRBG.write_private_key_to_pem("private_key.pem", rsa_key)
    # PRBG.write_public_key_to_pem("public_key.pem", rsa_key.public_key())

    p , q = PRBG.generate_primes(pseudo_rand_bytes)
    # print("p = ", p)
    # print("q = ", q)

    private_key, public_key = PRBG.generate_key(p, q)
    # print(private_key)
    # print(public_key)

    PRBG.write_private_key_to_pem("private_key2.pem", private_key)
    PRBG.write_public_key_to_pem("public_key2.pem", public_key)

