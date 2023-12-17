import PRBG
import sys

if __name__ == '__main__':
    
    # Get the arguments
    if len(sys.argv) != 4:
        print('Usage: python3 rsagen.py <password> <confusion_string> <iteration_count>')
        sys.exit(1)

    password = sys.argv[1]
    confusion_string = sys.argv[2]
    iteration_count = int(sys.argv[3])

    bootstrap_seed = PRBG.generate_seed(password, confusion_string, iteration_count)

    output = PRBG.generate_bytes(bootstrap_seed, password, confusion_string, iteration_count)

    # DEBUG: 
    # print(len(output))
    # print("Output: ", end="")
    # for i in range(len(output)):
    #     if(i % 32 ==0):
    #         print()
    #     print(hex(output[i]), end=" ")
    # print()

    # rsa_key = PRBG.generate_RSA_key_pair(bootstrap_seed, password, confusion_string, iteration_count)
    # PRBG.write_private_key_to_pem("private_key.pem", rsa_key)
    # PRBG.write_public_key_to_pem("public_key.pem", rsa_key.public_key())

    p , q = PRBG.generate_primes(output)
    # print("p = ", p)
    # print("q = ", q)

    private_key, public_key = PRBG.generate_key(p, q)
    # print(private_key)
    # print(public_key)

    PRBG.write_private_key_to_pem("private_key2.pem", private_key)
    PRBG.write_public_key_to_pem("public_key2.pem", public_key)

