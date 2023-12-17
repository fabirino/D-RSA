import PRBG
import sys


if __name__ == '__main__':

    # Get the arguments
    if len(sys.argv) != 4:
        print('Usage: python3 randgen.py <password> <confusion_string> <iteration_count>')
        sys.exit(1)

    password = sys.argv[1]
    confusion_string = sys.argv[2]
    iteration_count = int(sys.argv[3])

    bootstrap_seed = PRBG.generate_seed(password, confusion_string, iteration_count)

    # for i in range(PRBG.SEED_LEN):
    #     print(hex(bootstrap_seed[i]), end=" ")
    # print()

    output = PRBG.generate_bytes(bootstrap_seed, password, confusion_string, iteration_count)

    # DEBUG:
    # print("Output: ", end="")
    # for i in range(2048):
    #     if(i % 32 ==0):
    #         print()
    #     print(hex(output[i]), end=" ")
    # print()

    sys.stdout.buffer.write(output)