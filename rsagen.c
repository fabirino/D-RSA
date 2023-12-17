#include "PRBG.h"
#include <stdio.h>
#include <stdlib.h>


#define PUB_KEY_FILE "public_key3.pem"
#define PRIV_KEY_FILE "private_key3.pem"

int main(int argc, char* argv[]){
    // Read the Pseudo Random Bytes from input
    uint64_t bytes_read;
    uint8_t *pseudo_rand_bytes = NULL;
    pseudo_rand_bytes = read_msg_bytes(&bytes_read);
    if (!pseudo_rand_bytes || bytes_read == 0) {
        fprintf(stderr, "Error reading the pseudo random bytes from input.\n");
        exit(EXIT_FAILURE);
    }

    // DEBUG:
    // for (int i = 0; i < bytes_read; i++) {
    //     printf("%c", pseudo_rand_bytes[i]);
    // }


    RSA *rsa_key = generate_RSA_key_pair(pseudo_rand_bytes);

    // write_public_key_to_pem(PUB_KEY_FILE, "PUBLIC KEY", rsa_key);
    // write_private_key_to_pem(PRIV_KEY_FILE, "PRIVATE KEY", seed, rsa_key);

    return 0;
}