/**
 * @file PRBG.h
 * @brief Generates a pair of RSA keys and writes them to a PEM file.
 * @author Fábio Santos 1188351
 * @author Rodrigo Marques 118587
 * @date 23/12/2023
*/

#include "D-RSA.h"
#include <stdio.h>
#include <stdlib.h>


#define PUB_KEY_FILE "public_key2.pem"
#define PRIV_KEY_FILE "private_key2.pem"

int main(int argc, char* argv[]){

    if(argc != 1){
        printf("Usage: ./rsagen < <input_file>\n");
        return 1;
    }

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

    rsa_key_pair *rsa_key = generate_RSA_key_pair(pseudo_rand_bytes);

    write_public_key_to_pem(PUB_KEY_FILE,  rsa_key->public_key);
    write_private_key_to_pem(PRIV_KEY_FILE, rsa_key->private_key);
    free(rsa_key->public_key);
    free(rsa_key->private_key);
    free(rsa_key);

    return 0;
}