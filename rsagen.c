#include "PRBG.h"
#include <stdio.h>
#include <stdlib.h>


#define PUB_KEY_FILE "public_key.pem"
#define PRIV_KEY_FILE "private_key.pem"

int main(int argc, char* argv[]){
    // uint8_t seed[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    unsigned char seed[] = "password";

    RSA *rsa_key = generate_RSA_key_pair();

    write_public_key_to_pem(PUB_KEY_FILE, "PUBLIC KEY", rsa_key);
    write_private_key_to_pem(PRIV_KEY_FILE, "PRIVATE KEY", seed, rsa_key);

    return 0;
}