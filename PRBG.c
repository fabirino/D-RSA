#include "PRBG.h"

void generate_seed(const char *password, const char *confusion_string, int iteration_count, unsigned char *seed){
    // // Gere um salt aleatório
    // unsigned char salt[SALT_LEN];
    // if (RAND_bytes(salt, sizeof(salt)) != 1) {
    //     fprintf(stderr, "Erro ao gerar o salt.\n");
    //     exit(EXIT_FAILURE);
    // }

    // Use the PBKDF2 function to generate the seed
    if (PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), (unsigned char *)confusion_string, strlen(confusion_string), iteration_count, SEED_LEN, seed) != 1) {
        fprintf(stderr, "Erro ao gerar o seed.\n");
        exit(EXIT_FAILURE);
    }

    // Add the confusion string to the seed
    for (int i = 0; i < SEED_LEN;i++){
        seed[i] ^= confusion_string[i % strlen(confusion_string)];
    }

}