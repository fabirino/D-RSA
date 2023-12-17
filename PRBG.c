#include "PRBG.h"

// ============================================================
// ======================== RANDGEN ===========================
// ============================================================

void generate_seed(const char *password, const uint8_t *confusion_string, int iteration_count, uint8_t *bootstrap_seed) {

    // Use the PBKDF2 function to generate the seed
    if (PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), (unsigned char *)confusion_string, strlen(confusion_string), iteration_count, SEED_LEN, bootstrap_seed) != 1) {
        fprintf(stderr, "Erro ao gerar o seed.\n");
        exit(EXIT_FAILURE);
    }

    // Add the confusion string to the seed
    for (int i = 0; i < SEED_LEN; i++) {
        bootstrap_seed[i] ^= confusion_string[i % strlen(confusion_string)];
    }
}

/**
 * @brief Auxiliar function to compare two arrays
 * @param array1 First array
 * @param len1 Length of the first array
 * @param array2 Second array
 * @param len2 Length of the second array
 * @return 1 if the arrays are equal, 0 otherwise
 */
int _compare_arrays(uint8_t *array1, size_t len1, uint8_t *array2, size_t len2) {
    // Size of the sliding window
    uint8_t window_size = (len1 < len2) ? len1 : len2;

    // Compare the arrays
    if (len1 < len2) {
        // array1 is bigger than array2
        for (uint8_t i = 0; i < len2 - window_size + 1; i++) {
            for (int j = 0; j < window_size; j++) {
                if (array1[j] != array2[i + j]) {
                    break;
                }
                if (j == window_size - 1) {
                    return 1; // The arrays are equal
                }
            }
        }
    } else if (len1 > len2) {
        // array2 is bigger than array1
        for (uint8_t i = 0; i < len1 - window_size + 1; i++) {
            for (int j = 0; j < window_size; j++) {
                if (array1[i + j] != array2[j]) {
                    break;
                }
                if (j == window_size - 1) {
                    return 1; // The arrays are equal
                }
            }
        }
    } else {
        // array1 and array2 have the same size
        for (int i = 0; i < window_size; i++) {
            if (array1[i] != array2[i]) {
                break;
            }
            if (i == window_size - 1) {
                return 1; // The arrays are equal
            }
        }
    }
    return 0; // The arrays are different
}

/**
 * @brief Auxiliar function to inicialize the AES
 * @param key The key to use
 * @param iv The iv to use
 * @return The context of the AES
 */
EVP_CIPHER_CTX *_initAES(const uint8_t *password, const uint8_t *iv) {
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Error inicializing AES.\n");
        exit(EXIT_FAILURE);
    }

    // Prepare the key
    uint8_t *key = malloc(sizeof(uint8_t) * 32);
    uint8_t password_size = strlen(password);
    if (password_size < 32) {
        // The password is smaller than 32 bytes
        for (int i = 0; i < 32; i++) {
            key[i] = password[i % password_size];
        }
    } else {
        // The password is bigger than 32 bytes
        for (int i = 0; i < 32; i++) {
            key[i] = password[i];
        }
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        printf("Error creating bytes1.\n");
        exit(EXIT_FAILURE);
    }

    free(key);
    return ctx;
}

/**
 * @brief Auxiliar function to create the bytes
 * @param ctx The context of the AES
 * @param input The input to use
 * @param input_len The length of the input
 * @param output The output to use
 */
void _createBytes(EVP_CIPHER_CTX *ctx, const uint8_t *input, int input_len, uint8_t *output) {
    int ciphertext_len;

    if (1 != EVP_EncryptUpdate(ctx, output, &ciphertext_len, input, input_len)) {
        printf("Error creating bytes2.\n");
        exit(EXIT_FAILURE);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, output + ciphertext_len, &ciphertext_len)) {
        printf("Error creating bytes3.\n");
        exit(EXIT_FAILURE);
    }
}




void _create_bytes2(const uint8_t *password, const uint8_t *iv, const uint8_t *input, int input_len, uint8_t *output){

    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Error inicializing AES.\n");
        exit(EXIT_FAILURE);
    }

    // Prepare the key
    uint8_t *key = malloc(sizeof(uint8_t) * 32);
    uint8_t password_size = strlen(password);
    if (password_size < 32) {
        // The password is smaller than 32 bytes
        for (int i = 0; i < 32; i++) {
            key[i] = password[i % password_size];
        }
    } else {
        // The password is bigger than 32 bytes
        for (int i = 0; i < 32; i++) {
            key[i] = password[i];
        }
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        printf("Error creating bytes1.\n");
        exit(EXIT_FAILURE);
    }

    free(key);

    int ciphertext_len;

    if (1 != EVP_EncryptUpdate(ctx, output, &ciphertext_len, input, input_len)) {
        printf("Error creating bytes2.\n");
        exit(EXIT_FAILURE);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, output + ciphertext_len, &ciphertext_len)) {
        printf("Error creating bytes3.\n");
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX_free(ctx);
}



void generate_bytes(uint8_t *seed, uint8_t *password, uint8_t *confusion_string, int iteration_count, uint8_t *output) {

    // Initialize the PRBG with the seed
    size_t size1 = 0, size2 = 0;

    // Inicialize the output buffer
    uint8_t bytes [OUTPUT_BYTES] = {0};
    if (!bytes) {
        fprintf(stderr, "Error allocating memory.\n");
        exit(EXIT_FAILURE);
    }

    while (iteration_count--) {

        // Find the confusion pattern
        int found = 0;

        while (!found) {
            // Generate the bytes
            _create_bytes2(password, seed, bytes, SEED_LEN, output);

            // DEBUG: Print the bytes
            // printf("Bytes generated: ");
            // for (int i = 0; i < OUTPUT_BYTES; i++) {
            //     printf("%02x ", bytes[i]);
            // }
            // printf("\n");

            // Check if the confusion pattern is present
            size1 = 32;
            size2 = strlen(confusion_string);
            found = _compare_arrays(output, size1, confusion_string, size2);

            // Prepare the bytes for the next iteration
            for (int i = 0; i < OUTPUT_BYTES; i++) {
                bytes[i] = output[i];
            }
        }
        printf("Confusion pattern found.\n");


        // DEBUG: Print the bytes
        // printf("Bytes generated: ");
        // for (int i = 0; i < size1; i++) {
        //     printf("%02x ", bytes[i]);
        // }
        // printf("\n");
        // printf("Confusion pattern: ");
        // for (int i = 0; i < size2; i++) {
        //     printf("%02x ", confusion_string[i]);
        // }
        // printf("\n");
        // printf("\n");

        // Reinitialize the PRBG with the new seed
        uint8_t new_seed[SEED_LEN];
        _create_bytes2(password, seed, bytes, SEED_LEN, new_seed);
        // seed = new_seed;
        for (int i = 0; i < SEED_LEN; i++) {
            seed[i] = new_seed[i];
        }
    }
    // Generate the output
    _create_bytes2(password, seed, bytes, OUTPUT_BYTES, output);
    EVP_cleanup();
}

// ============================================================
// ======================== RSAGEN ============================
// ============================================================

uint8_t *read_msg_bytes(uint64_t *bytes_read) {
    uint8_t aux;
    uint8_t *input_bytes = NULL;

    (*bytes_read) = 0;
    while (fread(&aux, sizeof(uint8_t), 1, stdin) == 1) {
        input_bytes = realloc(input_bytes, (++(*bytes_read)) * sizeof(uint8_t));
        if (!input_bytes) {
            fprintf(stderr, "Failed to realloc memory!\n");
            return NULL;
        }
        input_bytes[(*bytes_read) - 1] = aux;
    }
    return input_bytes;
}

RSA *generate_RSA_key_pair(uint8_t *pseudo_rand_num) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    // Set the exponent
    if (!BN_set_word(e, 65537)) {
        fprintf(stderr, "Error setting the public exponent.\n");
        exit(EXIT_FAILURE);
    }

    // Generate the key pair
    if (!RSA_generate_key_ex(rsa, KEY_LENGTH, e, NULL)) {
        fprintf(stderr, "Error generating the key pair.\n");
        exit(EXIT_FAILURE);
    }

    BN_free(e);
    return rsa;
}

void write_private_key_to_pem(const char *filename, const char *header, const unsigned char *key, RSA *rsa_key) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error opening the file.\n");
        exit(EXIT_FAILURE);
    }

    // Write the key to the file
    if (!PEM_write_RSAPrivateKey(file, rsa_key, EVP_aes_256_cbc(), NULL, 0, NULL, key)) {
        fprintf(stderr, "Error writing the key to the file.\n");
        exit(EXIT_FAILURE);
    }

    fclose(file);
}

void write_public_key_to_pem(const char *filename, const char *header, RSA *rsa_key) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error opening file: %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // Use PEM_write_RSA_PUBKEY to write the public key without encryption
    if (!PEM_write_RSA_PUBKEY(file, rsa_key)) {
        fprintf(stderr, "Error writing RSA public key to PEM file.\n");
        exit(EXIT_FAILURE);
    }

    fclose(file);
}