/**
 * @file PRBG.c
 * @brief Implementation of DRSA.
 * @author Fábio Santos 1188351
 * @author Rodrigo Marques 118587
 * @date 23/12/2023
*/

#include "D-RSA.h"

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

void _create_bytes2(const uint8_t *password, const uint8_t *iv, const uint8_t *input, int input_len, uint8_t *output) {

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

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/**
 * @brief Auxiliar function to create the bytes using AES
 * @param password The key to use
 * @param iv The iv to use
 * @param input_data The input to use
 * @param input_length The length of the input
 * @param output The output bytes produced
 */
void _create_bytes3(const uint8_t *password, const uint8_t *iv, const uint8_t *input_data, size_t input_length, uint8_t *output) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, password, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, output, &len, input_data, input_length))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, output + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

void generate_bytes(uint8_t *seed, uint8_t *password, uint8_t *confusion_string, int iteration_count, uint8_t *PRB) {

    // Initialize the PRBG with the seed
    uint8_t output[32] = {0};
    size_t size = 0;

    // Inicialize the output buffer
    uint8_t bytes[OUTPUT_BYTES] = {0};
    if (!bytes) {
        fprintf(stderr, "Error allocating memory.\n");
        exit(EXIT_FAILURE);
    }

    while (iteration_count--) {

        // Find the confusion pattern
        int found = 0;

        while (!found) {
            // Generate the bytes
            _create_bytes3(password, seed, bytes, OUTPUT_BYTES, output);

            // DEBUG: Print the bytes
            // printf("Bytes generated: ");
            // for (int i = 0; i < OUTPUT_BYTES; i++) {
            //     printf("%02x ", bytes[i]);
            // }
            // printf("\n");

            // Check if the confusion pattern is present
            size = strlen(confusion_string);
            found = _compare_arrays(output, OUTPUT_BYTES, confusion_string, size);

            // Prepare the bytes for the next iteration
            for (int i = 0; i < OUTPUT_BYTES; i++) {
                bytes[i] = output[i];
            }
            memset(output, 0, OUTPUT_BYTES);
        }

        // DEBUG: Print the bytes
        // printf("Confusion pattern found.\n");

        // Reinitialize the PRBG with the new seed
        uint8_t new_seed[SEED_LEN];
        _create_bytes3(password, seed, bytes, SEED_LEN, new_seed);
        // seed = new_seed;
        for (int i = 0; i < SEED_LEN; i++) {
            seed[i] = new_seed[i];
        }
        memset(new_seed, 0, SEED_LEN);
    }

    // Generate the output
    for (int i = 0; i < 16; i++) {
        // Create 32 bytes 16 times and store them in the PRB (512 bytes == 4046 bits)
        _create_bytes3(password, seed, bytes, OUTPUT_BYTES, output);

        for (int j = 0; j < OUTPUT_BYTES; j++) {
            PRB[i * OUTPUT_BYTES + j] = output[j];
        }

        for (int j = 0; j < OUTPUT_BYTES; j++) {
            bytes[j] = output[j];
        }
    }

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

/**
 * @brief Finds the next prime number after num
 * @param num The number to start from
 */
void next_prime(BIGNUM *num) {
    BIGNUM *one = BN_new();
    BN_one(one);
    while (!BN_is_prime(num, BN_prime_checks, NULL, NULL, NULL)) {
        BN_add(num, num, one);
    }
    BN_free(one);
}

/**
 * @brief Converts a stream of bytes to base64
 * @param bytes The bytes to convert
 * @param size The size of the bytes
 * @return The base64 string
 */
uint8_t *bytes_to_base64(uint8_t *bytes, size_t size) {
    // Codifica em Base64
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);

    BIO_write(b64, bytes, size);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    // Alocar espaço suficiente para a string Base64
    char *base64_encoded = malloc(bptr->length + 1);
    if (!base64_encoded) {
        fprintf(stderr, "Error allocating memory.\n");
        exit(EXIT_FAILURE);
    }
    memcpy(base64_encoded, bptr->data, bptr->length);
    base64_encoded[bptr->length] = '\0';

    BIO_free_all(b64);
    return base64_encoded;
}

rsa_key_pair *generate_RSA_key_pair(uint8_t *pseudo_rand_num) {

    // Divide the array in half and store the values in p and q
    size_t half_size = 512 / 2;
    uint8_t *p_bytes = pseudo_rand_num;
    uint8_t *q_bytes = pseudo_rand_num + half_size;

    // DEBUG:
    // printf("p_bytes: ");
    // for (size_t i = 0; i < half_size; i++) {
    //     printf("%02x ", p_bytes[i]);
    // }
    // printf("\n");

    // printf("q_bytes: ");
    // for (size_t i = 0; i < half_size; i++) {
    //     printf("%02x ", q_bytes[i]);
    // }
    // printf("\n");

    // Convert the bytes to BIGNUMs
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    if (!q || !p) {
        fprintf(stderr, "Error initializing BIGNUM\n");
        exit(EXIT_FAILURE);
    }
    BN_bin2bn(p_bytes, half_size, p);
    BN_bin2bn(q_bytes, half_size, q);
    // Find the next primes after p and q
    next_prime(p);
    next_prime(q);

    // printf("p: %s\n", BN_bn2hex(p));
    // printf("q: %s\n", BN_bn2hex(q));

    // Calulate n, e, d, phi, dmp1, dmq1, iqmp
    BIGNUM *e = BN_new();
    if (!BN_set_word(e, 65537) || !e) {
        fprintf(stderr, "Error setting the public exponent.\n");
        exit(EXIT_FAILURE);
    }

    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    if (!n || !d || !phi || !p_minus_1 || !q_minus_1 || !ctx) {
        fprintf(stderr, "Error initializing BIGNUM\n");
        exit(EXIT_FAILURE);
    }

    BN_mul(n, p, q, ctx);
    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());
    BN_mul(phi, p_minus_1, q_minus_1, ctx);
    BN_mod_inverse(d, e, phi, NULL);

    rsa_key_pair *rsa_key = malloc(sizeof(rsa_key_pair));
    rsa_key->private_key = malloc(sizeof(char) * 2048);
    rsa_key->public_key = malloc(sizeof(char) * 2048);

    if (!rsa_key || !rsa_key->private_key || !rsa_key->public_key) {
        fprintf(stderr, "Error allocating memory.\n");
        exit(EXIT_FAILURE);
    }

    // Write the private key
    BIGNUM *public = BN_new();
    BIGNUM *private = BN_new();
    if (!public || !private) {
        fprintf(stderr, "Error initializing BIGNUM\n");
        exit(EXIT_FAILURE);
    }

    // Converter o BIGNUM n para bytes
    size_t n_size = BN_num_bytes(n);
    uint8_t *n_bytes = malloc(n_size);
    if (!n_bytes) {
        fprintf(stderr, "Error allocating memory.\n");
        exit(EXIT_FAILURE);
    }
    BN_bn2bin(n, n_bytes);

    // Converter o BIGNUM e para bytes
    size_t e_size = BN_num_bytes(e);
    uint8_t *e_bytes = malloc(e_size);
    if (!e_bytes) {
        fprintf(stderr, "Error allocating memory.\n");
        exit(EXIT_FAILURE);
    }
    BN_bn2bin(e, e_bytes);

    // Converter o BIGNUM d para bytes
    size_t d_size = BN_num_bytes(d);
    uint8_t *d_bytes = malloc(d_size);
    if (!d_bytes) {
        fprintf(stderr, "Error allocating memory.\n");
        exit(EXIT_FAILURE);
    }
    BN_bn2bin(d, d_bytes);

    // Concatenar os bytes de n e e
    size_t concat_size_pub = n_size + e_size;
    uint8_t *concat_pub = malloc(concat_size_pub);
    if (!concat_pub) {
        fprintf(stderr, "Error allocating memory.\n");
        exit(EXIT_FAILURE);
    }
    memcpy(concat_pub, n_bytes, n_size);
    memcpy(concat_pub + n_size, e_bytes, e_size);

    // Concatenar os bytes de n e d
    size_t concat_size_priv = n_size + d_size;
    uint8_t *concat_priv = malloc(concat_size_priv);
    if (!concat_priv) {
        fprintf(stderr, "Error allocating memory.\n");
        exit(EXIT_FAILURE);
    }
    memcpy(concat_priv, n_bytes, n_size);
    memcpy(concat_priv + n_size, d_bytes, d_size);

    char *public_key = NULL;
    public_key = bytes_to_base64(concat_pub, concat_size_pub);
    char *private_key = NULL;
    private_key = bytes_to_base64(concat_priv, concat_size_priv);

    strcpy(rsa_key->private_key, private_key);
    strcpy(rsa_key->public_key, public_key);

    free(n_bytes);
    free(e_bytes);
    free(d_bytes);
    free(concat_pub);
    free(concat_priv);
    free(public_key);
    free(private_key);

    return rsa_key;
}

void write_private_key_to_pem(const char *filename, char *key) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error opening file: %s\n", filename);
        exit(EXIT_FAILURE);
    }

    fprintf(file, "-----BEGIN RSA PRIVATE KEY-----\n");

    size_t key_length = strlen(key);
    size_t segment_length = 64;
    for (size_t i = 0; i < key_length; i += segment_length) {
        fprintf(file, "%.*s\n", (int)(i + segment_length > key_length ? key_length - i : segment_length), key + i);
    }
    fprintf(file, "-----END RSA PRIVATE KEY-----\n");

    fclose(file);
}

void write_public_key_to_pem(const char *filename, char *key) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error opening file: %s\n", filename);
        exit(EXIT_FAILURE);
    }

    fprintf(file, "-----BEGIN RSA PUBLIC KEY-----\n");

    size_t key_length = strlen(key);
    size_t segment_length = 64;
    for (size_t i = 0; i < key_length; i += segment_length) {
        fprintf(file, "%.*s\n", (int)(i + segment_length > key_length ? key_length - i : segment_length), key + i);
    }
    fprintf(file, "-----END RSA PUBLIC KEY-----\n");

    fclose(file);
}