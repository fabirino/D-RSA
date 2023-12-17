#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SEED_LEN 16         // size of the seed in bytes (16 because the iv of AES is 16 bytes)
#define OUTPUT_BYTES 32     // number of bytes to generate
#define KEY_LENGTH  2048    // RSA key length

// ============================================================
// ======================== RANDGEN ===========================
// ============================================================

/**
 * @brief Generates a seed from the provided password, confusion string, and iteration count.
 * @param password The password to use.
 * @param confusion_string The confusion string to use.
 * @param iteration_count The number of iterations to use.
 * @param seed The buffer to store the generated seed in.
 */
void generate_seed(const char *password, const uint8_t *confusion_string, int iteration_count, uint8_t *bootstrap_seed);

int compare_arrays(uint8_t *array1, size_t len1, uint8_t *array2, size_t len2);

/**
 * @brief Uses a PRBG to produce a stream of random bytes
 * @param seed The seed to initialize the PRBG.
 * @param output The buffer to store the generated pseudo-random bytes.
 */
void generate_bytes(uint8_t *seed, uint8_t *password, uint8_t *confusion_string, int iteration_count, uint8_t *output);

// ============================================================
// ======================== RSAGEN ============================
// ============================================================

uint8_t *read_msg_bytes(uint64_t *bytes_read);

RSA *generate_RSA_key_pair();

void write_private_key_to_pem(const char *filename, const char *header, const unsigned char *key, RSA *rsa_key);

void write_public_key_to_pem(const char *filename, const char *header, RSA *rsa_key);