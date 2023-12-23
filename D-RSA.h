/**
 * @file D-RSA.h
 * @brief Header file for PRBG.
 * @author Fábio Santos 1188351
 * @author Rodrigo Marques 118587
 * @date 23/12/2023
*/

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#define SEED_LEN 16         // size of the seed in bytes (16 because the iv of AES is 16 bytes)
#define OUTPUT_BYTES 32     // number of bytes to generate

typedef struct rsa_key_pair {
    unsigned char *public_key;
    unsigned char *private_key;
} rsa_key_pair;

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

/**
 * @brief Uses a PRBG to produce a stream of random bytes
 * @param seed The seed to initialize the PRBG.
 * @param password The password to use.
 * @param confusion_string The confusion string to find.
 * @param iteration_count The number of iterations to use.
 * @param PRN Pseudo-random stream of bytes.
 */
void generate_bytes(uint8_t *seed, uint8_t *password, uint8_t *confusion_string, int iteration_count, uint8_t *PRB);

// ============================================================
// ======================== RSAGEN ============================
// ============================================================

/**
* @brief reads message from stdin and stores it in an array of bytes
* @param bytes_read number of bytes read
* @return array of bytes containing the message
*/
uint8_t *read_msg_bytes(uint64_t *bytes_read);

/**
 * @brief Generates a RSA key pair
 * @param pseudo_rand_num The pseudo-random number to use.
 * @return Structu containing the RSA key pair.
*/
rsa_key_pair *generate_RSA_key_pair(uint8_t *pseudo_rand_num);

/**
 * @brief Writes the private key to a PEM file
 * @param filename The name of the file to write to
 * @param key The private key to write.
*/
void write_private_key_to_pem(const char *filename, char *key);

/**
 * @brief Writes the public key to a PEM file
 * @param filename The name of the file to write to
 * @param key The public key to write.
*/
void write_public_key_to_pem(const char *filename, char *key);