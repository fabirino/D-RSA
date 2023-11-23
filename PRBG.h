#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define SEED_LEN 32      // size of the seed in bytes
// #define SALT_LEN 16     // size of the salt in bytes

/**
 * @brief Generates a seed from the provided password, confusion string, and iteration count.
 * @param password The password to use.
 * @param confusion_string The confusion string to use.
 * @param iteration_count The number of iterations to use.
 * @param seed The buffer to store the generated seed in.
*/
void generate_seed(const char *password, const char *confusion_string, int iteration_count, unsigned char *seed);

