/**
 * @file PRBG.h
 * @brief Measure the time it takes to perform a seed generation with PBKDF2.
 * @author Fábio Santos 1188351
 * @author Rodrigo Marques 118587
 * @date 23/12/2023
*/

#include "D-RSA.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    // Get the arguments
    if (argc != 4) {
        printf("Usage: ./randgen <password> <confusion_string> <iteration_count> \n");
        return 1;
    }

    // Assign the arguments
    uint8_t *password = (uint8_t *)malloc(strlen(argv[1]) + 1);
    uint8_t *confusion_string = (uint8_t *)malloc(strlen(argv[2]) + 1);

    if (password == NULL || confusion_string == NULL) {
        fprintf(stderr, "Error allocating memory.\n");
        exit(EXIT_FAILURE);
    }

    strncpy(password, argv[1], strlen(argv[1]));
    password[strlen(argv[1])] = '\0';
    strncpy(confusion_string, argv[2], strlen(argv[2]));
    confusion_string[strlen(argv[2])] = '\0';
    int iteration_count = atoi(argv[3]);

    // Generate the bootstrap_seed
    uint8_t bootstrap_seed[SEED_LEN];
    generate_seed(password, confusion_string, iteration_count, bootstrap_seed);
}