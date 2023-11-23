#include "PRBG.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]){
    
    // Get the arguments
    if (argc != 4){
        printf("Usage: ./randgen <password> <confusion_string> <iteration_count> \n");
        return 1;
    }

    // Assign the arguments
    char* password = argv[1];
    char* confusion_string = argv[2];
    int iteration_count = atoi(argv[3]);


    // Generate the bootstrap_seed
    unsigned char bootstrap_seed[SEED_LEN];
    generate_seed(password, confusion_string, iteration_count, bootstrap_seed);

    // Print the bootstrap_seed
    for (int i = 0; i < SEED_LEN; i++){
        printf("%02x ", bootstrap_seed[i]);
    }
    printf("\n");


    return 0;
}