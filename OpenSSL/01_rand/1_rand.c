#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define MAX 128

void handle_errors() {
    // Library for simple err handling
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    // Allocate space in memory to store generated sequence
    unsigned char random_string[MAX];

    // To perform initialization of PRNG we do so
    //Load file may fail
    if(RAND_load_file("/dev/random",64) != 64) { // Not needed more than 64
        handle_errors();
        //fprintf(stderr,"Error with PRNG initialization\n");
        //return -1;
    }  
    
    // It can file too. Return 1 on success, -1 if not supported, 0 on other failure
    if(RAND_bytes(random_string, MAX) != 1) {
        handle_errors();
        //fprintf(stderr,"Error with PRNG generation");
        //return -1;
    }

    //Can't use standard string print
    printf("Sequence generated: ");
    for(int i=0;i<MAX;i++) 
        printf("%02x-",random_string[i]);
    printf("\n");

    return 0;
}