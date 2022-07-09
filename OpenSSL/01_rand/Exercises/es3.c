/**
 * Using OpenSSL, generate two 32 bit integers (int), multiply them (modulo 2^32) and print the result.
 */
#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define BYTES 4

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    unsigned char n1[BYTES], n2[BYTES];

    if(RAND_load_file("/dev/random",64) != 64)
        handle_errors(); 

    if((RAND_bytes(n1, BYTES) != 1) || (RAND_bytes(n2,BYTES) != 1))
        handle_errors();

    printf("N1: ");
    int res1 = 0;
    for(int i=0; i<BYTES*2 ; i++) {
        res1 += n1[(BYTES*2)-1]*pow(16,i);
    }
    printf("%d\n",res1);

    printf("N2: ");
    int res2 = 0;
    for(int i=0; i<BYTES*2 ; i++) {
        res2 += n2[(BYTES*2)-1]*pow(16,i);
    }
    printf("%d\n",res2);

    printf("Result: %d", res1*res2);

    return 0;
}