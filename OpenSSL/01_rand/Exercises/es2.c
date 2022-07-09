/**
 * Writes a program in C that, using the OpenSSL library, generates randomly the private key 
 * to be used for encrypting data with AES128 in CBC and the needed IV. 
 * Pay attention to select the proper PRNG.
 */
#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define PSIZE 128
#define IVSIZE 16

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    unsigned char iv[IVSIZE], key[PSIZE];

    if(RAND_load_file("/dev/random",64) != 64)
        handle_errors(); 

    if((RAND_bytes(iv,IVSIZE) != 1) || (RAND_priv_bytes(key,PSIZE) != 1))
        handle_errors();

    printf("Private key: ");
    for(int i=0; i<PSIZE ; i++) {
        printf("%02x",key[i]);
    }
    printf("\n");

    printf("IV: ");
    for(int i=0; i<IVSIZE ; i++) {
        printf("%02x",iv[i]);
    }

    return 0;
}