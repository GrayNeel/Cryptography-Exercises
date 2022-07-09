#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>

#define MAX 128

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    unsigned char r1[MAX], r2[MAX];
    
    if(RAND_load_file("/dev/random",64) != 64)
        handle_errors(); 

    if((RAND_bytes(r1,MAX) != 1) || (RAND_bytes(r2,MAX) != 1))
        handle_errors();
    
    int i;
    unsigned char res[MAX];

    for(i=0; i<MAX; i++) {
        res[i] = r1[i] ^ r2[i];
    }

    printf("XORed string: ");
    for(i=0; i<MAX; i++) {
        printf("%02x-",res[i]);
    }

    return 0;
}