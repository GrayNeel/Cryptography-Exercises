#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#include <openssl/evp.h>

#define MAXBUF 1024
// First parameter is the name of the file to hash

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr,"Invalid parameters number usage: %s string_to_hash\n", argv[0]);
        exit(-1);
    }
    //char message[] = "This is the message to hash!!!";

    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
        printf("Couldn't open the input file, try again\n");
        exit(1);
    }

    // Best practise
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    unsigned char key[] = "01234567887654321"; // ASCII characters

    // Pointer to the data structure
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();

    // Init 
    if(!HMAC_Init_ex(hmac_ctx,key,strlen(key), EVP_sha1(), NULL)) 
        handle_errors();

    unsigned char buffer[MAXBUF];
    int n_read;
    while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0) {
        if(!HMAC_Update(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    // Feed the context with data to be used for the operation
    //EVP_DigestUpdate(md, argv[1], strlen(argv[1]));

    // Differently from digest the hmac size does not explicity
    // ask the name of a digest function but it needs to ask
    // the information about the output of the mark(?) directly from
    // the context
    unsigned char hmac_value[HMAC_size(hmac_ctx)];

    // How many data actually generated
    int hmac_len;

    // Finalize the digest
    if(!HMAC_Final(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    // Free memory
    HMAC_CTX_free(hmac_ctx);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("The HMAC is: ");
    for(int i=0;i<hmac_len;i++) {
        printf("%02x",hmac_value[i]);
    }
    printf("\n");

    // Can compare the result with
    // openssl hmac -sha1 input.txt

    return 0;
}