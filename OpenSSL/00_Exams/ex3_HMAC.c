/**
 * The program has to check if the computed mac equals
 * the one passed as the second parameter of the command line
 * the program return 0 if the comparison is successfull.
 * The hmac key is stored on the file /keys/hmac_key
 * The mac needs to be computed using hmac-sha256
 * 
 **/

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    if(argc != 3){
        fprintf(stderr,"Invalid parameters. Usage: %s filename HMAC\n",argv[0]);
        exit(1);
    }

    /* Open file to compute mac */
    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }

    /* Hmac to be checked */
    unsigned char hmac_binary[strlen(argv[2])/2];
    for(int i = 0; i < strlen(argv[2])/2;i++){
        sscanf(&argv[2][2*i],"%2hhx", &hmac_binary[i]);
    }

    /* Hmac key loading */
    FILE *f_key;
    if((f_key = fopen("/keys/hmac_key","r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }
    
    unsigned char keybuf[MAXBUF];
    if(fread(keybuf,1,MAXBUF,f_key) < 0)
        exit(1);
    fclose(f_key);

    unsigned char key[strlen(keybuf)/2];
    for(int i = 0; i < strlen(keybuf)/2;i++){
        sscanf(&keybuf[2*i],"%2hhx", &key[i]);
    }

    HMAC_CTX  *hmac_ctx = HMAC_CTX_new();

    if(!HMAC_Init_ex(hmac_ctx, key, strlen(key), EVP_sha256(), NULL))
        handle_errors();

    int n;
    unsigned char buffer[MAXBUF];
    while((n = fread(buffer,1,MAXBUF,f_in)) > 0){
        if(!HMAC_Update(hmac_ctx, buffer, n))
            handle_errors();
    }

    unsigned char hmac_value[HMAC_size(hmac_ctx)];
    int hmac_len;


    if(!HMAC_Final(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    HMAC_CTX_free(hmac_ctx);

    if( (hmac_len == (strlen(argv[2])/2)) && (CRYPTO_memcmp(hmac_binary, hmac_value, hmac_len) != 0))
        handle_errors();

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();

    return 0;
}