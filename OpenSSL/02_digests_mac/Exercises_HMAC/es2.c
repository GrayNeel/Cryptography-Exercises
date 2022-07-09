/**
 * @file es2.c
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2022-07-06
 * 
 * @copyright Copyright (c) 2022
 * 
 * 2. Write a program in C that, using the OpenSSL library, verifies that the HMAC 
 * of a file computed using SHA256 (or or SHA 512 or SHA3) equals the value that is 
 * passed as the first parameter from the command line.
 * The filename is passed as the second parameter from the command line.
 */
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
    if(argc != 3) {
        fprintf(stderr,"Invalid parameters number usage: %s string_to_check file_to_check\n", argv[0]);
        exit(-1);
    }
    //char message[] = "This is the message to hash!!!";

    if(argv[1] == NULL) {
        printf("Invalid check string, try again\n");
        exit(1);
    }

    FILE *f_in;
    if((f_in = fopen(argv[2],"r")) == NULL) {
        printf("Couldn't open the input file, try again\n");
        exit(1);
    }

    // Best practise
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    unsigned char key[] = "01234567887654321"; // ASCII characters
    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key));

    // Pointer to the data structure
    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();
    
    // Init - second parameter is for digital signature (PubKMat) 
    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha1(), NULL, hmac_key))
        handle_errors();

    unsigned char buffer[MAXBUF];
    int n_read;
    while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0) {
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    // Feed the context with data to be used for the operation
    //EVP_DigestUpdate(md, argv[1], strlen(argv[1]));

    // Differently from digest the hmac size does not explicity
    // ask the name of a digest function but it needs to ask
    // the information about the output of the mark(?) directly from
    // the context
    unsigned char hmac_value[EVP_MD_size(EVP_sha1())];

    // How many data actually generated
    size_t hmac_len;

    // Finalize the digest
    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    // Free memory
    EVP_MD_CTX_free(hmac_ctx);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("The HMAC is: ");
    for(int i=0;i<hmac_len;i++) {
        printf("%02x",hmac_value[i]);
    }
    printf("\n");
    // /2 because we start from hexadecimal to binary
    unsigned char hmac_binary[strlen(argv[1])/2];

    for(int i=0; i < strlen(argv[1])/2; i++) {
        // Transform hexa to binary
        // h = half the size, double because we go from 32 bits to 16 to 8 (1 byte)
        sscanf(&argv[1][2*i], "%2hhx", &hmac_binary[i]);

    }

    // Length actual comparison of the buffers
    // this hmac_len is different from 03 ex because
    // we recompute again the mac to compare it with the one
    // provided in the hmac variable
    if((hmac_len == strlen(argv[1])/2) && (CRYPTO_memcmp(hmac_binary, hmac_value, hmac_len) == 0)) {
        printf("Verification successful");
    } else 
        printf("Verification failure");

    // Can compare the result with
    // openssl hmac -sha1 input.txt

    return 0;
}