#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
   
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(ctx == NULL)
        abort();

    unsigned char key[] = "1234567890abcdef"; //ASCII 16 Bytes = 128 bit
    unsigned char iv[] = "abcdef1234567890"; //ASCII

    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();


    unsigned char plaintext[] = "This variable contains the data to encrypt"; // 42 bytes
    // 48 is the first multiple of 16
    unsigned char ciphertext[48];

    int length;
    int ciphertext_len = 0;

    if(!EVP_CipherUpdate(ctx, ciphertext, &length, plaintext, strlen(plaintext)))
        handle_errors();

    printf("After update: %d\n", length);
    ciphertext_len += length;

    // Write the new output from ciphertext len bytes after the beginning of the cyphertext buffer
    if(!EVP_CipherFinal(ctx, ciphertext+ciphertext_len,&length))
        handle_errors();

    printf("After final: %d\n", length);
    ciphertext_len+=length;

    EVP_CIPHER_CTX_free(ctx);

    printf("Size of the ciphertext: %d\n", ciphertext_len);

    for(int i=0; i<ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }    
    printf("\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}