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

    unsigned char key[] = "1234567890abcdef"; //ASCII 16 Bytes = 128 bit
    unsigned char iv[] = "abcdef1234567890"; //ASCII
    unsigned char ciphertext[] = "13713c9b8081468892c518592730b3496d2c58ed3a9735d90788e7c24e8d324d75f6c9f5c6e43ee7dccad4a3221d697e";

    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, DECRYPT))
        handle_errors();

    // At most as long as ciphertext
    unsigned char plaintext[strlen(ciphertext)/2];

    unsigned char ciphertext_bin[strlen(ciphertext)/2];

    for(int i=0;i<strlen(ciphertext)/2;i++) {
        sscanf(&ciphertext[2*i], "%2hhx", &ciphertext_bin[i]);
    }

    int length;
    int plaintext_len = 0;

    EVP_CipherUpdate(ctx, plaintext, &length, ciphertext_bin, strlen(ciphertext)/2);

    printf("After update: %d\n", length);
    plaintext_len += length;

    EVP_CipherFinal(ctx, ciphertext+plaintext_len,&length);
    printf("After final: %d\n", length);
    plaintext_len+=length;

    EVP_CIPHER_CTX_free(ctx);

    // If not sure allocate more bytes up
    plaintext[plaintext_len]='\0';

    printf("Size of the plaintext: %d\n", plaintext_len);
    printf("Plaintext: %s\n", plaintext);
    return 0;
}