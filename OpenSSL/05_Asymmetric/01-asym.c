#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    
    // Programmatically generate RSA key
    RSA *rsa_keypair;
    BIGNUM *bne = BN_new();
    if(!BN_set_word(bne, RSA_F4))
        handle_errors();

    rsa_keypair = RSA_new();

    if(!RSA_generate_key_ex(rsa_keypair, 2048, bne, NULL))
        handle_errors();

    FILE *rsa_file;
    if((rsa_file = fopen("private.pem", "w")) == NULL) {
        fprintf(stderr, "Problems creating the file\n");
        abort();
    }

    if(!PEM_write_RSAPrivateKey(rsa_file, rsa_keypair, NULL, NULL, 0, NULL, NULL))
        handle_errors();

    fclose(rsa_file);

    if((rsa_file = fopen("public.pem", "w")) == NULL) {
        fprintf(stderr, "Problems creating the file\n");
        abort();
    }

    if(!PEM_write_RSA_PUBKEY(rsa_file, rsa_keypair))
        handle_errors();

    fclose(rsa_file);

    ////////////////////////////////////////////////
    unsigned char msg[] = "This is the message to encrypt\n";
    unsigned char encrypted_msg[RSA_size(rsa_keypair)];

    int encrypted_len;

    encrypted_len = RSA_public_encrypt(strlen(msg)+1, msg, encrypted_msg, rsa_keypair, RSA_PKCS1_OAEP_PADDING);

    if(encrypted_len == -1)
        handle_errors();

    FILE *out;
    if((out = fopen("encrypted.enc", "w")) == NULL) {
        fprintf(stderr, "Problems creating the file\n");
        abort();
    }

    if(fwrite(encrypted_msg, 1, encrypted_len, out) < encrypted_len) {
        fprintf(stderr, "Problems saving onto file\n");
        abort();
    }

    fclose(out);
    printf("File saved!\n");

    ////////////////////////////////////////////////
    printf("I'm reading the encrypted file...\n");

    // Here encrypted_msg can be used again

    FILE *in;
    if((in = fopen("encrypted.enc", "r")) == NULL) {
        fprintf(stderr, "Problems reading the file\n");
        abort();
    }
    
    if( (encrypted_len = fread(encrypted_msg, 1, RSA_size(rsa_keypair), in)) != RSA_size(rsa_keypair)) {
        fprintf(stderr, "Problems reading the file\n");
        abort();
    }
    fclose(in);

    unsigned char decrypted_msg[RSA_size(rsa_keypair)];

    if(RSA_private_decrypt(encrypted_len, encrypted_msg, decrypted_msg, rsa_keypair, RSA_PKCS1_OAEP_PADDING) == -1)
        handle_errors();

    printf("Dec mes: %s\n", decrypted_msg);

    RSA_free(rsa_keypair);
    BN_free(bne);


    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}