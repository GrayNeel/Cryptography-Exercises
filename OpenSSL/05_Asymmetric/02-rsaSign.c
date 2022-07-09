#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define MAXBUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

// argv[1] is the name of the file to sign
// argv[2] is the name of the file where the private key is stored

int main(int argc, char **argv) {
    
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if(argc != 3) {
        fprintf(stderr, "Invalid parameters. Usage: %s file_to_sign file_key\n", argv[0]);
        exit(1);
    }
    
    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
        fprintf(stderr, "Couldn't open the input file, try again\n");
        exit(1);
    }

    FILE *f_key;
    if((f_in = fopen(argv[2],"r")) == NULL) {
        fprintf(stderr, "Couldn't open the key file, try again\n");
        exit(1);
    }

    // DigestSign --> EVP PKEY * 
    EVP_PKEY *private_key = PEM_read_PrivateKey(f_key, NULL, NULL, NULL);
    fclose(f_key);

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
 
    if(!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, private_key))
        handle_errors();

    unsigned char buffer[MAXBUFFER];
    size_t n_read;

    while((n_read = fread(buffer, 1, MAXBUFFER, f_in)) > 0) {
        if(!EVP_DigestSignUpdate(sign_ctx, buffer, n_read))
            handle_errors();
    }

    fclose(f_in);

    unsigned char signature[EVP_PKEY_size(private_key)];
    size_t sig_len;
    size_t dgst_len;

    if(!EVP_DigestSignFinal(sign_ctx, NULL, &dgst_len))
        handle_errors();

    if(!EVP_DigestSignFinal(sign_ctx, signature, &sig_len))
        handle_errors();

    EVP_MD_CTX_free(sign_ctx);

    FILE *out;
    if((out = fopen("signature.bin","w")) == NULL) {
        fprintf(stderr, "Couldn't create the signature file, try again\n");
        exit(1);
    }

    if(fwrite(signature, 1, sig_len, out) < sig_len)
        handle_errors(); 

    fclose(out);
    printf("Signature written!\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}