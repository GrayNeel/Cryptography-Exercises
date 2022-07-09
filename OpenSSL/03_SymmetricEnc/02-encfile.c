#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

//argv[1] -> Input file
//argv[2] -> key (hexstring)
//argv[3] -> IV (hexstring)
//Save in a buffer in memory the result of the encryption


int main(int argc, char **argv) {
   
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if( argc != 5 ) {
        printf("Invalid parameters. Usage %s input_file key IV\n", argv[0]);
        exit(-1);
    } 

    FILE *f_in;

    if((f_in=fopen(argv[1],"r")) == NULL) {
        printf("Errors opening the input file: %s\n", argv[1]);
        exit(-1);
    }

    if(strlen(argv[2])/2 != 32) {
        printf("Wrong key length: %s\n", argv[2]);
        exit(-1);
    }

    unsigned char key[strlen(argv[2])/2];

    for(int i=0;i<strlen(argv[2])/2;i++) {
        sscanf(&argv[2][2*i], "%2hhx", &key[i]);
    }


    if(strlen(argv[3])/2 != 32) {
        printf("Wrong IV length: %s\n", argv[3]);
        exit(-1);
    }

    FILE *f_out;

    if((f_out=fopen(argv[4],"wb")) == NULL) {
        printf("Errors opening the output file: %s\n", argv[4]);
        exit(-1);
    }

    unsigned char iv[strlen(argv[3])/2];

    for(int i=0;i<strlen(argv[3])/2;i++) {
        sscanf(&argv[3][2*i], "%2hhx", &key[i]);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(ctx==NULL)
        abort();

    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    unsigned char buffer[MAXBUF];
    int n_read;

    unsigned char ciphertext[MAXBUF+16];
    int length;
    int ciphertext_len = 0;

    while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0) {

        if(!EVP_CipherUpdate(ctx, ciphertext, &length, buffer, n_read))
            handle_errors();

        ciphertext_len+=length;

        if(fwrite(ciphertext,1,length,f_out) < length) {
            fprintf(stderr,"Error writing into the output file.\n");
            abort();
        }
    }

    if(!EVP_CipherFinal(ctx, ciphertext,&length))
        handle_errors();
        
    if(fwrite(ciphertext,1,length,f_out) < length) {
        fprintf(stderr,"Error writing into the output file.\n");
        abort();
    }

    ciphertext_len+=length;

    EVP_CIPHER_CTX_free(ctx);

    printf("Size of the ciphertext: %d\n", ciphertext_len);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    fclose(f_in);
    fclose(f_out);
    
    return 0;
}