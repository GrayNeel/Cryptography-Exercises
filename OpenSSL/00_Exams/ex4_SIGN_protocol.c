/**
 * The specification of the SIGN protocol includes the following operations:
 * - Generate a random 128-bit number, name it r1
 * - Generate a random 128-bit number, name it r2
 * - Concatenate them to obtain a 256-bit AES key name k
 * - Encrypt the content of the FILE *f_in; with AES and k and save it on the file FILE *f_out
 *   (assume both files have been properly opened)
 * - Generate the signature of the encrypted file FILE *f_out with the RSA keypair available
 *   as EVP_PKEY* rsa_key (properly loaded in advance).
 *
 *  Implement the protocol steps above in C, and make the proper decisions when the protocol omits
 *  information.
 **/ 
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>

#define ENCRYPT 1
#define MAX_ENC_LEN 1000000
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){
	ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
	  
	/* init the random engine: */
	int rc = RAND_load_file("/dev/random", 64);
	if(rc != 64) {
		handle_errors();
	}

	/* Generate r1 and r2 as 128-bit numbers */  
	unsigned char k1[16], k2[16];

    if(!RAND_bytes(k1,16))
        handle_errors();
    if(!RAND_bytes(k2,16))
        handle_errors();
	
	/* Create key variable that is the sum of both length (256 bit -> 32 bytes) */
	char k[16+16];
	
	/* Concatenate both strings into k */
	for(int i=0; i<16; i++) {
		k[i] = k1[i]
	}
	
	for(int i=16; i<16+16; i++) {
		hex_k[i] = k2[i]
	}
	
	/* Suppose they are already opened */
	FILE *f_in;
	FILE *f_out;
	
	/* Suppose to already have an IV */
	char *iv;
	
	/* Start encrypting with key k and iv on file */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(ctx,EVP_aes_256_cbc(), key, iv, ENCRYPT))
        handle_errors();

    
    int lenght;
    unsigned char ciphertext[MAX_BUFFER+16];

    int n_read;
    unsigned char buffer[MAX_BUFFER];


    while((n_read = fread(buffer,1,MAX_BUFFER,f_in)) > 0){
        if(!EVP_CipherUpdate(ctx,ciphertext,&lenght,buffer,n_read))
            handle_errors();

        if(fwrite(ciphertext, 1, lenght,f_out) < lenght){
            fprintf(stderr,"Error writing the output file\n");
            abort();
        }
    }
            
    if(!EVP_CipherFinal_ex(ctx,ciphertext,&lenght))
        handle_errors();

    printf("lenght=%d\n",lenght);

    if(fwrite(ciphertext,1, lenght, f_out) < lenght){
        fprintf(stderr,"Error writing in the output file\n");
        abort();
    }

	/* Rewind the file to read it again for signature */
	rewind(f_out);

	/* Close and free anything that is no more needed */
	fclose(f_in);

	BN_free(r1);
	BN_free(r2);
    EVP_CIPHER_CTX_free(ctx);
	
	/* Assume already loaded */
	EVP_PKEY* rsa_key;
	
	EVP_MD_CTX  *sign_ctx = EVP_MD_CTX_new();

	/* Choose sha256 for signature */
    if(!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, rsa_key))
            handle_errors();
    
    size_t n_read;
	
    while((n_read = fread(buffer,1,MAXBUFFER,f_out)) > 0){
        if(!EVP_DigestSignUpdate(sign_ctx, buffer, n_read))
            handle_errors();
    }

    unsigned char signature[EVP_PKEY_size(rsa_key)];
    size_t sig_len;
    size_t digest_len;
    
    if(!EVP_DigestSignFinal(sign_ctx, NULL, &digest_len))
        handle_errors();  


    if(!EVP_DigestSignFinal(sign_ctx, signature, &sig_len))
        handle_errors();

    EVP_MD_CTX_free(sign_ctx);
	
	fclose(f_out);
	
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	return 0;
}