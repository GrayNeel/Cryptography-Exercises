/**
 * The specification of the CRAZY protocol includes the following operations:
 * 
 * 1. Generate two strong random 128-bit integers, name them rand1 and rand2
 * 
 * 2. Obtain the first key as
 * k1 = (rand1 + rand2) * (rand1 - rand2) mod 2^128
 * 
 * 3. Obtain the second key as
 * k2 = (rand1 * rand2) / (rand1 - rand2) mod 2^128
 * 
 * 4. Encrypt k2 using k1 using a stron encryption algorithm (and mode) of your choice
 * call it enc_k2.
 * 
 * 5. Generate an RSA keypair with a 2048 bit modulus.
 * 
 * 6. Encrypt enc_k2 using the just generated RSA key.
 * 
 * Implement in C the protocol steps described above, make the proper decisions when
 * the protocol omits information.
 * 
 **/

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#define ENCRYPT 1
#define DECRYPT 0

#define BITS 128

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {
    
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    BIGNUM *rand1=BN_new();
    BIGNUM *rand2=BN_new();
    BN_CTX *ctx=BN_CTX_new();

    // Generate randoms
    BN_rand(rand1,BITS,0,1);
    BN_rand(rand2,BITS,0,1);

    // Generating k1
    BIGNUM *sum=BN_new();
    BN_add(sum,rand1,rand2);
  
    BIGNUM *sub=BN_new();
    BN_sub(sub,rand1,rand2);

    BIGNUM *mul=BN_new();
    BN_mul(mul,sum,sub,ctx);

    // Generate 2^128 bignum modulus
    BIGNUM *mod=BN_new();
    BIGNUM *base=BN_new();
    BIGNUM *exp=BN_new();

    BN_set_word(base,2);
    BN_set_word(exp,128);

    BN_exp(mod,base,exp,ctx);

    // Calculate mod
    BIGNUM *k1=BN_new();
    BN_mod(k1,mul,mod,ctx);

    // Calculate k2
    BN_mul(mul,rand1,rand2,ctx);
    BIGNUM *div=BN_new();
    BN_div(div,NULL,mul,sub,ctx);

    BIGNUM *k2=BN_new();
    BN_mod(k2,div,mod,ctx);

    BN_free(rand1);
    BN_free(rand2);
    BN_free(sum);
    BN_free(sub);
    BN_free(mul);
    BN_free(mod);
    BN_free(base);
    BN_free(exp);
    BN_free(div);

    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();

    char *c_k1 = BN_bn2hex(k1);
	char *c_k2 = BN_bn2hex(k2);
    char *iv;

    if(!EVP_CipherInit(aes_ctx, EVP_aes_128_cbc(), c_k1, iv, ENCRYPT))
        handle_errors();

    unsigned char enc_k2[strlen(c_k2)+16];

    int update_len, final_len;
    int ciphertext_len=0;

    if(!EVP_CipherUpdate(ctx,enc_k2,&update_len, c_k2,strlen(c_k2)))
        handle_errors();

    ciphertext_len+=update_len;

    if(!EVP_CipherFinal_ex(ctx,enc_k2+ciphertext_len,&final_len))
        handle_errors();

    ciphertext_len+=final_len;

    RSA *rsa_keypair = NULL;
    BIGNUM *bne = NULL;

    int bits = 2048;
    unsigned long e = RSA_F4;

    bne = BN_new();
    if(!BN_set_word(bne,e))
        handle_errors();

    rsa_keypair = RSA_new();
    if(!RSA_generate_key_ex(rsa_keypair, bits, bne, NULL)) /* callback not needed for our purposes */
        handle_errors();

    BN_free(bne);
    
    int encrypted_data_len;
    unsigned char encrypted_data[RSA_size(rsa_keypair)];


    if((encrypted_data_len = RSA_public_encrypt(strlen(enc_k2), enc_k2, encrypted_data, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1) 
            handle_errors();
    
    EVP_CIPHER_CTX_free(ctx);

    RSA_free(rsa_keypair);

	BN_CTX_free(ctx);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    return 0;
}