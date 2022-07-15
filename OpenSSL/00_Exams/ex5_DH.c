// Sketch the Diffie-Hellman key agreement protocol in C using the OpenSSl library.
// Imagine you have a client CARL that starts communicating with a server SARA.
// CARL initiates the communication and proposes the public parameters.

// Assume you have access to a set of high-level communication primitives that allow
// you to send and receive big numbers and to properly format them (e.g., based on a BIO)
// so that you don't have to think about the communication issues for this exercise.

// void send_to_sara(BIGNUM b)
// BIGNUM receive_from_sara()
// void send_to_carl(BIGNUM b)
// BIGNUM receive_from_carl()

// Finally answer the following question: what CARL and SARA have to do if they want
// to generate an AES-256 key?

// Choose p and q
// Sara generates a secret A and perform q^a mod p and send to carl
// Carl generates a secret B and perform q^b mod p and send to sara
// Sara performs B^a mod p = K
// Carl performs A^b mod p = K

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

// Carl's side
int main() {
	ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
	
	BIGNUM *p=BN_new();
	BIGNUM *q=BN_new();
	BN_CTX *ctx=BN_CTX_new();
	
	int rc = RAND_load_file("/dev/random", 64);
	if(rc != 64) {
		handle_errors();
	}
	
	if (!BN_generate_prime_ex(p, 64*8, 0, NULL, NULL, NULL)) 
		handle_errors();
	
	if (!BN_generate_prime_ex(q, 64*8, 0, NULL, NULL, NULL)) 
		handle_errors();

	BIGNUM *b=BN_new();
	// b has to be max p-2 so i use 63 bytes numbers 
	BN_rand(b,63,0,1);

	// q^b mod p 
	BIGNUM *N1 = BN_new();
	if (!BN_mod_exp(N1,q,b,p,ctx)) {
		handle_errors();
	}

	send_to_sara(p);
	send_to_sara(q);
	send_to_sara(N1);
	
	BIGNUM *N2 = receive_from_sara();
	
	// Compute K 
	// A^b mod p = K
	
	BIGNUM *K = BN_new();
	if (!BN_mod_exp(K,N2,b,p,ctx)) {
		handle_errors();
	}
	
	BN_free(N1);
	BN_free(N2);
	
	BN_CTX_free(ctx);
	BN_free(p);
	BN_free(q);
	BN_free(k);
	
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	return 0;
}

// Finally answer the following question: what CARL and SARA have to do if they want
// to generate an AES-256 key?

// One of the two has to generate the AES-256 key using PRNG
// and then it will be encrypted using the key K obtained from DH as
// AES*K mod p = AES_KEY
// The other side will decrypt it with AES_KEY*K^-1 mod p
// And both will have the AES-256 key.