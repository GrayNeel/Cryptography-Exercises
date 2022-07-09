#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/err.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main() {
    ERR_load_crypto_strings();

    char num_string[] = "1234512345123451234512345123451234512346";
    char hex_string[] = "3A0BE6DE14A23197B6FE071D5EBBD6DD9";

    BIGNUM *prime1 = BN_new();
    BIGNUM *prime2 = BN_new();

    // ex1 needs also a context

    // ex if openssl 1.1, deprecated in 3.0
    // prime1 where to safe
    // 1024 = minimum length in bits of generated prime
    // safe = if (p-1)/2 is also a prime
    // add, rem -->?  p  
    // p % add == rem
    // if rem is NULL --> rem = 1
    // if rem is NULL and safe is true --> rem = 3 add must be multiple of 4.
    // cb = connects the output with process generation
    
    if(!BN_generate_prime_ex(prime1, 1024, 0, NULL, NULL, NULL))
        handle_errors();

    BN_print_fp(stdout, prime1);
    puts("");

    if(BN_is_prime_ex(prime1, 16, NULL, NULL))
        printf("It is a prime number\n");
    else
        printf("It is not a prime number\n");
    //BN_check_prime(prime1, ctx, cb)

    BN_set_word(prime2, 16);
    if(BN_is_prime_ex(prime2, 16, NULL, NULL))
        printf("It is a prime number\n");
    else
        printf("It is not a prime number\n");

    printf("Bits p1: %d\n", BN_num_bytes(prime1));
    printf("Bits p2: %d\n", BN_num_bytes(prime2));


    BN_free(prime1);
    BN_free(prime2);

    ERR_load_crypto_strings();
    return 0;
}