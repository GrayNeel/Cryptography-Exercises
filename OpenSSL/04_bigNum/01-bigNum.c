#include <stdio.h>

#include <openssl/bn.h>

int main() {
    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();

    BN_print_fp(stdout, bn1);
    printf("\n");
    
    // Transform a long to a BN
    BN_set_word(bn1, 12300000);
    BN_print_fp(stdout, bn1);
    printf("\n");

    BN_set_word(bn2, 124);
    BN_print_fp(stdout, bn2);
    printf("\n");

    BIGNUM *res = BN_new();
    BN_add(res, bn1, bn2);
    BN_print_fp(stdout, res);
    printf("\n");

    BN_CTX *ctx = BN_CTX_new();
    BN_mod(res, bn1, bn2, ctx);
    BN_print_fp(stdout, res);
    printf("\n");

    BN_free(bn1);
    BN_free(bn2);
    BN_free(res);
    BN_CTX_free(ctx);

    return 0;
}