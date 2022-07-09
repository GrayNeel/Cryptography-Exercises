#include <stdio.h>

#include <openssl/bn.h>

int main() {
    char num_string[] = "1234512345123451234512345123451234512346";
    char hex_string[] = "3A0BE6DE14A23197B6FE071D5EBBD6DD9";

    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();

    BN_dec2bn(&bn1, num_string);
    BN_print_fp(stdout, bn1);
    printf("\n");

    BN_hex2bn(&bn2, hex_string);
    BN_print_fp(stdout, bn2);
    printf("\n");

    if(BN_cmp(bn1, bn2) == 0) {
        printf("BN1 and BN2 are equal\n");
    } else {
        printf("BN1 and BN2 are different\n");
    }

    printf("bn1 = %s", BN_bn2hex(bn1));
    printf("bn1 = %s", BN_bn2dec(bn1));

    BN_free(bn1);
    BN_free(bn2);

    return 0;
}