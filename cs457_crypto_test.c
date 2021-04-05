/**
 * @file cs457_crypto_test.c
 * @author Fanourakis Nikos (csd4237@csd.uoc.gr)
 * @brief Test for cryptographic library cs457_crypto
 * 
 */

#include "cs457_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>



int main(int argc, char *argv[])
{
    uint8_t *key, *plaintext, *ciphertext, *result;
    uint8_t feistel_keys[NUM_OF_ROUNDS][(BLOCK_SIZE / 2) + 1];
    FILE *output, *input;
    int opt, algorithm;
    char *file_name;
    size_t counter, plaintext_size;
    unsigned char **key_matrix;

    output = stdout;
    input = stdin;
    algorithm = ONE_TIME_PAD;
    while ((opt = getopt(argc, argv, "i:o:1cpafh")) != -1)
    {
        switch (opt)
        {
        case 'i':
            file_name = strdup(optarg);
            if (!(input = fopen(file_name, "r")))
            {
                fprintf(stderr, "Cannot read file: %s\n", file_name);
                free(file_name);
                return -1;
            }
            free(file_name);
            break;
        case 'o':
            file_name = strdup(optarg);
            if (!(output = fopen(file_name, "w+")))
            {
                fprintf(stderr, "Cannot open file: %s\n", file_name);
                free(file_name);
                return -1;
            }
            free(file_name);
            break;
        case '1':
            algorithm = ONE_TIME_PAD;
            break;
        case 'c':
            algorithm = CAESAR_CIPHER;
            break;
        case 'p':
            algorithm = PLAYFAIR_CIPHER;
            break;
        case 'a':
            algorithm = AFFINE_CIPHER;
            break;
        case 'f':
            algorithm = FEISTEL_CIPHER;
            break;
        case 'h':
            printf(
                "Options:\n"
                "   -i \"inputfile\"      The input file.\n"
                "   -o \"outputfile\"     The output file.\n"
                "   -1                  If set, the program uses one time pad algorithm for the cryptography.\n"
                "   -c                  If set, the program uses caesar's cipher algorithm for the cryptography.\n"
                "   -p                  If set, the program uses playfair cipher algorithm for the cryptography.\n"
                "   -a                  If set, the program uses affine cipher algorithm for the cryptography.\n"
                "   -f                  If set, the program uses feistel cipher algorithm for the cryptography.\n"
                "   -h                  Prints this help\n"
                "By default:\n"
                "   Input file stream is stdin.\n"
                "   Output file stream is stdout.\n"
                "   Cryptography algorithm is one time pad.\n");
            return 0;
        default:
            printf("Wrong command line arguments. Type -i for input file and -o for output file.\n");
            return -1;
        }
    }

    plaintext = read_plaintext(input);
    plaintext_size = strlen((char *)plaintext);
    fprintf(output, "Plaintext:\n%s\n", plaintext);
    fprintf(output, "Plaintext len: %lu\n\n", plaintext_size);
    if (algorithm == ONE_TIME_PAD)
    {
        printf("You chose one time pad algorithm for your encryption.\n");
        key = key_generator(plaintext_size);
        fprintf(output, "Key: %s\n", key);
        fprintf(output, "Key len: %lu\n\n", strlen((char *)key));
        ciphertext = otp_encrypt(plaintext, key);
        fprintf(output, "Ciphertext:\n%s\n", ciphertext);
        fprintf(output, "Ciphertext len: %lu\n\n", strlen((char *)ciphertext));
        result = otp_decrypt(ciphertext, key);
        free(key);
    }
    else if (algorithm == CAESAR_CIPHER)
    {
        printf("You chose caesar's cipher algorithm for your encryption.\n");
        printf("N == %hu\n", NUM);
        ciphertext = caesar_encrypt(plaintext, NUM);
        fprintf(output, "Ciphertext:\n%s\n", ciphertext);
        fprintf(output, "Ciphertext len: %lu\n\n", strlen((char *)ciphertext));
        result = caesar_decrypt(ciphertext, NUM);
    }
    else if (algorithm == PLAYFAIR_CIPHER)
    {
        printf("You chose playfair cipher algorithm for your encryption.\n");
        key_matrix = playfair_keymatrix((unsigned char *)"HELLO WORLD");
        print_keymatrix(key_matrix);

        ciphertext = playfair_encrypt(plaintext, key_matrix);
        fprintf(output, "Ciphertext:\n%s\n", ciphertext);
        fprintf(output, "Ciphertext len: %lu\n\n", strlen((char *)ciphertext));
        result = playfair_decrypt(ciphertext, key_matrix);
        for (counter = 0; counter < 5; counter++)
        {
            free(*(key_matrix + counter));
        }
        free(key_matrix);
    }
    else if (algorithm == AFFINE_CIPHER)
    {
        printf("You chose affine cipher algorithm for your encryption.\n");
        ciphertext = affine_encrypt(plaintext);
        fprintf(output, "Ciphertext:\n%s\n", ciphertext);
        fprintf(output, "Ciphertext len: %lu\n\n", strlen((char *)ciphertext));
        result = affine_decrypt(ciphertext);
    }
    else if (algorithm == FEISTEL_CIPHER)
    {
        printf("You chose feistel cipher algorithm for your encryption.\n");
        ciphertext = feistel_encrypt(plaintext, feistel_keys);
        fprintf(output, "Ciphertext:\n%s\n", ciphertext);
        fprintf(output, "Ciphertext len: %lu\n\n", strlen((char *)ciphertext));
        result = feistel_decrypt(ciphertext, feistel_keys, plaintext_size);
    }

    fprintf(output, "Message:\n%s\n", result);
    fprintf(output, "Result len: %lu\n", strlen((char *)result));
    free(result);
    free(ciphertext);
    free(plaintext);
    fclose(output);
    fclose(input);
    return 0;
}