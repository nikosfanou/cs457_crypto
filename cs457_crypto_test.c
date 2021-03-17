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

/* Some helpful functions */

/**
 * @brief Creates a key with the same size as plaintext using /dev/urandom.
 * 
 * @param plaintext Message to be encrypted
 * @return uint8_t* Returns the key
 */
uint8_t *key_generator(uint8_t *plaintext)
{
    size_t key_size;
    uint8_t *key;
    FILE *randomData;
    size_t randomDataLen;
    size_t read_result;

    assert(plaintext);
    key_size = strlen((char *)plaintext);
    randomData = fopen("/dev/urandom", "r");

    if (!randomData)
    {
        fprintf(stderr, "Failed to open /dev/urandom.\n");
        exit(EXIT_FAILURE);
    }
    randomDataLen = 0;
    key = (uint8_t *)malloc(sizeof(uint8_t) * (key_size + 1));
    memset(key, 0, sizeof(uint8_t) * (key_size + 1));
    while (randomDataLen < key_size)
    {
        read_result = fread(key + randomDataLen, sizeof(uint8_t), sizeof(uint8_t), randomData);
        if (*(key + randomDataLen) == '\0') /*  ayto mporei na fygei tlk an h readplaintext de krataei ta special character. */
        {
            continue;
        }
        randomDataLen += read_result;
    }
    *(key + key_size) = '\0';
    fclose(randomData);
    return key;
}

/**
 * @brief Reads the content of the input file and copies it on a string. Then returns
 * the string.
 * 
 * @param input_message Pointer on the input file
 * @return uint8_t* Message to be encrypted
 */
uint8_t *read_plaintext(FILE *input_message)
{
    int c;
    int counter;
    size_t length;
    uint8_t *plaintext;

    assert(input_message);
    length = 0;
    if (input_message == stdin)
    {
        counter = 1;
        plaintext = malloc(sizeof(uint8_t) * (counter * INIT_INPUT_SIZE) + 1);
        if (!plaintext)
        {
            fprintf(stderr, "Malloc failed in read_plaintext().\n");
            exit(EXIT_FAILURE);
        }

        c = fgetc(input_message);
        while (!feof(input_message))
        {
            if (length == counter * INIT_INPUT_SIZE)
            {
                counter++;
                plaintext = realloc(plaintext, sizeof(uint8_t) * (counter * INIT_INPUT_SIZE) + 1);
                if (!plaintext)
                {
                    fprintf(stderr, "Realloc failed in read_plaintext().\n");
                    exit(EXIT_FAILURE);
                }
            }
            *(plaintext + length) = (uint8_t)c;
            length++;
            c = fgetc(input_message);
        }
    }
    else
    {
        fseek(input_message, 0, SEEK_END);
        length = ftell(input_message);
        fseek(input_message, 0, SEEK_SET);
        plaintext = malloc(sizeof(uint8_t) * (length + 1));
        if (!plaintext)
        {
            fprintf(stderr, "Malloc failed in read_plaintext().\n");
            exit(EXIT_FAILURE);
        }
        fread(plaintext, sizeof(uint8_t), length, input_message);
    }

    *(plaintext + length) = '\0';
    return plaintext;
}

int main(int argc, char *argv[])
{
    uint8_t *key;
    uint8_t *plaintext;
    uint8_t *ciphertext;
    uint8_t *result;
    FILE *output;
    FILE *input;
    int opt;
    char *file_name;
    int algorithm;
    size_t counter;
    unsigned char **key_matrix;

    output = stdout;
    input = stdin;
    algorithm = PLAYFAIR_CIPHER;
    while ((opt = getopt(argc, argv, "i:o:1:c:p:a:f:h")) != -1)
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
            printf("Usage:\n[-i]: The input file. By default input file stream is stdin.\n[-o]: The output file. By default output file stream is stdout.\n[-h]: Prints the help prompt.\n");
            return 0;
        default:
            printf("Wrong command line arguments. Type -i for input file and -o for output file.\n");
            return -1;
        }
    }

    plaintext = read_plaintext(input);
    fprintf(output, "Plaintext:\n%s\n", plaintext);
    fprintf(output, "Plaintext len: %lu\n\n", strlen((char *)plaintext));
    if (algorithm == ONE_TIME_PAD)
    {
        printf("You chose one time pad algorithm for your encryption.\n");
        key = key_generator(plaintext);
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
    }else if (algorithm == PLAYFAIR_CIPHER){
        printf("You chose playfair cipher algorithm for your encryption.\n");
        key_matrix = playfair_keymatrix("hello world");
        /*
            encrypt
            decrypt
        */
        /*for (counter = 0; counter < 5; counter++)
        {
            free(key_matrix + counter);
        }*/
       /*free(key_matrix);*/
    }

    /*fprintf(output, "Message:\n%s\n", result);
    fprintf(output, "Result len: %lu\n", strlen((char *)result));*/

    free(plaintext);
    /*free(ciphertext);
    free(result);*/
    fclose(output);
    fclose(input);
    return 0;
}