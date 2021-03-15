/**
 * @file cs457_crypto.c
 * @author Fanourakis Nikos (csd4237@csd.uoc.gr)
 * @brief Implementation of the simple cryptographic library using C
 * 
 */

/*#include "cs457_crypto.h"*/
#include <stdint.h> /*na pane .h*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define INIT_INPUT_SIZE 128
#define DIGIT_START 48 /* Start of digits in ascii table */
#define DIGIT_END 57   /* End of digits in ascii table */
#define UPPERCASE_START 65
#define LOWERCASE_START 97
#define UPPERCASE_END 90
#define LOWERCASE_END 122
#define NUM_OF_DIGITS 10
#define NUM_OF_LETTERS 26
/*#define ONE_TIME_PAD 1
#define CAESAR_CIPHER 2*/

uint8_t *key_generator(uint8_t *plaintext)
{
    int key_size;
    uint8_t *key;
    FILE *randomData;
    size_t randomDataLen;
    size_t read_result;

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
        if (*(key + randomDataLen) == '\0')
        {
            continue;
        }
        randomDataLen += read_result;
    }
    *(key + key_size) = '\0';
    fclose(randomData);
    /*printf("Plaintext: %s\n", plaintext);
    printf("Plaintext len: %lu\n", strlen(plaintext));
    printf("Key: %s\n", key);
    printf("Key len: %lu\n", strlen((char *)key));*/
    return key;
}

uint8_t *read_plaintext(FILE *input_message)
{
    int c;
    int counter;
    long length;
    uint8_t *plaintext;

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

/*uint8_t *otp_encrypt(uint8_t *plaintext, uint8_t *key);
uint8_t *otp_decrypt(uint8_t *ciphertext, uint8_t *key);*/

int isUppercaseLetter(uint8_t character)
{
    if (character >= UPPERCASE_START && character <= UPPERCASE_END)
        return 1;
    return 0;
}

int isLowercaseLetter(uint8_t character)
{
    if (character >= LOWERCASE_START && character <= LOWERCASE_END)
        return 1;
    return 0;
}

int isDigit(uint8_t character)
{
    if (character >= DIGIT_START && character <= DIGIT_END)
        return 1;
    return 0;
}

uint8_t *caesar_encrypt(uint8_t *plaintext, uint16_t N)
{
    int len;
    int count;
    uint8_t *ciphertext;
    uint8_t character;

    len = strlen(plaintext);
    ciphertext = malloc(sizeof(uint8_t) * (len + 1));
    if (!ciphertext)
    {
        fprintf(stderr, "Malloc failed at caesar_encrypt().\n");
        exit(EXIT_FAILURE);
    }

    count = 0;
    while (count < len)
    {
        character = *(plaintext + count);
        if (isDigit(character))
        {
            *(ciphertext + count) = character + (N % NUM_OF_DIGITS);
            if (*(ciphertext + count) > DIGIT_END)
                *(ciphertext + count) = (*(ciphertext + count) % (DIGIT_END + 1)) + DIGIT_START;
        }
        else if (isUppercaseLetter(character))
        {
            *(ciphertext + count) = character + (N % NUM_OF_LETTERS);
            if (*(ciphertext + count) > UPPERCASE_END)
                *(ciphertext + count) = (*(ciphertext + count) % (UPPERCASE_END + 1)) + UPPERCASE_START;
        }
        else if (isLowercaseLetter(character))
        {
            *(ciphertext + count) = character + (N % NUM_OF_LETTERS);
            if (*(ciphertext + count) > LOWERCASE_END)
                *(ciphertext + count) = (*(ciphertext + count) % (LOWERCASE_END + 1)) + LOWERCASE_START;
        }
        else
        {
            *(ciphertext + count) = character;
        }
        count++;
    }
    *(ciphertext + count) = '\0';
    return ciphertext;
}

uint8_t *caesar_decrypt(uint8_t *ciphertext, uint16_t N)
{
    int len;
    int count;
    uint8_t *plaintext;
    uint8_t character;

    len = strlen(ciphertext);
    plaintext = malloc(sizeof(uint8_t) * (len + 1));
    if (!plaintext)
    {
        fprintf(stderr, "Malloc failed at caesar_decrypt().\n");
        exit(EXIT_FAILURE);
    }

    count = 0;
    while (count < len)
    {
        character = *(ciphertext + count);
        if (isDigit(character))
        {
            *(plaintext + count) = character - ( N % NUM_OF_DIGITS);
            if (*(plaintext + count) < DIGIT_START)
                *(plaintext + count) = (*(plaintext + count) - DIGIT_START + 1) % NUM_OF_DIGITS + DIGIT_END;

        }
        else if (isUppercaseLetter(character))
        {
            *(plaintext + count) = character - ( N % NUM_OF_LETTERS);
            if (*(plaintext + count) < UPPERCASE_START)
                *(plaintext + count) = (*(plaintext + count) - UPPERCASE_START + 1) % NUM_OF_LETTERS + UPPERCASE_END;
        }
        else if (isLowercaseLetter(character))
        {
            *(plaintext + count) = character - ( N % NUM_OF_LETTERS);
            if (*(plaintext + count) < LOWERCASE_START)
                *(plaintext + count) = (*(plaintext + count) - LOWERCASE_START + 1) % NUM_OF_LETTERS + LOWERCASE_END;
        }
        else
        {
            *(plaintext + count) = character;
        }
        count++;
    }
    *(plaintext + count) = '\0';
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

    output = stdout;
    input = stdin;

    while ((opt = getopt(argc, argv, "i:o")) != -1)
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
        default:
            printf("Wrong command line arguments. Type -i for input file and -o for output file.\n");
            return -1;
        }
    }

    plaintext = read_plaintext(input);
    /*key = key_generator(plaintext);*/
    printf("Plaintext: %s\n", plaintext);
    printf("Plaintext len: %lu\n", strlen(plaintext));
    /*printf("Key: %s\n", key);
    printf("Key len: %lu\n", strlen((char *)key));
    free(key);*/
    ciphertext = caesar_encrypt(plaintext, 65535);
    printf("Ciphertext: %s\n", ciphertext);
    printf("Ciphertext len: %lu\n", strlen(ciphertext));
    result = caesar_decrypt(ciphertext, 65535);
    printf("Result: %s\n", result);
    printf("Result len: %lu\n", strlen(result));

    free(plaintext);
    free(ciphertext);
    free(result);
    fclose(output);
    fclose(input);
    return 0;
}

/* Paizei sigoura isws na einai epikindino gia megala N 

if(character + N > UPPERCASE_END)
    *(ciphertext + count) = ( (character + N) % (UPPERCASE_END + 1) % NUM_OF_LETTERS ) + UPPERCASE_START; 
else
    *(ciphertext + count) = character + N;

*/