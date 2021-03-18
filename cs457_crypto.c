/**
 * @file cs457_crypto.c
 * @author Fanourakis Nikos (csd4237@csd.uoc.gr)
 * @brief Implementation of the simple cryptographic library using C
 * 
 */

#include "cs457_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

uint8_t *otp_encrypt(uint8_t *plaintext, uint8_t *key)
{
    size_t length, counter;
    uint8_t *ciphertext;

    assert(key);
    assert(plaintext);
    length = strlen((char *)plaintext);
    ciphertext = malloc(sizeof(uint8_t) * (length + 1));
    counter = 0;
    while (counter < length)
    {
        *(ciphertext + counter) = *(plaintext + counter) ^ *(key + counter);
        counter++;
    }
    *(ciphertext + counter) = '\0';
    return ciphertext;
}

uint8_t *otp_decrypt(uint8_t *ciphertext, uint8_t *key)
{
    size_t length, counter;
    uint8_t *plaintext;

    assert(key);
    assert(ciphertext);
    length = strlen((char *)key);
    plaintext = malloc(sizeof(uint8_t) * (length + 1));
    counter = 0;
    while (counter < length)
    {
        *(plaintext + counter) = *(ciphertext + counter) ^ *(key + counter);
        counter++;
    }
    *(plaintext + counter) = '\0';
    return plaintext;
}

uint8_t *caesar_encrypt(uint8_t *plaintext, uint16_t N)
{
    size_t len;
    size_t count;
    uint8_t *ciphertext;
    uint8_t character;

    assert(plaintext);
    len = strlen((char *)plaintext);
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
    size_t len;
    size_t count;
    uint8_t *plaintext;
    uint8_t character;

    assert(ciphertext);
    len = strlen((char *)ciphertext);
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
            *(plaintext + count) = character - (N % NUM_OF_DIGITS);
            if (*(plaintext + count) < DIGIT_START)
                *(plaintext + count) = (*(plaintext + count) - DIGIT_START + 1) % NUM_OF_DIGITS + DIGIT_END;
        }
        else if (isUppercaseLetter(character))
        {
            *(plaintext + count) = character - (N % NUM_OF_LETTERS);
            if (*(plaintext + count) < UPPERCASE_START)
                *(plaintext + count) = (*(plaintext + count) - UPPERCASE_START + 1) % NUM_OF_LETTERS + UPPERCASE_END;
        }
        else if (isLowercaseLetter(character))
        {
            *(plaintext + count) = character - (N % NUM_OF_LETTERS);
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

unsigned char **playfair_keymatrix(unsigned char *key)
{
    size_t length, counter, matrix_char;
    unsigned char **key_matrix;
    int alphabet_table[NUM_OF_LETTERS];

    for (counter = 0; counter < NUM_OF_LETTERS; counter++)
    {
        alphabet_table[counter] = 0;
    }
    length = strlen((char *)key);
    matrix_char = 0;

    printf("Key of keymatrix: %s\n", key);

    /* Key matrix is 5x5 */
    key_matrix = (unsigned char **)malloc(5 * sizeof(unsigned char *));
    for (counter = 0; counter < 5; counter++)
    {
        *(key_matrix + counter) = (unsigned char *)malloc(5 * sizeof(unsigned char));
    }

    for (counter = 0; counter < length; counter++)
    {
        if (!isUppercaseLetter(*(key + counter)))
            continue;

        if (*(key + counter) != 74) /* 74 is J code on Ascii table */
        {
            if (!alphabet_table[*(key + counter) - UPPERCASE_START])
            {
                key_matrix[matrix_char / 5][matrix_char % 5] = *(key + counter);
                /**( *(key_matrix + (matrix_char / 5) ) + (matrix_char % 5) ) = *(key + counter);*/
                matrix_char++;
                alphabet_table[*(key + counter) - UPPERCASE_START] = 1;
                if (*(key + counter) == 73) /* 73 is I code on Ascii table */
                    alphabet_table[*(key + counter) + 1 - UPPERCASE_START] = 1;
            }
        }
        else /* reach here if read J */
        {
            if (!alphabet_table[*(key + counter) - UPPERCASE_START])
            {
                key_matrix[matrix_char / 5][matrix_char % 5] = *(key + counter) - 1;
                /**( *(key_matrix + (matrix_char / 5) ) + (matrix_char % 5) ) = *(key + counter) - 1;*/
                matrix_char++;
                alphabet_table[*(key + counter) - 1 - UPPERCASE_START] = 1;
                alphabet_table[*(key + counter) - UPPERCASE_START] = 1;
            }
        }
    }

    for (counter = 0; counter < NUM_OF_LETTERS; counter++)
    {
        if (!alphabet_table[counter])
        {
            key_matrix[matrix_char / 5][matrix_char % 5] = UPPERCASE_START + counter;
            /**( *(key_matrix + (matrix_char / 5) ) + (matrix_char % 5) ) = UPPERCASE_START + counter;*/
            if(counter == 8) /* I is the 9th letter in the alphabet. */
                alphabet_table[counter + 1] = 1;
            matrix_char++;
        }
    }

    return key_matrix;
}

/*
    An einai idia sth dyada vazoume X
    An plaintext einai monos arithmos tote vazoume X gia na symplhrwthei h dyada
    Ara se oles tis dyades antikathistoyme to X me ton aristero char ektos th teleytaia fora
    kai mono an exoyme length mono arithmo.
    Gia ta alla akolouthoume tous kanones tou pinaka
*/