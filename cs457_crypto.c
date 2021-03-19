/**
 * @file cs457_crypto.c
 * @author Fanourakis Nikos (csd4237@csd.uoc.gr)
 * @brief Implementation of the simple cryptographic library using C
 * 
 */

#include "cs457_crypto.h"
#include "queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/**
 * @brief   Global variable to store where X is a second character in a
 *          pair of characters in playfair cipher.
 * 
 */
queue_t *Xqueue;

/**
 * @brief   Stores if the plaintext size is odd number.
 *          Used to know if the last X of the ciphertext is there because of
 *          a double character or not.
 *          If 0, its a double character.
 *          If 1, its not.
 * 
 */
int message_odd;

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

    assert(key);
    for (counter = 0; counter < NUM_OF_LETTERS; counter++)
    {
        alphabet_table[counter] = 0;
    }
    length = strlen((char *)key);
    matrix_char = 0;

    printf("Key of keymatrix: %s\n", key);

    /* Key matrix is 5x5 */
    key_matrix = (unsigned char **)malloc(KEYMATRIX_ROWS * sizeof(unsigned char *));
    for (counter = 0; counter < KEYMATRIX_ROWS; counter++)
    {
        *(key_matrix + counter) = (unsigned char *)malloc(KEYMATRIX_COLUMNS * sizeof(unsigned char));
    }

    for (counter = 0; counter < length; counter++)
    {
        if (!isUppercaseLetter(*(key + counter)))
            continue;

        if (*(key + counter) != 74) /* 74 is J code on Ascii table */
        {
            if (!alphabet_table[*(key + counter) - UPPERCASE_START])
            {
                key_matrix[matrix_char / KEYMATRIX_ROWS][matrix_char % KEYMATRIX_COLUMNS] = *(key + counter);
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
                key_matrix[matrix_char / KEYMATRIX_ROWS][matrix_char % KEYMATRIX_COLUMNS] = *(key + counter) - 1;
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
            key_matrix[matrix_char / KEYMATRIX_ROWS][matrix_char % KEYMATRIX_COLUMNS] = UPPERCASE_START + counter;
            if (counter == 8) /* I is the 9th letter in the alphabet. */
                alphabet_table[counter + 1] = 1;
            matrix_char++;
        }
    }

    return key_matrix;
}

void getPositionOnKeymatrix(unsigned char **keymatrix, unsigned char letter, size_t *row, size_t *column)
{
    size_t counter;

    for (counter = 0; counter < KEYMATRIX_SIZE; counter++)
    {
        if (letter == keymatrix[counter / KEYMATRIX_ROWS][counter % KEYMATRIX_COLUMNS])
        {
            *row = counter / KEYMATRIX_ROWS;
            *column = counter % KEYMATRIX_COLUMNS;
            return;
        }
    }
    return;
}

unsigned char *playfair_encrypt(unsigned char *plaintext, unsigned char **key)
{
    size_t length, counter, ciphertext_size, columnOfFirst, columnOfSecond, rowOfFirst, rowOfSecond;
    unsigned char *ciphertext;

    assert(plaintext);
    assert(key);
    length = strlen((char *)plaintext);
    ciphertext_size = 0;
    Xqueue = queue_init();

    if (isOdd(length))
        ciphertext = malloc(sizeof(unsigned char) * (length + 2));
    else
        ciphertext = malloc(sizeof(unsigned char) * (length + 1));

    for (counter = 0; counter < length; counter++)
    {
        /* kratame mono ta kefalaia */
        if (!isUppercaseLetter(*(plaintext + counter)))
            continue;
        *(ciphertext + ciphertext_size) = *(plaintext + counter);
        ciphertext_size++;
    }

    for (counter = 0; counter < ciphertext_size; counter = counter + 2)
    {
        /* kanw ton prwto elegxo gia na kanw asfalh elegxo tou deyterou */
        if ((counter != ciphertext_size - 1) && (*(ciphertext + counter + 1) == 'X'))
            enqueue(Xqueue, counter + 1);

        /*  counter panta zygos ara an mpei sthn epomenh if logw tou prwtou
            to ciphertext_size einai monos arithmos kai ftasame sth teleytaia dyada (monada mexri twra). */
        if ((counter == ciphertext_size - 1) || (*(ciphertext + counter) == *(ciphertext + counter + 1)))
        {
            *(ciphertext + counter + 1) = 'X';
        }
    }
    message_odd = isOdd(ciphertext_size);
    ciphertext_size = ciphertext_size + isOdd(ciphertext_size);

    for (counter = 0; counter < ciphertext_size; counter = counter + 2)
    {
        if (*(ciphertext + counter) == 'J')
        {
            *(ciphertext + counter) = 'I';
            /*isws xrhsimopoihthei stack */
        }
        if (*(ciphertext + counter + 1) == 'J')
        {
            *(ciphertext + counter + 1) = 'I';
        }

        getPositionOnKeymatrix(key, *(ciphertext + counter), &rowOfFirst, &columnOfFirst);
        getPositionOnKeymatrix(key, *(ciphertext + counter + 1), &rowOfSecond, &columnOfSecond);
        if (!sameKeyMatrixRow(rowOfFirst, rowOfSecond) && !sameKeyMatrixColumn(columnOfFirst, columnOfSecond))
        {
            *(ciphertext + counter) = key[rowOfFirst][columnOfSecond];
            *(ciphertext + counter + 1) = key[rowOfSecond][columnOfFirst];
        }
        if (sameKeyMatrixRow(rowOfFirst, rowOfSecond))
        {
            *(ciphertext + counter) = key[rowOfFirst][(columnOfFirst + 1) % KEYMATRIX_COLUMNS];
            *(ciphertext + counter + 1) = key[rowOfSecond][(columnOfSecond + 1) % KEYMATRIX_COLUMNS];
        }
        if (sameKeyMatrixColumn(columnOfFirst, columnOfSecond))
        {
            *(ciphertext + counter) = key[(rowOfFirst + 1) % KEYMATRIX_ROWS][columnOfFirst];
            *(ciphertext + counter + 1) = key[(rowOfSecond + 1) % KEYMATRIX_ROWS][columnOfSecond];
        }
    }

    /* An einai monos arithmos vazoume ena X sto telos kai meta to terminal */
    *(ciphertext + ciphertext_size) = '\0';
    return ciphertext;
}

unsigned char *playfair_decrypt(unsigned char *ciphertext, unsigned char **key)
{
    size_t length, counter, columnOfFirst, columnOfSecond, rowOfFirst, rowOfSecond;
    unsigned char *plaintext;

    assert(ciphertext);
    assert(key);
    length = strlen((char *)ciphertext);

    plaintext = malloc(sizeof(unsigned char) * (length + 1));
    for (counter = 0; counter < length; counter = counter + 2)
    {
        getPositionOnKeymatrix(key, *(ciphertext + counter), &rowOfFirst, &columnOfFirst);
        getPositionOnKeymatrix(key, *(ciphertext + counter + 1), &rowOfSecond, &columnOfSecond);
        if (!sameKeyMatrixRow(rowOfFirst, rowOfSecond) && !sameKeyMatrixColumn(columnOfFirst, columnOfSecond))
        {
            *(plaintext + counter) = key[rowOfFirst][columnOfSecond];
            *(plaintext + counter + 1) = key[rowOfSecond][columnOfFirst];
        }
        if (sameKeyMatrixRow(rowOfFirst, rowOfSecond))
        {
            *(plaintext + counter) = key[rowOfFirst][(columnOfFirst - 1 + KEYMATRIX_COLUMNS) % KEYMATRIX_COLUMNS];
            *(plaintext + counter + 1) = key[rowOfSecond][(columnOfSecond - 1 + KEYMATRIX_COLUMNS) % KEYMATRIX_COLUMNS];
        }
        if (sameKeyMatrixColumn(columnOfFirst, columnOfSecond))
        {
            *(plaintext + counter) = key[(rowOfFirst - 1 + KEYMATRIX_ROWS) % KEYMATRIX_ROWS][columnOfFirst];
            *(plaintext + counter + 1) = key[(rowOfSecond - 1 + KEYMATRIX_ROWS) % KEYMATRIX_ROWS][columnOfSecond];
        }
    }

    for (counter = 0; counter < length; counter = counter + 2)
    {
        /* An kapoios xarakthras htan ontws X mpainei edw */
        if (!queue_is_empty(Xqueue) && queue_peek(Xqueue) == counter + 1)
        {
            printf("Xqueue size: %u\n", Xqueue->size);
            dequeue(Xqueue);
            continue;
        }

        if (*(plaintext + counter + 1) == 'X')
        {
            if ((counter == length - 2) && message_odd)
                *(plaintext + counter + 1) = '\0';
            else
                *(plaintext + counter + 1) = *(plaintext + counter);
        }
    }
    queue_free(Xqueue);
    Xqueue = NULL;
    *(plaintext + length) = '\0';
    return plaintext;
}