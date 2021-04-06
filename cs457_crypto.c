/**
 * @file cs457_crypto.c
 * @author Fanourakis Nikos (csd4237@csd.uoc.gr)
 * @brief Implementation of the simple cryptographic library using C
 * 
 */

#include "cs457_crypto.h"
#include "queue/queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/**
 * @brief   Global variable to store where X is a second character in a
 *          pair of characters in playfair cipher.
 * 
 */
queue_t *Xqueue = NULL;

/**
 * @brief   Global variable to store where J exists in the plaintext.
 * 
 */
queue_t *Jqueue = NULL;

/**
 * @brief   Stores if the plaintext size is odd number.
 *          Used to know if the last X of the ciphertext is there because of
 *          a double character or not.
 *          If 0, its a double character.
 *          If 1, its not.
 * 
 */
int message_odd = 0;

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

uint8_t *key_generator(size_t plaintext_size)
{
    uint8_t *key;
    FILE *randomData;
    size_t randomDataLen;
    size_t read_result;

    randomData = fopen("/dev/urandom", "r");

    if (!randomData)
    {
        fprintf(stderr, "Failed to open /dev/urandom.\n");
        exit(EXIT_FAILURE);
    }
    randomDataLen = 0;
    key = (uint8_t *)malloc(sizeof(uint8_t) * (plaintext_size + 1));
    if (!key)
    {
        fprintf(stderr, "Malloc failed in key_generator().\n");
        exit(EXIT_FAILURE);
    }
    memset(key, 0, sizeof(uint8_t) * (plaintext_size + 1));
    while (randomDataLen < plaintext_size)
    {
        read_result = fread(key + randomDataLen, sizeof(uint8_t), sizeof(uint8_t), randomData);
        /* If random character is terminal then give some other character. */
        if (*(key + randomDataLen) == '\0')
        {
            continue;
        }
        randomDataLen += read_result;
    }
    *(key + plaintext_size) = '\0';
    fclose(randomData);
    return key;
}

void apply_xor(uint8_t *result, uint8_t *str1, uint8_t *str2, size_t length)
{
    size_t counter;

    assert(str1);
    assert(str2);
    assert(result);

    counter = 0;
    while (counter < length)
    {
        *(result + counter) = *(str1 + counter) ^ *(str2 + counter);
        counter++;
    }
    return;
}

uint8_t *otp_encrypt(uint8_t *plaintext, uint8_t *key)
{
    size_t length;
    uint8_t *ciphertext;

    assert(key);
    assert(plaintext);
    length = strlen((char *)plaintext);
    ciphertext = malloc(sizeof(uint8_t) * (length + 1));
    if (!ciphertext)
    {
        fprintf(stderr, "Malloc failed in otp_encrypt().\n");
        exit(EXIT_FAILURE);
    }
    apply_xor(ciphertext, plaintext, key, length);
    ciphertext[length] = '\0';
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
    if (!plaintext)
    {
        fprintf(stderr, "Malloc failed in otp_decrypt().\n");
        exit(EXIT_FAILURE);
    }
    apply_xor(plaintext, ciphertext, key, length);
    plaintext[length] = '\0';
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
        *(ciphertext + count) = character + (N % CEASAR_ALPHABET_SIZE);
        /* If read digit */
        if (isDigit(character))
        {
            /* If with the addition of N it surpasses digit end then add the amount of letters that exist
            between digits and uppercase letters in ascii table */
            if (*(ciphertext + count) > DIGIT_END)
                *(ciphertext + count) = *(ciphertext + count) + (UPPERCASE_START - DIGIT_END - 1);

            /* If with the addition of N and the amount of letters that exist
            between digits and uppercase letters in ascii table
            it surpasses uppercase end then add the amount of letters that exist
            between lowercase and uppercase letters in ascii table */
            if (*(ciphertext + count) > UPPERCASE_END)
                *(ciphertext + count) = *(ciphertext + count) + (LOWERCASE_START - UPPERCASE_END - 1);

            /* If with the addition of the previous, it surpasses lowercase end then wrap around! */
            if (*(ciphertext + count) > LOWERCASE_END)
                *(ciphertext + count) = (*(ciphertext + count) % (LOWERCASE_END + 1)) + DIGIT_START; /* WRAP AROUND */
        }
        else if (isUppercaseLetter(character))
        {
            if (*(ciphertext + count) > UPPERCASE_END)
                *(ciphertext + count) = *(ciphertext + count) + (LOWERCASE_START - UPPERCASE_END - 1);

            if (*(ciphertext + count) > LOWERCASE_END)
            {
                *(ciphertext + count) = (*(ciphertext + count) % (LOWERCASE_END + 1)) + DIGIT_START;
                if (*(ciphertext + count) > DIGIT_END)
                    *(ciphertext + count) = *(ciphertext + count) + (UPPERCASE_START - DIGIT_END - 1);
            }
        }
        else if (isLowercaseLetter(character))
        {
            if (*(ciphertext + count) > LOWERCASE_END)
            {
                *(ciphertext + count) = (*(ciphertext + count) % (LOWERCASE_END + 1)) + DIGIT_START;
                if (*(ciphertext + count) > DIGIT_END)
                    *(ciphertext + count) = *(ciphertext + count) + (UPPERCASE_START - DIGIT_END - 1);

                if (*(ciphertext + count) > UPPERCASE_END)
                    *(ciphertext + count) = *(ciphertext + count) + (LOWERCASE_START - UPPERCASE_END - 1);
            }
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
        /* The only difference between encryption and decryption */
        *(plaintext + count) = character + CEASAR_ALPHABET_SIZE - (N % CEASAR_ALPHABET_SIZE);
        if (isDigit(character))
        {
            if (*(plaintext + count) > DIGIT_END)
                *(plaintext + count) = *(plaintext + count) + (UPPERCASE_START - DIGIT_END - 1);

            if (*(plaintext + count) > UPPERCASE_END)
                *(plaintext + count) = *(plaintext + count) + (LOWERCASE_START - UPPERCASE_END - 1);

            if (*(plaintext + count) > LOWERCASE_END)
                *(plaintext + count) = (*(plaintext + count) % (LOWERCASE_END + 1)) + DIGIT_START;
        }
        else if (isUppercaseLetter(character))
        {
            if (*(plaintext + count) > UPPERCASE_END)
                *(plaintext + count) = *(plaintext + count) + (LOWERCASE_START - UPPERCASE_END - 1);

            if (*(plaintext + count) > LOWERCASE_END)
            {
                *(plaintext + count) = (*(plaintext + count) % (LOWERCASE_END + 1)) + DIGIT_START;
                if (*(plaintext + count) > DIGIT_END)
                    *(plaintext + count) = *(plaintext + count) + (UPPERCASE_START - DIGIT_END - 1);
            }
        }
        else if (isLowercaseLetter(character))
        {
            if (*(plaintext + count) > LOWERCASE_END)
            {
                *(plaintext + count) = (*(plaintext + count) % (LOWERCASE_END + 1)) + DIGIT_START;
                if (*(plaintext + count) > DIGIT_END)
                    *(plaintext + count) = *(plaintext + count) + (UPPERCASE_START - DIGIT_END - 1);

                if (*(plaintext + count) > UPPERCASE_END)
                    *(plaintext + count) = *(plaintext + count) + (LOWERCASE_START - UPPERCASE_END - 1);
            }
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
    int alphabet_table[NUM_OF_LETTERS]; /* a table to store if a letter is already in the matrix */

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
    if (!key_matrix)
    {
        fprintf(stderr, "Malloc failed in playfair_keymatrix().\n");
        exit(EXIT_FAILURE);
    }
    for (counter = 0; counter < KEYMATRIX_ROWS; counter++)
    {
        *(key_matrix + counter) = (unsigned char *)malloc(KEYMATRIX_COLUMNS * sizeof(unsigned char));
        if (!key_matrix[counter])
        {
            fprintf(stderr, "Malloc failed in playfair_keymatrix().\n");
            exit(EXIT_FAILURE);
        }
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

    /* Add on the matrix the rest letters */
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

void print_keymatrix(unsigned char **key_matrix)
{
    uint32_t counter;
    printf("Keymatrix:\n");
    for (counter = 0; counter < KEYMATRIX_SIZE; counter++)
    {
        printf("%c", key_matrix[counter / KEYMATRIX_ROWS][counter % KEYMATRIX_COLUMNS]);
        if ((counter % KEYMATRIX_COLUMNS) == 4)
            printf("\n");
    }
    return;
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
    Jqueue = queue_init();

    ciphertext = malloc(sizeof(unsigned char) * (length + isOdd(length) + 1));
    if (!ciphertext)
    {
        fprintf(stderr, "Malloc failed in playfair_encrypt().\n");
        exit(EXIT_FAILURE);
    }

    for (counter = 0; counter < length; counter++)
    {
        /* Keep only uppercase letters */
        if (isUppercaseLetter(*(plaintext + counter)))
        {
            *(ciphertext + ciphertext_size) = *(plaintext + counter);
            ciphertext_size++;
        }
    }

    for (counter = 0; counter < ciphertext_size; counter = counter + 2)
    {
        /*  Keep in a queue the positions of X that exist as a second char
            on a pair of chars (but not the last pair). */
        if ((counter != ciphertext_size - 1) && (*(ciphertext + counter + 1) == 'X'))
            enqueue(Xqueue, counter + 1);

        /*  Counter is always even. So if we get in the next if statement because of the first expression
            it means that ciphertext_size is odd and we reached the last pair (which is one char in reality).
            So we must make another one pair and we fill it with X.*/
        if ((counter == ciphertext_size - 1) || (*(ciphertext + counter) == *(ciphertext + counter + 1)))
            *(ciphertext + counter + 1) = 'X';
    }

    message_odd = isOdd(ciphertext_size);
    ciphertext_size = ciphertext_size + isOdd(ciphertext_size);

    for (counter = 0; counter < ciphertext_size; counter = counter + 2)
    {
        /* If found J put I but store the position of J on a queue*/
        if (*(ciphertext + counter) == 'J')
        {
            *(ciphertext + counter) = 'I';
            enqueue(Jqueue, counter);
        }
        if (*(ciphertext + counter + 1) == 'J')
        {
            *(ciphertext + counter + 1) = 'I';
            enqueue(Jqueue, counter + 1);
        }

        getPositionOnKeymatrix(key, *(ciphertext + counter), &rowOfFirst, &columnOfFirst);
        getPositionOnKeymatrix(key, *(ciphertext + counter + 1), &rowOfSecond, &columnOfSecond);
        /*  If the characters are on different row and column their encrypted characters
            are the characters with the same row as them but with the column of the other. */
        if (!sameKeyMatrixRow(rowOfFirst, rowOfSecond) && !sameKeyMatrixColumn(columnOfFirst, columnOfSecond))
        {
            *(ciphertext + counter) = key[rowOfFirst][columnOfSecond];
            *(ciphertext + counter + 1) = key[rowOfSecond][columnOfFirst];
        }
        /*  If the characters are on the same row their encrypted characters
            are the characters with the same row as them but with the next (right) column. */
        if (sameKeyMatrixRow(rowOfFirst, rowOfSecond))
        {
            *(ciphertext + counter) = key[rowOfFirst][(columnOfFirst + 1) % KEYMATRIX_COLUMNS];
            *(ciphertext + counter + 1) = key[rowOfSecond][(columnOfSecond + 1) % KEYMATRIX_COLUMNS];
        }
        /*  If the characters are on the same column their encrypted characters
            are the characters with the same column as them but with the next (below) row. */
        if (sameKeyMatrixColumn(columnOfFirst, columnOfSecond))
        {
            *(ciphertext + counter) = key[(rowOfFirst + 1) % KEYMATRIX_ROWS][columnOfFirst];
            *(ciphertext + counter + 1) = key[(rowOfSecond + 1) % KEYMATRIX_ROWS][columnOfSecond];
        }
    }

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
    if (!plaintext)
    {
        fprintf(stderr, "Malloc failed in playfair_decrypt().\n");
        exit(EXIT_FAILURE);
    }
    for (counter = 0; counter < length; counter = counter + 2)
    {
        getPositionOnKeymatrix(key, *(ciphertext + counter), &rowOfFirst, &columnOfFirst);
        getPositionOnKeymatrix(key, *(ciphertext + counter + 1), &rowOfSecond, &columnOfSecond);
        /*  If the characters are on different row and column their encrypted characters
            are the characters with the same row as them but with the column of the other. */
        if (!sameKeyMatrixRow(rowOfFirst, rowOfSecond) && !sameKeyMatrixColumn(columnOfFirst, columnOfSecond))
        {
            *(plaintext + counter) = key[rowOfFirst][columnOfSecond];
            *(plaintext + counter + 1) = key[rowOfSecond][columnOfFirst];
        }
        /*  If the characters are on the same row their encrypted characters
            are the characters with the same row as them but with the previous (left) column. */
        if (sameKeyMatrixRow(rowOfFirst, rowOfSecond))
        {
            *(plaintext + counter) = key[rowOfFirst][(columnOfFirst - 1 + KEYMATRIX_COLUMNS) % KEYMATRIX_COLUMNS];
            *(plaintext + counter + 1) = key[rowOfSecond][(columnOfSecond - 1 + KEYMATRIX_COLUMNS) % KEYMATRIX_COLUMNS];
        }
        /*  If the characters are on the same column their encrypted characters
            are the characters with the same column as them but with the previous (above) row. */
        if (sameKeyMatrixColumn(columnOfFirst, columnOfSecond))
        {
            *(plaintext + counter) = key[(rowOfFirst - 1 + KEYMATRIX_ROWS) % KEYMATRIX_ROWS][columnOfFirst];
            *(plaintext + counter + 1) = key[(rowOfSecond - 1 + KEYMATRIX_ROWS) % KEYMATRIX_ROWS][columnOfSecond];
        }
    }

    for (counter = 0; counter < length; counter = counter + 2)
    {
        /* J replacements */
        if (!queue_is_empty(Jqueue) && queue_peek(Jqueue) == counter)
        {
            dequeue(Jqueue);
            *(plaintext + counter) = 'J';
        }

        if (!queue_is_empty(Jqueue) && queue_peek(Jqueue) == counter + 1)
        {
            dequeue(Jqueue);
            *(plaintext + counter + 1) = 'J';
            continue;
        }

        /* If the second character of the pair was X in plaintext then dequeue and continue */
        if (!queue_is_empty(Xqueue) && queue_peek(Xqueue) == counter + 1)
        {
            dequeue(Xqueue);
            continue;
        }

        /*  If the second character of the pair is X and we reach here, it means that we placed it
            because of a duplicate character or because of ciphertext fulfillment (plaintext size was odd).*/
        if (*(plaintext + counter + 1) == 'X')
        {
            if ((counter == length - 2) && message_odd)
                *(plaintext + counter + 1) = '\0';
            else
                *(plaintext + counter + 1) = *(plaintext + counter);
        }
    }
    queue_free(Xqueue);
    queue_free(Jqueue);
    Xqueue = NULL;
    Jqueue = NULL;
    *(plaintext + length) = '\0';
    return plaintext;
}

uint8_t *affine_encrypt(uint8_t *plaintext)
{
    size_t counter, length, ciphertext_size;
    uint8_t *ciphertext;

    length = strlen((char *)plaintext);
    ciphertext = malloc(sizeof(uint8_t) * (length + 1));
    if (!ciphertext)
    {
        fprintf(stderr, "Malloc failed in affine_encrypt().\n");
        exit(EXIT_FAILURE);
    }
    ciphertext_size = 0;
    for (counter = 0; counter < length; counter++)
    {
        /* Keep only uppercase letters and convert lowercase to uppercase */
        if (!isUppercaseLetter(*(plaintext + counter)))
        {
            if (isLowercaseLetter(*(plaintext + counter)))
            {
                *(ciphertext + ciphertext_size) = *(plaintext + counter) - UPPER_LOWER_DISTANCE;
                ciphertext_size++;
            }
            continue;
        }

        *(ciphertext + ciphertext_size) = *(plaintext + counter);
        ciphertext_size++;
    }

    for (counter = 0; counter < ciphertext_size; counter++)
    {
        /* f(x) = (A * X + B) mod M */
        *(ciphertext + counter) = ((A * (*(ciphertext + counter) - UPPERCASE_START) + B) % M) + UPPERCASE_START;
    }

    *(ciphertext + ciphertext_size) = '\0';
    return ciphertext;
}

uint8_t *affine_decrypt(uint8_t *ciphertext)
{
    uint8_t *plaintext;
    size_t counter, length;

    length = strlen((char *)ciphertext);
    plaintext = malloc(sizeof(uint8_t) * (length + 1));
    if (!plaintext)
    {
        fprintf(stderr, "Malloc failed in affine_decrypt().\n");
        exit(EXIT_FAILURE);
    }
    /*  D(x) = A^-1 * (X - B) mod M 
        A^-1 is the modular multiplicative inverse of A mod M*/
    for (counter = 0; counter < length; counter++)
    {
        *(plaintext + counter) = ((modInverse(A, M) * ((*(ciphertext + counter) + UPPERCASE_START) - B)) % M) + UPPERCASE_START;
    }

    *(plaintext + length) = '\0';
    return plaintext;
}

int modInverse(int a, int m)
{
    int x;
    for (x = 1; x < m; x++)
        if (((a % m) * (x % m)) % m == 1)
            return x;
}

void feistel_swap(uint8_t *left_block, uint8_t *right_block)
{
    uint8_t *temp_block;
    size_t length;

    /* left and right block always have 4 bytes size because of previous padding*/
    length = BLOCK_SIZE / 2;
    temp_block = (uint8_t *)malloc(sizeof(uint8_t) * (length + 1));
    if (!temp_block)
    {
        fprintf(stderr, "Malloc failed in feistel_swap().\n");
        exit(EXIT_FAILURE);
    }
    memcpy(temp_block, right_block, sizeof(uint8_t) * length);
    memcpy(right_block, left_block, sizeof(uint8_t) * length);
    memcpy(left_block, temp_block, sizeof(uint8_t) * length);

    free(temp_block);
    return;
}

uint8_t *feistel_round(uint8_t *block, uint8_t *key)
{
    uint8_t *round_block;
    size_t counter, length;

    /* left and right block always have 4 bytes size because of previous padding */
    length = BLOCK_SIZE / 2;
    round_block = (uint8_t *)malloc(sizeof(uint8_t) * (length + 1));
    if (!round_block)
    {
        fprintf(stderr, "Malloc failed in feistel_round().\n");
        exit(EXIT_FAILURE);
    }
    counter = 0;
    while (counter < length)
    {
        round_block[counter] = (block[counter] * key[counter]) % TWO_POWER_FOUR;
        counter++;
    }
    return round_block;
}

uint8_t *feistel_padding(uint8_t *block, size_t padding_block_size)
{
    size_t block_size;
    uint8_t *padded_block;

    padded_block = (uint8_t *)malloc(sizeof(uint8_t) * (padding_block_size + 1));
    if (!padded_block)
    {
        fprintf(stderr, "Malloc failed in feistel_padding().\n");
        exit(EXIT_FAILURE);
    }
    block_size = strlen((char *)block);
    memset(padded_block, 0, padding_block_size);
    memcpy(padded_block, block, sizeof(uint8_t) * block_size);

    return padded_block;
}

uint8_t *feistel_encrypt(uint8_t *plaintext, uint8_t keys[][BLOCK_SIZE / 2])
{
    size_t length, total_blocks, blocks_counter, plaintext_size;
    int rounds_counter;
    uint8_t *left_block, *right_block, *round_block, *ciphertext, *key, *padded_plaintext;

    plaintext_size = strlen((char *)plaintext);
    total_blocks = plaintext_size / BLOCK_SIZE;
    if (plaintext_size % BLOCK_SIZE)
        total_blocks++;

    length = total_blocks * BLOCK_SIZE;
    /* Padding so that plaintext has length == n*64 bits (n*8 bytes)*/
    padded_plaintext = feistel_padding(plaintext, length);
    ciphertext = (uint8_t *)malloc(sizeof(uint8_t) * (length + 1));
    left_block = (uint8_t *)malloc(sizeof(uint8_t) * ((BLOCK_SIZE / 2) + 1));
    right_block = (uint8_t *)malloc(sizeof(uint8_t) * ((BLOCK_SIZE / 2) + 1));
    if (!ciphertext || !left_block || !right_block)
    {
        fprintf(stderr, "Malloc failed in feistel_encrypt().\n");
        exit(EXIT_FAILURE);
    }

    rounds_counter = 0;
    /* Feistel keys generation */
    while (rounds_counter < NUM_OF_ROUNDS)
    {
        key = key_generator(BLOCK_SIZE / 2);
        memcpy(keys[rounds_counter], key, sizeof(uint8_t) * (BLOCK_SIZE / 2));
        free(key);
        key = NULL;
        rounds_counter++;
    }

    blocks_counter = 0;
    rounds_counter = 0;
    /* Divide plaintext into blocks of 8 bytes */
    while (blocks_counter < total_blocks)
    {
        memcpy(left_block, (padded_plaintext + (blocks_counter * BLOCK_SIZE)), sizeof(uint8_t) * (BLOCK_SIZE / 2));
        memcpy(right_block, (padded_plaintext + (blocks_counter * BLOCK_SIZE) + BLOCK_SIZE / 2), sizeof(uint8_t) * (BLOCK_SIZE / 2));
        while (rounds_counter < NUM_OF_ROUNDS)
        {
            round_block = feistel_round(right_block, keys[rounds_counter]);
            apply_xor(left_block, left_block, round_block, BLOCK_SIZE / 2);
            feistel_swap(left_block, right_block);
            rounds_counter++;
            free(round_block);
            round_block = NULL;
        }
        rounds_counter = 0;
        /* Put first the right block and then the left block instead of another swap */
        memcpy((ciphertext + (blocks_counter * BLOCK_SIZE)), right_block, sizeof(uint8_t) * (BLOCK_SIZE / 2));
        memcpy((ciphertext + (blocks_counter * BLOCK_SIZE) + BLOCK_SIZE / 2), left_block, sizeof(uint8_t) * (BLOCK_SIZE / 2));
        blocks_counter++;
    }

    ciphertext[length] = '\0';
    free(left_block);
    free(right_block);
    free(padded_plaintext);
    return ciphertext;
}

uint8_t *feistel_decrypt(uint8_t *ciphertext, uint8_t keys[][BLOCK_SIZE / 2], size_t plaintext_size)
{
    size_t length, total_blocks, blocks_counter;
    int rounds_counter;
    uint8_t *left_block, *right_block, *round_block, *plaintext;

    total_blocks = plaintext_size / BLOCK_SIZE;
    if (plaintext_size % BLOCK_SIZE)
        total_blocks++;

    length = total_blocks * BLOCK_SIZE;
    plaintext = (uint8_t *)malloc(sizeof(uint8_t) * (length + 1));
    left_block = (uint8_t *)malloc(sizeof(uint8_t) * ((BLOCK_SIZE / 2) + 1));
    right_block = (uint8_t *)malloc(sizeof(uint8_t) * ((BLOCK_SIZE / 2) + 1));
    if (!plaintext || !left_block || !right_block)
    {
        fprintf(stderr, "Malloc failed in feistel_decrypt().\n");
        exit(EXIT_FAILURE);
    }

    blocks_counter = 0;
    rounds_counter = NUM_OF_ROUNDS - 1;
    /* Divide plaintext into blocks of 8 bytes */
    while (blocks_counter < total_blocks)
    {
        memcpy(left_block, (ciphertext + (blocks_counter * BLOCK_SIZE)), sizeof(uint8_t) * (BLOCK_SIZE / 2));
        memcpy(right_block, (ciphertext + (blocks_counter * BLOCK_SIZE) + BLOCK_SIZE / 2), sizeof(uint8_t) * (BLOCK_SIZE / 2));

        /* Reverse order of the keys */
        while (rounds_counter >= 0)
        {
            round_block = feistel_round(right_block, keys[rounds_counter]);
            apply_xor(left_block, left_block, round_block, BLOCK_SIZE / 2);
            feistel_swap(left_block, right_block);
            rounds_counter--;
            free(round_block);
            round_block = NULL;
        }
        rounds_counter = NUM_OF_ROUNDS - 1;
        /* Put first the right block and then the left block instead of another swap */
        memcpy((plaintext + (blocks_counter * BLOCK_SIZE)), right_block, sizeof(uint8_t) * (BLOCK_SIZE / 2));
        memcpy((plaintext + (blocks_counter * BLOCK_SIZE) + BLOCK_SIZE / 2), left_block, sizeof(uint8_t) * (BLOCK_SIZE / 2));
        blocks_counter++;
    }

    plaintext[length] = '\0';
    free(left_block);
    free(right_block);
    return plaintext;
}
