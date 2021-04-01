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
    memset(key, 0, sizeof(uint8_t) * (plaintext_size + 1));
    while (randomDataLen < plaintext_size)
    {
        read_result = fread(key + randomDataLen, sizeof(uint8_t), sizeof(uint8_t), randomData);
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
        *(ciphertext + count) = character + (N % CEASAR_ALPHABET_SIZE);
        if (isDigit(character))
        {
            if (*(ciphertext + count) > DIGIT_END)
                *(ciphertext + count) = *(ciphertext + count) + (UPPERCASE_START - DIGIT_END - 1);

            if (*(ciphertext + count) > UPPERCASE_END)
                *(ciphertext + count) = *(ciphertext + count) + (LOWERCASE_START - UPPERCASE_END - 1);

            if (*(ciphertext + count) > LOWERCASE_END)
                *(ciphertext + count) = (*(ciphertext + count) % (LOWERCASE_END + 1)) + DIGIT_START; /* WRAP AROUND */
        }
        else if (isUppercaseLetter(character))
        {
            if (*(ciphertext + count) > UPPERCASE_END)
                *(ciphertext + count) = *(ciphertext + count) + (LOWERCASE_START - UPPERCASE_END - 1);

            if (*(ciphertext + count) > LOWERCASE_END)
            {
                *(ciphertext + count) = (*(ciphertext + count) % (LOWERCASE_END + 1)) + DIGIT_START; /* WRAP AROUND */
                if (*(ciphertext + count) > DIGIT_END)
                    *(ciphertext + count) = *(ciphertext + count) + (UPPERCASE_START - DIGIT_END - 1);
            }
        }
        else if (isLowercaseLetter(character))
        {
            if (*(ciphertext + count) > LOWERCASE_END)
            {
                *(ciphertext + count) = (*(ciphertext + count) % (LOWERCASE_END + 1)) + DIGIT_START; /* WRAP AROUND */
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
        *(plaintext + count) = character + CEASAR_ALPHABET_SIZE - (N % CEASAR_ALPHABET_SIZE);
        if (isDigit(character))
        {
            if (*(plaintext + count) > DIGIT_END)
                *(plaintext + count) = *(plaintext + count) + (UPPERCASE_START - DIGIT_END - 1);

            if (*(plaintext + count) > UPPERCASE_END)
                *(plaintext + count) = *(plaintext + count) + (LOWERCASE_START - UPPERCASE_END - 1);

            if (*(plaintext + count) > LOWERCASE_END)
                *(plaintext + count) = (*(plaintext + count) % (LOWERCASE_END + 1)) + DIGIT_START; /* WRAP AROUND */
        }
        else if (isUppercaseLetter(character))
        {
            if (*(plaintext + count) > UPPERCASE_END)
                *(plaintext + count) = *(plaintext + count) + (LOWERCASE_START - UPPERCASE_END - 1);

            if (*(plaintext + count) > LOWERCASE_END)
            {
                *(plaintext + count) = (*(plaintext + count) % (LOWERCASE_END + 1)) + DIGIT_START; /* WRAP AROUND */
                if (*(plaintext + count) > DIGIT_END)
                    *(plaintext + count) = *(plaintext + count) + (UPPERCASE_START - DIGIT_END - 1);
            }
        }
        else if (isLowercaseLetter(character))
        {
            if (*(plaintext + count) > LOWERCASE_END)
            {
                *(plaintext + count) = (*(plaintext + count) % (LOWERCASE_END + 1)) + DIGIT_START; /* WRAP AROUND */
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
    Jqueue = queue_init();

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
            enqueue(Jqueue, counter);
        }
        if (*(ciphertext + counter + 1) == 'J')
        {
            *(ciphertext + counter + 1) = 'I';
            enqueue(Jqueue, counter + 1);
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
        /* elegxoi gia J */
        if (!queue_is_empty(Jqueue) && queue_peek(Jqueue) == counter)
        {
            printf("Jqueue sizeA: %u\n", Jqueue->size);
            dequeue(Jqueue);
            *(plaintext + counter) = 'J';
        }

        if (!queue_is_empty(Jqueue) && queue_peek(Jqueue) == counter + 1)
        {
            printf("Jqueue sizeB: %u\n", Jqueue->size);
            dequeue(Jqueue);
            *(plaintext + counter + 1) = 'J';
            continue;
        }

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
    ciphertext_size = 0;
    for (counter = 0; counter < length; counter++)
    {
        /* kratame mono ta kefalaia kai ta mikra ta kanoume kefalaia */
        if (!isUppercaseLetter(*(plaintext + counter)))
        {
            if (isLowercaseLetter(*(plaintext + counter)))
            {
                //convert to upper
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

/* AN DEN PAIZEI H STRNCPY
while(counter < BLOCK_SIZE){
        if(counter < (BLOCK_SIZE / 2)){
            swapped_block[counter] = right_block[counter];
        }else{
            swapped_block[counter] = left_block[counter - (BLOCK_SIZE / 2)];
        }
        counter ++;
    }*/
void swap(uint8_t *left_block, uint8_t *right_block)
{
    uint8_t *temp_block;

    temp_block = (uint8_t *)malloc(sizeof(uint8_t) * (BLOCK_SIZE / 2 + 1));

    strncpy((char *)temp_block, (char *)right_block, BLOCK_SIZE / 2);
    temp_block[BLOCK_SIZE / 2] = '\0';
    strncpy((char *)right_block, (char *)left_block, BLOCK_SIZE / 2);
    strncpy((char *)left_block, (char *)temp_block, BLOCK_SIZE / 2);

    free(temp_block);
    return;
}

uint8_t *feistel_round(uint8_t *block, uint8_t *key)
{
    /*  Pairnei to deksi meros ths 64adas bits -> an einai < 32 bits prosthetei terminals
        Kanei kapoia praksh me to key --> F(K_i,R_i) = (R_i * K_i) mod (2^32)
        */
}

uint8_t *feistel_encrypt(uint8_t *plaintext, uint8_t *keys[])
{
    size_t length, total_blocks, last_block_size, blocks_counter, rounds_counter;
    uint8_t *left_block, *right_block, *ciphertext, *key;
    /*  Xwrizw to plaintext se 64ades bits
        Exw 8 kleidia kai gia kathe kleidi
        kalw th round gia kathe deksi miso ths 64adas
        kanw XOR me to aristero miso ths antistoixhs 64adas
        kanw swap to deksi me to aristero meros
        */
    // meta to loop isws ksana swapped?
    length = strlen((char*) plaintext);
    ciphertext =  (uint8_t *) malloc (sizeof(uint8_t ) * (length + 1));
    left_block =  (uint8_t *) malloc (sizeof(uint8_t ) * (BLOCK_SIZE / 2 + 1));
    right_block = (uint8_t *) malloc (sizeof(uint8_t ) * (BLOCK_SIZE / 2 + 1));
    total_blocks = length / BLOCK_SIZE;
    if(last_block_size = (length % BLOCK_SIZE))
        total_blocks++;

    blocks_counter = 0;
    rounds_counter = 0;
    while(rounds_counter < NUM_OF_ROUNDS){
        key = key_generator(BLOCK_SIZE / 2);
        strcpy(keys[rounds_counter], key);
        free(key);
        key = NULL;
        while(blocks_counter < total_blocks){
            strncpy(left_block, plaintext[blocks_counter], BLOCK_SIZE / 2);
            strncpy(right_block, plaintext[blocks_counter + BLOCK_SIZE / 2], BLOCK_SIZE / 2);
            feistel_round(right_block, keys[rounds_counter]);
            //xor left right blocks
            swap(left_block, right_block);
            blocks_counter++;
        }
        rounds_counter++;
    }
    
    ciphertext[length] = '\0';
    return ciphertext;
}

uint8_t *feistel_decrypt(uint8_t *ciphertext, uint8_t *keys[])
{
    /*  Xwrizw to ciphertext se 64ades bits
        Exw 8 kleidia kai gia kathe kleidi phgainontas anapoda
        kalw th round gia kathe deksi miso ths 64adas
        kanw XOR me to aristero miso ths antistoixhs 64adas
        kanw swap to deksi me to aristero meros
        */
    // meta to loop isws ksana swapped?
}