/**
 * @file cs457_crypto.h
 * @author Fanourakis Nikos (csd4237@csd.uoc.gr)
 * @brief A simple cryptographic library using C
 * Five cryptographic algorithms: 
 * (i) One-time pad, (ii) Caesar’s cipher, (iii) Playfair cipher,
 * (iv) Affine cipher and (v) Feistel cipher
 */

#include <stdint.h>
#include <unistd.h>

/*  N in the range of 0 to 65,535 
    KEY for caesar's cryptography*/
#define NUM 57894
#define INIT_INPUT_SIZE 128

/* Start of digits in ascii table */
#define DIGIT_START 48
/* End of digits in ascii table */
#define DIGIT_END 57
#define UPPERCASE_START 65
#define LOWERCASE_START 97
#define UPPERCASE_END 90
#define LOWERCASE_END 122
#define NUM_OF_DIGITS 10
#define NUM_OF_LETTERS 26
#define CEASAR_ALPHABET_SIZE    (NUM_OF_DIGITS + 2 * NUM_OF_LETTERS)

#define KEYMATRIX_SIZE 25
#define KEYMATRIX_ROWS 5
#define KEYMATRIX_COLUMNS 5

/*  h apostash metaksy kefalaiwn kai mikrwn xarakthrwn ston pinaka ASCII 
    Xrhsimevei sthn antikatastash twn mikrwn xarakthrwn se megala. */
#define UPPER_LOWER_DISTANCE 32
/*  f(x) = (A * X + B) mod M
    A is a constant
    B is the magnitude of the shift
    X is the letter to encrypt
    M the number of letters
*/
#define A 11
#define B 19
#define M 26

#define BLOCK_SIZE 64
#define NUM_OF_ROUNDS 8

#define ONE_TIME_PAD 1
#define CAESAR_CIPHER 2
#define PLAYFAIR_CIPHER 3
#define AFFINE_CIPHER 4
#define FEISTEL_CIPHER 5

/**
 * @brief Checks if character is uppercase letter.
 * 
 */
#define isUppercaseLetter(character) \
    (character >= UPPERCASE_START && character <= UPPERCASE_END)

/**
 * @brief Checks if character is lowercase letter.
 * 
 */
#define isLowercaseLetter(character) \
    (character >= LOWERCASE_START && character <= LOWERCASE_END)

/**
 * @brief Checks if character is digit.
 * 
 */
#define isDigit(character) \
    (character >= DIGIT_START && character <= DIGIT_END)

/**
 * @brief Checks if number is odd.
 * 
 */
#define isOdd(number) \
    (number % 2)

/**
 * @brief Checks if the two uppercase letters are in the same row in keymatrix.
 * 
 */
#define sameKeyMatrixRow(row1, row2) \
    (row1 == row2)

/**
 * @brief Checks if the two uppercase letters are in the same column in keymatrix.
 * 
 */
#define sameKeyMatrixColumn(column1, column2) \
    (column1 == column2)

/**
 * @brief One-time pad encryption
 * 
 * @param plaintext     Message to be encrypted
 * @param key Key for   encryption-decryption
 * @return uint8_t*     Encrypted message (ciphertext)
 */
uint8_t *otp_encrypt(uint8_t *plaintext, uint8_t *key);

/**
 * @brief One-time pad decryption
 * 
 * @param ciphertext    Message to be decrypted
 * @param key Key for   encryption-decryption
 * @return uint8_t*     Decrypted message (plaintext)
 */
uint8_t *otp_decrypt(uint8_t *ciphertext, uint8_t *key);

/**
 * @brief Caesar's cipher encryption
 * 
 * @param plaintext     Message to be encrypted
 * @param N             N-positions down the alphabet for the encryption of a character
 * @return uint8_t*     Encrypted message (ciphertext)
 */
uint8_t *caesar_encrypt(uint8_t *plaintext, uint16_t N);

/**
 * @brief Caesar's cipher decryption
 * 
 * @param ciphertext    Message to be decrypted
 * @param N             N-positions down the alphabet for the encryption of a character
 * @return uint8_t*     Decrypted message (plaintext)
 */
uint8_t *caesar_decrypt(uint8_t *ciphertext, uint16_t N);

/**
 * @brief Playfair cipher encryption
 * 
 * @param plaintext     Message to be encrypted
 * @param key           5x5 matrix key for encryption-decryption
 * @return unsigned*    Encrypted message (ciphertext)
 */
unsigned char *playfair_encrypt(unsigned char *plaintext, unsigned char **key);

/**
 * @brief Playfair cipher decryption
 * 
 * @param ciphertext    Message to be decrypted
 * @param key           5x5 matrix key for encryption-decryption
 * @return unsigned*    Decrypted message (plaintext)
 */
unsigned char *playfair_decrypt(unsigned char *ciphertext, unsigned char **key);

/**
 * @brief Creates and returns a 5x5 matrix key
 * 
 * @param key           Key for encryption-decryption
 * @return unsigned**   5x5 matrix key
 */
unsigned char **playfair_keymatrix(unsigned char *key);

/**
 * @brief   Gets the position of letter on Keymatrix object 
 *          and stores it at row,column parameters
 * 
 * @param keymatrix 5x5 matrix key
 * @param letter    Character of plaintext/ciphertext
 * @param row       The row of the letter on the keymatrix
 * @param column    The column of the letter on the keymatrix
 */
void getPositionOnKeymatrix(unsigned char **keymatrix, unsigned char letter, size_t *row, size_t *column);

/**
 * @brief Affine cipher encryption
 * 
 * @param plaintext     Message to be encrypted
 * @return uint8_t*     Encrypted message (ciphertext)
 */
uint8_t *affine_encrypt(uint8_t *plaintext);

/**
 * @brief Affine cipher decryption
 * 
 * @param ciphertext    Message to be decrypted
 * @return uint8_t*     Decrypted message (plaintext)
 */
uint8_t * affine_decrypt(uint8_t* ciphertext);

/**
 * @brief   Function taken from geeks for geeks
 *          Given two integers ‘a’ and ‘m’, finds modular multiplicative inverse of ‘a’ under modulo ‘m’.
 * 
 * @param a The integer a
 * @param m The integer m
 * @return int Returns modular multiplicative inverse of ‘a’ under modulo ‘m’.
 */
int modInverse(int a, int m);

/**
 * @brief The round function is run on half of the data to be
 * encrypted and its output is XORed with the other half of
 * the data.
 * 
 * @param block     Block of data to be encrypted/decrypted
 * @param key       Key for encryption-decryption
 * @return uint8_t* Encrypted/Decrypted message (ciphertext/plaintext)
 */
uint8_t* feistel_round(uint8_t* block, uint8_t* key);

/**
 * @brief Feistel cipher encryption
 * 
 * @param plaintext     Message to be encrypted
 * @param keys          Array of keys for encryption-decryption
 * @return uint8_t*     Encrypted message (ciphertext)
 */
uint8_t* feistel_encrypt(uint8_t* plaintext, uint8_t keys[]);

/**
 * @brief Feistel cipher decryption
 * 
 * @param ciphertext    Message to be decrypted
 * @param keys          Array of keys for encryption-decryption
 * @return uint8_t*     Decrypted message (plaintext)
 */
uint8_t* feistel_decrypt(uint8_t* ciphertext, uint8_t keys[]);


void swap(uint8_t *left_block, uint8_t *right_block, unsigned int length);