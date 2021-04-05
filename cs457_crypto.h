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
#include "crypto_defines.h"
#include <stdio.h>


/**
 * @brief Reads the content of the input file and copies it on a string. Then returns
 * the string.
 * 
 * @param input_message Pointer on the input file
 * @return uint8_t*     Message to be encrypted
 */
uint8_t *read_plaintext(FILE *input_message);

/**
 * @brief Creates a key with the same size as plaintext using /dev/urandom.
 * 
 * @param plaintext Message to be encrypted
 * @return uint8_t* Returns the key
 */
uint8_t *key_generator(size_t plaintext_size);

/**
 * @brief   Copies on string result the result of the xor operation on
 *          strings str1, str2 for length bytes.
 * 
 * @param result A string where the result of the operation xor is copied
 * @param str1 The first operand
 * @param str2 The second operand
 * @param length The size of the strings
 */
void apply_xor(uint8_t *result, uint8_t *str1, uint8_t *str2, size_t length);

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
 * @brief Prints the 5x5 keymatrix
 * 
 * @param key_matrix 5x5 matrix key
 */
void print_keymatrix(unsigned char **key_matrix);

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
uint8_t *affine_decrypt(uint8_t *ciphertext);

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
 * encrypted. Applies the operation F(K_i,R_i) = (R_i * K_i) mod (2^32) bits
 * where R_i is the right block of plain/cipher text and K_i is the key
 * in iteration i.
 * 
 * @param block     Block of data
 * @param key       Key for encryption-decryption
 * @return uint8_t* The result of the operation
 */
uint8_t *feistel_round(uint8_t *block, uint8_t *key);

/**
 * @brief Feistel cipher encryption
 * 
 * @param plaintext     Message to be encrypted
 * @param keys          Array of keys for encryption-decryption
 * @return uint8_t*     Encrypted message (ciphertext)
 */
uint8_t *feistel_encrypt(uint8_t *plaintext, uint8_t keys[][(BLOCK_SIZE / 2) + 1]);

/**
 * @brief Feistel cipher decryption
 * 
 * @param ciphertext        Message to be decrypted
 * @param keys              Array of keys for encryption-decryption
 * @param plaintext_size    The size of the plaintext
 * @return uint8_t*         Decrypted message (plaintext)
 */
uint8_t *feistel_decrypt(uint8_t *ciphertext, uint8_t keys[][(BLOCK_SIZE / 2) + 1], size_t plaintext_size);

/**
 * @brief   Swaps the left block with the right block.
 *          So now left is equal with old right and right
 *          is equal with old left.
 * 
 * @param left_block Left half of a data block
 * @param right_block Right half of a data block
 */
void feistel_swap(uint8_t *left_block, uint8_t *right_block);

/**
 * @brief If the block doesnt have size of n*64 bits
 * this function creates a new block, copies the old in it 
 * and fills it with terminal characters until its size
 * is equal with padding_block_size.
 * 
 * @param block Block of data (cipher/plain text)
 * @param padding_block_size The desired length of the padding block
 * @return uint8_t* Returns the padding block
 */
uint8_t *feistel_padding(uint8_t *block, size_t padding_block_size);