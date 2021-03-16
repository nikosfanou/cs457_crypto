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

/* N in the range of 0 to 65,535 */
#define NUM 12
#define INIT_INPUT_SIZE 128

#define DIGIT_START 48 /* Start of digits in ascii table */
#define DIGIT_END 57   /* End of digits in ascii table */
#define UPPERCASE_START 65
#define LOWERCASE_START 97
#define UPPERCASE_END 90
#define LOWERCASE_END 122
#define NUM_OF_DIGITS 10
#define NUM_OF_LETTERS 26

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
 * @brief One-time pad encryption
 * 
 * @param plaintext Message to be encrypted
 * @param key Key for encryption-decryption
 * @return uint8_t* Encrypted message (ciphertext)
 */
/*uint8_t* otp_encrypt(uint8_t* plaintext, uint8_t* key);*/

/**
 * @brief One-time pad decryption
 * 
 * @param ciphertext Message to be decrypted
 * @param key Key for encryption-decryption
 * @return uint8_t* Decrypted message (plaintext)
 */
/* uint8_t* otp_decrypt(uint8_t* ciphertext, uint8_t * key); */

/**
 * @brief Caesar's cipher encryption
 * 
 * @param plaintext Message to be encrypted
 * @param N N-positions down the alphabet for the encryption of a character
 * @return uint8_t* Encrypted message (ciphertext)
 */
uint8_t* caesar_encrypt(uint8_t* plaintext, uint16_t N);

/**
 * @brief Caesar's cipher decryption
 * 
 * @param ciphertext Message to be decrypted
 * @param N N-positions down the alphabet for the encryption of a character
 * @return uint8_t* Decrypted message (plaintext)
 */
uint8_t* caesar_decrypt(uint8_t* ciphertext, uint16_t N);

/**
 * @brief Playfair cipher encryption
 * 
 * @param plaintext Message to be encrypted
 * @param key 5x5 matrix key for encryption-decryption
 * @return unsigned* Encrypted message (ciphertext)
 */
/* unsigned char* playfair_encrypt(unsigned char* plaintext, unsigned char** key); */

/**
 * @brief Playfair cipher decryption
 * 
 * @param ciphertext Message to be decrypted
 * @param key 5x5 matrix key for encryption-decryption
 * @return unsigned* Decrypted message (plaintext)
 */
/* unsigned char* playfair_decrypt(unsigned char* ciphertext, unsigned char** key); */

/**
 * @brief Creates and returns a 5x5 matrix key
 * 
 * @param key Key for encryption-decryption
 * @return unsigned**  5x5 matrix key
 */
/* unsigned char** playfair_keymatrix(unsigned char* key); */

/**
 * @brief Affine cipher encryption
 * 
 * @param plaintext Message to be encrypted
 * @return uint8_t* Encrypted message (ciphertext)
 */
/* uint8_t * affine_encrypt(uint8_t* plaintext); */

/**
 * @brief Affine cipher decryption
 * 
 * @param ciphertext Message to be decrypted
 * @return uint8_t* Decrypted message (plaintext)
 */
/* uint8_t * affine_decrypt(uint8_t* ciphertext); */

/**
 * @brief Feistel cipher encryption
 * 
 * @param plaintext Message to be encrypted
 * @param keys Array of keys for encryption-decryption
 * @return uint8_t* Encrypted message (ciphertext)
 */
/* uint8_t* feistel_encrypt(uint8_t* plaintext, uint8_t keys[]); */

/**
 * @brief Feistel cipher decryption
 * 
 * @param ciphertext Message to be decrypted
 * @param keys Array of keys for encryption-decryption
 * @return uint8_t* Decrypted message (plaintext)
 */
/* uint8_t* feistel_decrypt(uint8_t* ciphertext, uint8_t keys[]); */

/**
 * @brief The round function is run on half of the data to be
 * encrypted and its output is XORed with the other half of
 * the data.
 * 
 * @param block Block of data to be encrypted/decrypted
 * @param key Key for encryption-decryption
 * @return uint8_t* Encrypted/Decrypted message (ciphertext/plaintext)
 */
/* uint8_t* round(uint8_t* block, uint8_t* key); */