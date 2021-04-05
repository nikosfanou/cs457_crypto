/**
 * @file crypto_defines.h
 * @author Fanourakis Nikos (csd4237@csd.uoc.gr)
 * @brief A header file which includes defines and macros
 * for cs457_crypto.h file.
 */

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
#define CEASAR_ALPHABET_SIZE (NUM_OF_DIGITS + 2 * NUM_OF_LETTERS)

#define KEYMATRIX_SIZE 25
#define KEYMATRIX_ROWS 5
#define KEYMATRIX_COLUMNS 5

/*  The distance of the first uppercase and
    the first lowercase letter in ASCII table. */
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

#define BLOCK_SIZE 8
#define NUM_OF_ROUNDS 8
/* 2 ^ 4 = 16 */
#define TWO_POWER_FOUR 16

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

