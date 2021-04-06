# A simple cryptographic library using C
## Fanourakis Nikos 4237

The cryptographic library will provide five cryptographic algorithms: 

(i) One-time pad, (ii) Caesar’s cipher, (iii) Playfair cipher,
(iv) Affine cipher and (v) Feistel cipher

##HOW TO COMPILE:

make all

##HOW TO RUN:

./crypto (-i "inputfile") (-o "outputfile") (-c for ceasar cipher) (-1 for one time pad cipher)
(-p for playfair cipher) (-a for affine cipher) (-f for feistel cipher)

Without arguments it runs with the defaults:

Input file = stdin

Output file = stdout

Cipher = one time pad

You can use:

make otp --> To run crypto with one time pad cipher and the default stream files.

make caesar --> To run crypto with caesar cipher and the default stream files.

make playfair --> To run crypto with playfair cipher and the default stream files.

make affine --> To run crypto with affine cipher and the default stream files.

make feistel --> To run crypto with feistel cipher and the default stream files.

##BRIEF DESCRIPTION OF HOW THE ALGORITHMS WORK:

One time pad:

    Encryption:

        XORs plaintext with a key of same size.

    Decryption:

        XORs ciphertext with the same key as in encryption.

    Alphabet set:

        All characters

Caesar's cipher:

    Encryption:

        Each byte/character of the plaintext is replaced by a
        byte/character found at some fixed number (N) of positions down the alphabet set.

    Decryption:

        Each byte/character of the ciphertext is replaced by a
        byte/character found at some fixed number (N) of positions up the alphabet set.

    Alphabet set:

        Alphabet set is digits, lower and uppercase letters.
        Other characters are not encrypted/decrypted.

Playfair cipher:

    The Playfair cipher uses a key to create a 5x5 key matrix. This key matrix will determine the encryption.
    In order to create the table, the letters of the key are placed in the grid, from left to right beginning
    from the first row. Then the rest of the alphabet's letters are inserted in the grid alphabetically.
    Each letter is placed once in the grid. Since the 5x5 grid can only hold 25 characters 'J' is usually omitted 
    and treated as 'I'. If the letters of the group are the same the second letter is replaced with 'X'.
    If the number of the letters in the plaintext is even, the last letters are grouped with an 'X' character.
    
    Encryption:

        If the letters are on the same row on the table they will be replaced with the letters to their
        immediate right respectively.
        If the letters appear on the same column of the key grid, they will be replaced with the letters
        immediately below respectively.
        If the letters are not on the same row or column, they will be replaced with the letters on the
        same row respectively but at the other pair of corners of the rectangle defined by the original pair.

    Decryption:

        If the letters are on the same row on the table they will be replaced with the letters to their
        immediate left respectively.
        If the letters appear on the same column of the key grid, they will be replaced with the letters
        immediately above respectively.
        If the letters are not on the same row or column, they will be replaced with the letters on the
        same row respectively but at the other pair of corners of the rectangle defined by the original pair.

    Alphabet set:

        Only uppercase letters.

Affine cipher:

    Encryption:

        Uses the function f(x) = ax + b mod m, where 'a' is a constant, 'b'
        is the magnitude of the shift and 'x' is the letter to encrypt.

    Decryption:

        Uses the function D(x) = a^-1 * (x - b) mod m where a^-1 is the modular multiplicative inverse
        of a mod m. The multiplicative inverse of a only exists if a and m are coprime.
        Hence without the restriction on a , decryption might not be possible. The letter x denotes the encrypted letter.

    Alphabet set:

        Only uppercase letters and lowercase are converted to uppercase.

Feistel cipher:

    Encryption:

        In order to encrypt a plaintext we first separate it in blocks of size 8 bytes. If it cannot be seperated in blocks
        of 8 bytes we fill it with terminal characters at the end. Each block is then splitted in half.
        We encrypt the left block by XOR-ing it with the output of the round function in each step. We do not apply
        any kind of operations in the right block. Lastly we reverse the order of the blocks (meaning the
        left goes right and the right goes left) and we repeat for 8 iterations.

    Decryption:

        Decryption works in the opposite way.

    Alphabet set:

        All characters.
