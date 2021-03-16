# Fanourakis Nikos csd4237

CC = gcc

LIB = cs457_crypto.h
LIB_IMP = cs457_crypto.c
TEST_FILE = cs457_crypto_test.c

GCC_FLAGS = -pedantic -o
HELP_FLAG = -h
OTP_FLAG = -1
CAESAR_FLAG = -c
PLAYFAIR_FLAG = -p
AFFINE_FLAG = -a
FEISTEL_FLAG = -f
EXEC_FILE = crypto

run: all
	./$(EXEC_FILE)

help: all
	./$(EXEC_FILE) $(HELP_FLAG)

otp: all
	./$(EXEC_FILE) $(OTP_FLAG)

caesar: all
	./$(EXEC_FILE) $(CAESAR_FLAG)

playfair: all
	./$(EXEC_FILE) $(PLAYFAIR_FLAG)

affine: all
	./$(EXEC_FILE) $(AFFINE_FLAG)

feistel: all
	./$(EXEC_FILE) $(FEISTEL_FLAG)

all: $(LIB) $(LIB_IMP) $(TEST_FILE)
	$(CC) $(LIB_IMP) $(TEST_FILE) $(GCC_FLAGS) $(EXEC_FILE)

clean:
	rm -f $(EXEC_FILE)
