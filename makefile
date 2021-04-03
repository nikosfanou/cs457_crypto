# Fanourakis Nikos csd4237

CC = gcc

CRYPTO_LIB = cs457_crypto.h
CRYPTO_IMP = cs457_crypto.c
CRYPTO_DEF = crypto_defines.h
QUEUE_LIB = queue/queue.h
QUEUE_IMP = queue/queue.c
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

all: $(CRYPTO_LIB) $(CRYPTO_IMP) $(TEST_FILE) $(QUEUE_LIB) $(QUEUE_IMP)
	$(CC) $(CRYPTO_IMP) $(TEST_FILE) $(QUEUE_IMP) $(GCC_FLAGS) $(EXEC_FILE)

clean:
	rm -f $(EXEC_FILE)
