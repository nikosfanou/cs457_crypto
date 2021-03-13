# Fanourakis Nikos csd4237

CC = gcc

LIB = cs457_crypto.h
LIB_IMP = cs457_crypto.c
TEST_FILE = cs457_crypto_test.c

GCC_FLAGS = -ansi -Warrior -pedantic
EXEC_FILE = crypto

run: all
	./$(EXEC_FILE)

all: $(LIB) $(LIB_IMP) $(TEST_FILE)
	$(CC) $(LIB_IMP) $(TEST_FILE) $(GCC_FLAGS) $(EXEC_FILE)

clean:
	rm -f $(EXEC_FILE)
