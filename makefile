CC = gcc
SRC = $(wildcard *.c) $(wildcard *.h)
WARNINGS = -Wall -Wextra -Wno-unused-result
INCLUDES = -lcrypto
CFLAGS = $(WARNINGS) -march=native -O2 -flto -s -D_FORTIFY_SOURCE=1 $(INCLUDES)
DFLAGS = -g

build: $(SRC)
	$(CC) -o cpass $(SRC) $(CFLAGS)

debug: $(SRC)
	$(CC) -o cpass-debug $(SRC) $(DFLAGS) $(INCLUDES)
