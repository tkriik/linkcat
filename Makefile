CFLAGS=		-g -O2 -std=c99 -pedantic -Wall -Wextra

SRC=		lc.c \
		dev_bsd.c \
		log.c

BIN=		lc

all: $(SRC)
	mkdir -p bin/
	$(CC) $(CFLAGS) -o bin/$(BIN) $(SRC)
