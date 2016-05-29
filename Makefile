CFLAGS=		-g -O2 -std=c99 -pedantic -Wall -Wextra
LFLAGS=		-lpthread

SRC=		lc.c \
		addr.c \
		dev_bsd.c

BIN=		lc

all: $(SRC)
	mkdir -p bin/
	$(CC) $(CFLAGS) -o bin/$(BIN) $(SRC) $(LFLAGS)

clean:
	rm -rf bin/
