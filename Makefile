CFLAGS=		-g -O2 -std=c99 -pedantic -Wall -Wextra

SRC=		lc.c \
		log.c

SRC_BSD=	dev_bsd.c

BIN=		lc

all:
	@echo "No OS target specified. Please run 'make bsd'"
	exit 1

bsd: $(SRC) $(SRC_BSD)
	mkdir -p bin/
	$(CC) $(CFLAGS) -o bin/$(BIN) $(SRC) $(SRC_BSD)

clean:
	rm -rf bin/
