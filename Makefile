CC=gcc
LIBFLAGS=-O -Wall -g -lm -lpthread
BINFLAGS=-O -Wall -g -lm -lpthread -lcrypto

all: ldb scanoss

ldb: src/external/ldb/ldb.c src/external/ldb/ldb.h src/external/ldb/command.c
	@$(CC) -c src/external/ldb/ldb.c src/external/ldb/command.c $(LIBFLAGS)
	@echo Library is built

scanoss: src/main.c src/scanoss.h src/limits.h 
	@$(CC) -o scanoss ldb.o src/main.c $(BINFLAGS)
	@echo Scanoss built

clean:
	@rm -f scanoss *.o

distclean: clean

install:
	@cp scanoss /usr/bin
