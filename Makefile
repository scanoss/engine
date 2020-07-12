CC=gcc
LIBFLAGS=-O -Wall -g -lm -lpthread
BINFLAGS=-O -Wall -g -lm -lpthread -lcrypto

all: ldb scanoss

ldb: src/external/ldb/ldb.c src/external/ldb/ldb.h src/external/ldb/command.c
	@$(CC) $(LIBFLAGS) -c src/external/ldb/ldb.c src/external/ldb/command.c 
	@echo Library is built

scanoss: src/main.c src/scanoss.h src/limits.h 
	@$(CC) $(BINFLAGS) -o scanoss ldb.o src/main.c $(LIB_BASE)
	@echo Scanoss built

clean:
	@rm -f scanoss *.o

distclean: clean

install:
	@cp scanoss /usr/bin
