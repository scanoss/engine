CC=gcc
LIBFLAGS=-O -Wall -g -lm -lpthread
BINFLAGS=-O -Wall -g -lm -lpthread -lcrypto -L. -lldb 

all: clean scanoss

scanoss: src/main.c src/scanoss.h src/limits.h 
	@$(CC) -o scanoss src/main.c $(BINFLAGS)
	@export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH
	@echo Scanoss built

clean:
	@echo Cleaning...
	@rm -f scanoss *.o

distclean: clean

install:
	@cp libldb.so /usr/lib
	@cp scanoss /usr/bin
