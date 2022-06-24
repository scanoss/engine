ifeq ($(origin CC),default)
CC = gcc
endif
CFLAGS ?= -O -lz -Wall -g -Iinc -Iexternal/inc -D_LARGEFILE64_SOURCE -D_GNU_SOURCE
OBJ = bin/main.o bin/decrypt.o bin/ignorelist.o bin/ignored_extensions.o bin/snippets.o bin/scan.o bin/match.o bin/report.o bin/copyright.o bin/vulnerability.o bin/quality.o bin/license.o bin/dependency.o bin/file.o bin/parse.o bin/query.o bin/debug.o bin/help.o bin/winnowing.o bin/crc32c.o bin/util.o bin/limits.o bin/json.o bin/rank.o bin/mz.o bin/attributions.o bin/cryptography.o bin/versions.o bin/url.o bin/semver.o bin/hpsm.o bin/match_list.o
 
 bin/%.o: src/%.c
	@echo Building deps
	$(CC) $(CFLAGS) -c -o $@ $<
	
 bin/%.o: external/src/%.c
	@echo Building external deps
	$(CC) $(CFLAGS) -c -o $@ $<

scanoss: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lldb -lm -lpthread -lcrypto -ldl
	@echo Scanoss built
clean:
	@echo Cleaning...
	@rm -f bin/*.o
	@rm -f scanoss *.o

distclean: clean

install:
	@cp scanoss /usr/bin

uninstall:
	@rm libldb.so /usr/lib
	@rm scanoss /usr/bin

