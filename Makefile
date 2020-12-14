CC = gcc
CFLAGS = -O -Wall -g -Isrc/external/json-parser -Isrc/external/ldb 
DEPS = src/main.c src/scanoss.h src/limits.h 
OBJ=obj/main.o obj/blacklist.o obj/scanoss.o obj/blacklist.o obj/scan.o obj/psi.o obj/keywords.o obj/match.o obj/report.o obj/spdx.o obj/cyclonedx.o obj/copyright.o obj/vulnerability.o obj/quality.o obj/license.o obj/dependency.o obj/file.o obj/parse.o obj/query.o obj/debug.o obj/help.o obj/winnowing.o obj/crc32c.o obj/util.o obj/limits.o obj/json.o
 obj/%.o: src/%.c
	@echo Building deps
	$(CC) $(CFLAGS) -c -o $@ $<

scanoss: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -L. -lldb -lm -lpthread -lcrypto
	export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH
	@echo Scanoss built
clean:
	@echo Cleaning...
	@rm -f obj/*.o
	@rm -f scanoss *.o

distclean: clean

install:
	@cp libldb.so /usr/lib
	@cp scanoss /usr/bin

