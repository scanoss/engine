ifeq ($(origin CC),default)
CC = gcc
endif
CCFLAGS ?= -O -lz -Wall -Wno-unused-result -Wno-deprecated-declarations -g -Iinc -Iexternal/inc -D_LARGEFILE64_SOURCE -D_GNU_SOURCE
LDFLAGS+= -lldb -lm -lpthread -lcrypto -ldl
SOURCES=$(wildcard src/*.c) $(wildcard src/**/*.c)  $(wildcard external/*.c) $(wildcard external/**/*.c)
OBJECTS=$(SOURCES:.c=.o) 
TARGET=scanoss
$(TARGET): $(OBJECTS)
	$(CC) -g -o $(TARGET) $^ $(LDFLAGS)

.PHONY: scanoss

%.o: %.c
	$(CC) $(CCFLAGS) -o $@ -c $<

clean_build:
	rm -rf src/*.o src/**/*.o external/src/*.o external/src/**/*.o

clean: clean_build
	rm -rf $(TARGET)

distclean: clean

install:
	@cp scanoss /usr/bin

