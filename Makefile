ifeq ($(origin CC),default)
CC = gcc
endif

LDFLAGS+= -lldb -lm -lpthread -ldl

LDB_CURRENT_VERSION := $(shell ldb -v | sed 's/ldb-//' | head -c 3)
LDB_TARGET_VERSION := 3.2

VERSION_IS_LESS := $(shell echo $(LDB_CURRENT_VERSION) \< $(LDB_TARGET_VERSION) | bc)
ifeq ($(VERSION_IS_LESS),1)
	LDFLAGS += -lcrypto -lz
endif

CCFLAGS ?= -O -lz -Wall -Wno-unused-result -Wno-deprecated-declarations -g -Iinc -Iexternal/inc -D_LARGEFILE64_SOURCE -D_GNU_SOURCE
SOURCES=$(wildcard src/*.c) $(wildcard src/**/*.c)  $(wildcard external/*.c) $(wildcard external/**/*.c)
OBJECTS=$(SOURCES:.c=.o) 
TARGET=scanoss


# Regla de prueba
$(TARGET): $(OBJECTS)
	@echo "Current version: $(LDB_CURRENT_VERSION)"
	@echo "LDFLAGS: $(LDFLAGS)"

	$(CC) -g -o $(TARGET) $^ $(LDFLAGS)

VERSION=$(shell ./version.sh)

.PHONY: scanoss

%.o: %.c
	$(CC) $(CCFLAGS) -o $@ -c $<

all: clean scanoss

clean_build:
	rm -rf src/*.o src/**/*.o external/src/*.o external/src/**/*.o

clean: clean_build
	rm -rf $(TARGET)

distclean: clean

install:
	@cp scanoss /usr/bin

prepare_deb_package: all ## Prepares the deb Package 
	@./package.sh deb $(VERSION)
	@echo deb package built

prepare_rpm_package: all ## Prepares the rpm Package 
	@./package.sh rpm $(VERSION)
	@echo rpm package built
