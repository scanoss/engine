ifeq ($(origin CC),default)
CC = gcc
endif

LDFLAGS+= -lldb -lm -lpthread -ldl

# Minimum LDB requirement. The single source of truth is inc/ldb_compat.h, which
# is also what the run time check in src/ldb_compat.c compiles against, so the
# build time and run time checks cannot drift apart.
LDB_COMPAT_HEADER := inc/ldb_compat.h
LDB_VERSION_CHECK := scripts/check_ldb_version.sh

CCFLAGS ?= -O -lz -Wall -Wno-unused-result -Wno-deprecated-declarations -g -Iinc -Iexternal/inc -D_LARGEFILE64_SOURCE -D_GNU_SOURCE
SOURCES=$(wildcard src/*.c) $(wildcard src/**/*.c)  $(wildcard external/*.c) $(wildcard external/**/*.c)
OBJECTS=$(SOURCES:.c=.o) 
TARGET=scanoss


# Regla de prueba
$(TARGET): $(OBJECTS) | check_ldb_version
	$(CC) -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)

# Verify the installed LDB before anything is compiled. Declared as an
# order-only prerequisite of every object so it also runs under `make -j`, and
# kept out of the plain `make clean` path.
.PHONY: check_ldb_version
check_ldb_version: $(LDB_VERSION_CHECK) $(LDB_COMPAT_HEADER)
	@$(LDB_VERSION_CHECK) $(LDB_COMPAT_HEADER)

VERSION=$(shell ./version.sh)

.PHONY: scanoss

%.o: %.c | check_ldb_version
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
