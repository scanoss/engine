CC = gcc
AR = ar
CFLAGS = -Wall -g -O0 -I../inc -I../external/inc -fPIC -D_GNU_SOURCE
LDFLAGS = -lssl -lcrypto -lz -lm

SRC_DIR = ../src
EXTERNAL_DIR = ../external
OBJ_DIR = obj
LIB_NAME = el.a

WRAPPER_SRCS = snippets_wrapper.c

ENGINE_SRCS = $(SRC_DIR)/snippets.c \
              $(SRC_DIR)/util.c \
              $(SRC_DIR)/scanlog.c \
              $(EXTERNAL_DIR)/src/crc32c.c

WRAPPER_OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(notdir $(WRAPPER_SRCS)))
ENGINE_OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(notdir $(ENGINE_SRCS)))
ALL_OBJS = $(WRAPPER_OBJS) $(ENGINE_OBJS)

.PHONY: all clean

all: $(OBJ_DIR) $(LIB_NAME)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(LIB_NAME): $(ALL_OBJS)
	$(AR) rcs $@ $^

$(OBJ_DIR)/snippets_wrapper.o: snippets_wrapper.c snippets_wrapper.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/crc32c.o: $(EXTERNAL_DIR)/src/crc32c.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(LIB_NAME)

test: $(LIB_NAME)
	go build -o wfp_scanner example/wfp_scanner.go
	./wfp_scanner example/test.wfp