# DIRTYFAIL — Makefile
#
# Builds a single statically-linked binary `dirtyfail` from src/*.c.
#
# Targets:
#   make           build optimized binary
#   make debug     build with -O0 -g for gdb
#   make static    build a fully static binary (musl recommended for portability)
#   make clean     remove build artifacts
#   make scan      build and run --scan against localhost
#
# Build prerequisites: gcc or clang, make, libc headers including
# <linux/xfrm.h>. On Debian/Ubuntu: `apt install build-essential linux-libc-dev`.
# On RHEL/Fedora: `dnf install gcc make kernel-headers`.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -Wno-pointer-arith \
           -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
LDFLAGS ?=

SRC_DIR := src
BUILD   := build
SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(BUILD)/%.o,$(SOURCES))
BIN     := dirtyfail

.PHONY: all debug static clean scan install

all: $(BIN)

$(BIN): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BUILD)/%.o: $(SRC_DIR)/%.c $(SRC_DIR)/common.h | $(BUILD)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

$(BUILD):
	@mkdir -p $(BUILD)

debug: CFLAGS := -O0 -g3 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
debug: clean $(BIN)

# `make static` works best with musl-gcc; glibc static linking pulls in
# NSS at runtime which breaks getpwnam.
static: LDFLAGS += -static
static: clean $(BIN)

clean:
	rm -rf $(BUILD) $(BIN)

scan: $(BIN)
	./$(BIN) --scan

install: $(BIN)
	install -m 0755 $(BIN) /usr/local/bin/dirtyfail
