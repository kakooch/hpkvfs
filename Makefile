# Makefile for HPKV FUSE Filesystem

# Compiler and Flags
CC = gcc
# Get flags from pkg-config, add required FUSE flag and warnings
CFLAGS = $(shell pkg-config --cflags fuse libcurl jansson) -D_FILE_OFFSET_BITS=64 -Wall -Wextra -O2
LDFLAGS = $(shell pkg-config --libs fuse libcurl jansson)

# Source and Target
SRC = hpkvfs.c
TARGET = hpkvfs

# Default target
all: $(TARGET)

# Build target executable
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Clean target
clean:
	rm -f $(TARGET)
	@echo "Clean complete."

# Phony targets
.PHONY: all clean

