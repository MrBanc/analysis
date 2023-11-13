# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -Isrc/include
CFLAGS_D := $(PARAM)
LDFLAGS := -lm -pthread -lcrypt

# Directories
SRC_DIR := src
INCLUDE_DIR := $(SRC_DIR)/include
FUNC_DIR := $(SRC_DIR)/functional
COMMON_DIR := $(SRC_DIR)/common
BUILD_DIR := build

# Source files
FUNC_SRC := $(wildcard $(FUNC_DIR)/*.c)
COMMON_SRC := $(wildcard $(COMMON_DIR)/*.c)

# Object files
FUNC_OBJ := $(patsubst $(FUNC_DIR)/%.c,$(BUILD_DIR)/%.o,$(FUNC_SRC))
COMMON_OBJ := $(patsubst $(COMMON_DIR)/%.c,$(BUILD_DIR)/%.o,$(COMMON_SRC))

# Targets
all: main

main: $(FUNC_OBJ) $(COMMON_OBJ)
	$(CC) $(CFLAGS) $(CFLAGS_D) $(LDFLAGS) main.c -o $@ $^

# Pattern rule for building object files
$(BUILD_DIR)/%.o: $(FUNC_DIR)/%.c
	$(CC) $(CFLAGS) $(CFLAGS_D) $(LDFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: $(COMMON_DIR)/%.c
	$(CC) $(CFLAGS) $(CFLAGS_D) $(LDFLAGS) -c -o $@ $<

# Clean target
clean:
	rm -rf $(BUILD_DIR)/*.o main
