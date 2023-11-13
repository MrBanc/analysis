CC := gcc
CFLAGS := $(PARAM)
BUILD_DIR := build

# Source files
SRC_DIR := src
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)

# Object files
OBJ_FILES := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%,$(SRC_FILES))

# Targets
all: $(OBJ_FILES)

$(BUILD_DIR)/%: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -o $@ $<

# Clean target
clean:
	rm -rf $(BUILD_DIR)/*