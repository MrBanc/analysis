CC := gcc
CFLAGS := $(PARAM)
BUILD_DIR := build

# Source files
SRC_DIR := src
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)

# Object files
OBJ_FILES := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%,$(SRC_FILES))

# Libraries
LIB_SRC_DIR := $(SRC_DIR)/lib
LIB_BUILD_DIR := $(BUILD_DIR)/lib
LIB_SRC_FILES := $(wildcard $(LIB_SRC_DIR)/*.c)
LIB_OBJ_FILES := $(patsubst $(LIB_SRC_DIR)/%.c,$(LIB_BUILD_DIR)/%.o,$(LIB_SRC_FILES))
LIB_SOBJ_FILES := $(patsubst $(LIB_SRC_DIR)/%.c,$(LIB_BUILD_DIR)/%.so,$(LIB_SRC_FILES))

# Targets
all: $(LIB_SOBJ_FILES) $(OBJ_FILES)

$(BUILD_DIR)/test%: $(SRC_DIR)/test%.c | $(BUILD_DIR)
	@if [ "$(shell echo $* | grep -E '^[0-9]+$$')" ]; then \
		$(CC) $(CFLAGS) -o $@ $< -ldl; \
	else \
		$(CC) $(CFLAGS) -o $@ $< -ldl -L$(LIB_BUILD_DIR) -lfptr
	fi

$(LIB_BUILD_DIR)/libfptr.so: $(LIB_BUILD_DIR)/libfptr2.so $(LIB_BUILD_DIR)/libfptr.o | $(LIB_BUILD_DIR)
	$(CC) $(CFLAGS) -shared -o $@ $^ -L$(LIB_BUILD_DIR) -lfptr2 -Wl,-rpath,'$$ORIGIN'

$(LIB_BUILD_DIR)/libfptr2.so: $(LIB_BUILD_DIR)/libfptr2.o | $(LIB_BUILD_DIR)
	$(CC) $(CFLAGS) -shared -o $@ $^

$(LIB_BUILD_DIR)/libfptr.o: $(LIB_SRC_DIR)/libfptr.c | $(LIB_BUILD_DIR)
	$(CC) $(CFLAGS) -c -fPIC -o $@ $< -L$(LIB_BUILD_DIR) -lfptr2

$(LIB_BUILD_DIR)/libfptr2.o: $(LIB_SRC_DIR)/libfptr2.c | $(LIB_BUILD_DIR)
	$(CC) $(CFLAGS) -c -fPIC -o $@ $<

# Ensure build directories exist
$(BUILD_DIR) $(LIB_BUILD_DIR):
	mkdir -p $@


# Clean target
clean:
	rm -rf $(BUILD_DIR)/*
