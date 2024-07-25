CC := gcc
CFLAGS := $(PARAM)
BUILD_DIR := build

CURRENT_DIR := $(shell pwd)

# Source files
SRC_DIR := src
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
ASM_SRC_FILES := $(wildcard $(SRC_DIR)/*.s)

# Object files
OBJ_FILES := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%,$(SRC_FILES))
ASM_OBJ_FILES := $(patsubst $(SRC_DIR)/%.s,$(BUILD_DIR)/%,$(ASM_SRC_FILES))

# Libraries
LIB_SRC_DIR := $(SRC_DIR)/lib
LIB_BUILD_DIR := $(BUILD_DIR)/lib
LIB_SRC_FILES := $(wildcard $(LIB_SRC_DIR)/*.c)
LIB_OBJ_FILES := $(patsubst $(LIB_SRC_DIR)/%.c,$(LIB_BUILD_DIR)/%.o,$(LIB_SRC_FILES))
LIB_SOBJ_FILES := $(patsubst $(LIB_SRC_DIR)/%.c,$(LIB_BUILD_DIR)/%.so,$(LIB_SRC_FILES))

# Targets
all: $(LIB_SOBJ_FILES) $(OBJ_FILES) $(ASM_OBJ_FILES)

$(BUILD_DIR)/test%: $(SRC_DIR)/test%.c | $(BUILD_DIR)
	@if [ "$(shell echo $* | grep -E '^[0-9]+$$')" ]; then \
		cd build && $(CC) $(CFLAGS) -o $(subst build/,,$@) $(addprefix ../,$^) -ldl && cd - > /dev/null; \
	else \
		cd build && $(CC) $(CFLAGS) -o $(subst build/,,$@) $(addprefix ../,$^) -ldl -L$(CURRENT_DIR)/$(LIB_BUILD_DIR) -lfptr -lfptr2 && cd -; \
	fi

$(BUILD_DIR)/test%: $(SRC_DIR)/test%.s | $(BUIrD_DIR)
	cd build && $(CC) $(CFLAGS) -o $(subst build/,,$@) $(addprefix ../,$^) && cd - > /dev/null

$(LIB_BUILD_DIR)/libfptr.so: $(LIB_BUILD_DIR)/libfptr2.so $(LIB_BUILD_DIR)/libfptr.o | $(LIB_BUILD_DIR)
	cd build && $(CC) $(CFLAGS) -shared -o $(subst build/,,$@) $(subst build/,,$^) -L$(CURRENT_DIR)/$(LIB_BUILD_DIR) && cd - > /dev/null

$(LIB_BUILD_DIR)/libfptr2.so: $(LIB_BUILD_DIR)/libfptr2.o | $(LIB_BUILD_DIR)
	cd build && $(CC) $(CFLAGS) -shared -o $(subst build/,,$@) $(subst build/,,$^) && cd - > /dev/null

$(LIB_BUILD_DIR)/libfptr.o: $(LIB_SRC_DIR)/libfptr.c | $(LIB_BUILD_DIR)
	cd build && $(CC) $(CFLAGS) -c -fPIC -o $(subst build/,,$@) $(addprefix ../,$^) -L$(CURRENT_DIR)/$(LIB_BUILD_DIR) -lfptr2 && cd - > /dev/null

$(LIB_BUILD_DIR)/libfptr2.o: $(LIB_SRC_DIR)/libfptr2.c | $(LIB_BUILD_DIR)
	cd build && $(CC) $(CFLAGS) -c -fPIC -o $(subst build/,,$@) $(addprefix ../,$^) && cd - > /dev/null

# Ensure build directories exist
$(BUILD_DIR) $(LIB_BUILD_DIR):
	mkdir -p $@


# Clean target
clean:
	rm -rf $(BUILD_DIR)/*
