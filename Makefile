include Makefile.inc

SRC_DIR=src
OBJ_DIR=obj
BIN_DIR=bin

SERVER_SOURCES=$(wildcard $(SRC_DIR)/server/*.c)
CLIENT_SOURCES=$(wildcard $(SRC_DIR)/client/*.c)
SHARED_SOURCES=$(filter-out $(wildcard $(SRC_DIR)/shared/*_test.c), $(wildcard $(SRC_DIR)/shared/*.c))
TEST_SOURCES=$(wildcard $(SRC_DIR)/shared/*_test.c)

SERVER_OBJECTS=$(SERVER_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TEST_BINS=$(TEST_SOURCES:$(SRC_DIR)/shared/%_test.c=$(BIN_DIR)/%_test)

SERVER_OUTPUT=$(BIN_DIR)/socks5d
CLIENT_OUTPUT=$(BIN_DIR)/client

all: $(SERVER_OUTPUT) $(CLIENT_OUTPUT)

$(SERVER_OUTPUT): $(SERVER_OBJECTS) $(SHARED_OBJECTS) | $(BIN_DIR)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $^ -o $@

$(CLIENT_OUTPUT): $(CLIENT_OBJECTS) $(SHARED_OBJECTS) | $(BIN_DIR)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $^ -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	mkdir -p $(dir $@)
	$(COMPILER) $(COMPILER_FLAGS) -I$(SRC_DIR)/shared -c $< -o $@

$(BIN_DIR)/%_test: $(SRC_DIR)/shared/%_test.c $(SHARED_OBJECTS) | $(BIN_DIR)
	$(COMPILER) $(COMPILER_FLAGS) -I$(SRC_DIR)/shared $^ -o $@

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "=== $$t ==="; ./$$t; done

sanitize: COMPILER_FLAGS+=-fsanitize=address,undefined
sanitize: all

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)

.PHONY: all test sanitize clean
