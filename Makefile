include Makefile.inc

SRC_DIR=src
OBJ_DIR=obj
BIN_DIR=bin

# All .c files except entry points and tests
SHARED_SOURCES=$(filter-out $(SRC_DIR)/main.c $(SRC_DIR)/client.c $(wildcard $(SRC_DIR)/*_test.c), $(wildcard $(SRC_DIR)/*.c))
SHARED_OBJECTS=$(SHARED_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

TEST_SOURCES=$(wildcard $(SRC_DIR)/*_test.c)
TEST_BINS=$(TEST_SOURCES:$(SRC_DIR)/%_test.c=$(BIN_DIR)/%_test)

SERVER_OUTPUT=$(BIN_DIR)/socks5d
CLIENT_OUTPUT=$(BIN_DIR)/client

all: $(SERVER_OUTPUT) $(CLIENT_OUTPUT)

$(SERVER_OUTPUT): $(OBJ_DIR)/main.o $(SHARED_OBJECTS) | $(BIN_DIR)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $^ -o $@

$(CLIENT_OUTPUT): $(OBJ_DIR)/client.o $(SHARED_OBJECTS) | $(BIN_DIR)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $^ -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(COMPILER) $(COMPILER_FLAGS) -c $< -o $@

$(BIN_DIR)/%_test: $(SRC_DIR)/%_test.c $(SHARED_OBJECTS) | $(BIN_DIR)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $^ -o $@

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
