include Makefile.inc

SRC_DIR=src
OBJ_DIR=obj
BIN_DIR=bin
TEST_DIR=test

SERVER_SOURCES=$(wildcard $(SRC_DIR)/server/*.c)
CLIENT_SOURCES=$(wildcard $(SRC_DIR)/client/*.c)
SHARED_SOURCES=$(wildcard $(SRC_DIR)/shared/*.c)
TEST_SOURCES=$(wildcard $(TEST_DIR)/*_test.c)

SERVER_OBJECTS=$(SERVER_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TEST_BINS=$(TEST_SOURCES:$(TEST_DIR)/%_test.c=$(BIN_DIR)/%_test)

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

# check (libcheck): use homebrew prefix if present, else system paths
CHECK_PREFIX=$(shell brew --prefix check 2>/dev/null)
CHECK_CFLAGS=$(if $(CHECK_PREFIX),-I$(CHECK_PREFIX)/include,)
CHECK_LIBS=$(if $(CHECK_PREFIX),-L$(CHECK_PREFIX)/lib -lcheck,-lcheck -lsubunit -lm)

# check.h relies on GNU extensions, so drop -Wpedantic/-Werror for tests.
TEST_COMPILER_FLAGS=$(filter-out -Wpedantic -Werror,$(COMPILER_FLAGS))

# Some test files #include the .c under test; for those, drop that object from
# the link to avoid duplicate symbols. Tests that include only the .h keep it.
$(BIN_DIR)/%_test: $(TEST_DIR)/%_test.c $(SHARED_OBJECTS) | $(BIN_DIR)
	$(COMPILER) $(TEST_COMPILER_FLAGS) -I$(SRC_DIR)/shared $(CHECK_CFLAGS) \
		$< $(if $(shell grep -l '#include "$*.c"' $<),$(filter-out $(OBJ_DIR)/shared/$*.o,$(SHARED_OBJECTS)),$(SHARED_OBJECTS)) \
		$(CHECK_LIBS) -o $@

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "=== $$t ==="; ./$$t; done

sanitize: COMPILER_FLAGS+=-fsanitize=address,undefined
sanitize: all

STRESS_DIR=$(TEST_DIR)/stress
STRESS_ECHO=$(BIN_DIR)/stress_echo
STRESS_CLIENT=$(BIN_DIR)/stress_client

$(STRESS_ECHO): $(STRESS_DIR)/echo_server.c | $(BIN_DIR)
	$(COMPILER) $(COMPILER_FLAGS) $< -o $@

$(STRESS_CLIENT): $(STRESS_DIR)/stress_client.c | $(BIN_DIR)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $< -o $@

stress: $(SERVER_OUTPUT) $(STRESS_ECHO) $(STRESS_CLIENT)
	$(STRESS_DIR)/run_stress.sh

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)

.PHONY: all test sanitize stress clean
