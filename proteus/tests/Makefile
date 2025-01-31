TESTS_DIR = $(abspath .)
BASE_DIR = $(abspath $(TESTS_DIR)/..)
RISCV_TESTS_DIR = $(TESTS_DIR)/riscv-tests
ISA_TESTS_DIR = $(RISCV_TESTS_DIR)/isa
BUILD_DIR = $(TESTS_DIR)/build
SIM_DIR = $(BASE_DIR)/sim
SIM_EXE = $(SIM_DIR)/build/sim
CORE ?= riscv.CoreExtMem
BUILD_CORE ?= 1

#RISCV_PREFIX ?= riscv64-unknown-elf
#changed this from 64bit to 32bit for Proteus
RISCV_PREFIX = riscv32-unknown-elf
CC = $(RISCV_PREFIX)-gcc
LD = $(RISCV_PREFIX)-gcc
OBJCOPY = $(RISCV_PREFIX)-objcopy
ARCHFLAGS ?= -march=rv32imzicsr -mabi=ilp32
CFLAGS = $(ARCHFLAGS)

ifeq ($(BUILD_CORE),1)
FORCE = FORCE
else
FORCE =
endif

#To add custom tests, in a terminal set CUSTOM_TESTS_DIR
#e.g to Add the cheriEncrypt tests, in terminal type: 
#export CUSTOM_TESTS_DIR=/<path>/ProteusCore/ProteusCore/src/main/scala/riscv/plugins/cheriEncrypt/tests
#echo $CUSTOM_TESTS_DIR

-include $(CUSTOM_TESTS_DIR)/Makefile.include

#1a. For all tests use line below:
#TEST_DIRS ?= $(ISA_TESTS_DIR)/rv32ui $(ISA_TESTS_DIR)/rv32mi $(ISA_TESTS_DIR)/rv32um $(CUSTOM_TESTS_DIR) $(EXTRA_TEST_DIRS)

#1b. or For custom tests only use line below:
TEST_DIRS ?= $(CUSTOM_TESTS_DIR)

#2a. To run all tests in the directory use line below:
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '*.S')

#2b. or To run a specific test in the directory, name the file as per below:
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'permsEncrypt.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_CSealEncrypt.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_sealAndInvoke.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_sealAndInvoke_data_outsidewrite.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_sealAndInvoke_jump.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_sealAndInvoke_data_write.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_sealAndInvoke_withoutEncrypt.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_sealAndInvoke_data_write_2ndBatch.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_sealAndInvoke_data_read_2ndBatch.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_sealAndInvoke_code_2Batches.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_sealAndInvoke_code_2Batches_jump.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_sealAndInvoke_code_5Batches.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_sealAndInvoke_code_5Batches_jump.S')


#2c. or run a set of tests with 32 byte batch size
#Note set core.scala to 32 byte batch size and buffer size to 8, set core mem size to at least 256 KiB
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_*.S')

#3. exception tests 
# !Warning - these tests cause hardware exceptions and the simulations will run forever unless stopped manually.
# check TrapHandler_exceptionSignals_trapCause[3:0] in simulations, 0A for a CHERI exception
# and CEXC_CAUSE[4:0] for specific cause
# set core mem size to at least 256 KiB
#export CUSTOM_TESTS_DIR=/<path>/ProteusCore/ProteusCore/src/main/scala/riscv/plugins/cheriEncrypt/tests/hardwareExceptions
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'X_*')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'X_EncCapLenViolationa_32_CSealEncrypt.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'X_EncCapLenViolationb_32_CSealEncrypt.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'X_EncKeyTableViolation_32_CSealEncrypt.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'X_PermitEncryptionViolation_32_sealAndInvoke.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'X_EncTagViolation_32_sealAndInvoke.S')

#4. benchmark tests 
# set core mem size to at least 256 KiB
#export CUSTOM_TESTS_DIR=/<path>/ProteusCore/ProteusCore/src/main/scala/riscv/plugins/cheriEncrypt/tests/benchmark
#32 byte batch size
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'sealBenchmark1_*.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'invokeBenchmark1_*.S')
#64 byte batch size
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'sealBenchmark2_*.S')
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'invokeBenchmark2_64.S')
#128 byte batch size
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'invokeBenchmark2_128.S')
#128 byte batch size
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'sealBenchmark3_*.S')
#256 byte batch size
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'sealBenchmark4_*.S')

#5. large enclaves
#export CUSTOM_TESTS_DIR=/<path>/ProteusCore/ProteusCore/src/main/scala/riscv/plugins/cheriEncrypt/tests/large_enclaves
#batch size variable
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'testmultibatch_128.S')


UNSUPPORTED_TESTS = %fence_i.S %breakpoint.S
ALL_TESTS = $(filter-out $(UNSUPPORTED_TESTS),$(ALL_ISA_TESTS))
ALL_TARGETS = $(addsuffix .pass,$(basename $(addprefix $(BUILD_DIR)/,$(notdir $(ALL_TESTS)))))


all: $(ALL_TARGETS)

.SECONDARY:

VPATH = $(TEST_DIRS)

$(BUILD_DIR)/%.o: %.S
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(TESTS_DIR) -I$(ISA_TESTS_DIR)/macros/scalar -c -o $@ $^

%.elf: %.o
	$(LD) $(ARCHFLAGS) -ffreestanding -nostdlib -T tests.ld -o $@ $^

%.bin: %.elf
	$(OBJCOPY) -O binary $^ $@

$(SIM_EXE): $(FORCE)
	make -C $(SIM_DIR) CORE=$(CORE)

.PHONY: FORCE

%.pass: %.bin $(SIM_EXE)
	cd $(BASE_DIR); $(SIM_EXE) $<
	touch $@
