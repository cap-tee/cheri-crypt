# CHERI-Crypt tests

## Basic tests

These run basic instruction tests, in a terminal set CUSTOM_TESTS_DIR
```
export CUSTOM_TESTS_DIR=/home/<path>/proteus/src/main/scala/riscv/plugins/cheriEncrypt/tests
```
To run the tests (from top level project directory):
```
make -C tests
```
To view the simulation of the last test:
```
gtkwave sim.vcd
```
### 32 byte batch tests

Firstly set up the following: 32 byte batch size, 8 depth fifo (see `cheriEncrypt/core.scala`), Key table with 3 slots

To run all 32 byte batch tests, set in the make file as follows: 
```
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32*.S')
```
To run a single test, set exact name of test in the make file as follows:
```
#ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name '32_sealAndInvoke_data_write.S')
```
**Code section fit into one 32-byte batch:**

* **32_sealAndInvoke_withoutEncrypt.S** - *basic seal and invoke without encryption, but using the encryption instructions.*

* **32_CSealEncrypt.S** - *seal encryption of a single capability*

* **32_sealAndInvoke.S** - *basic seal with encryption and invoke. No data access*

* **32_sealAndInvoke_data_write.S** - *seal with encryption and invoke. Enclave single data write and read. Invoke repeated 10 times.*

* **32_sealAndInvoke_data_outsidewrite.S** - *seal with encryption and invoke. Enclave read and write outside encrypted enclave area. Invoke repeated 10 times.*

* **32_sealAndInvoke_jump.S** - *seal with encryption and invoke. Enclave code jump near end of code section to check prefetch and bounds. Invoke repeated 10 times.*

**Enclave with multiple 32-byte batches:**

* **32_sealAndInvoke_data_write_2ndBatch.S** - *enclave code writes to 1st and then 2nd data batch*

* **32_sealAndInvoke_data_read_2ndBatch.S** - *enclave code reads to 1st and then 2nd data batch*

* **32_sealAndInvoke_code_2Batches.S** - *enclave code consists of 2 Batches*

* **32_sealAndInvoke_code_2Batches_jump.S** - *enclave code consists of 2 Batches and includes a jump*

* **32_sealAndInvoke_code_5Batches.S** - *enclave code consists of 5 Batches - (assumes 4 cache lines to test cachelines being re-used)*

* **32_sealAndInvoke_code_5Batches_jump.S** - *enclave code consists of 5 Batches and a jump - (assumes 4 cache lines to test cachelines being re-used)*

## Hardware exception tests

These tests check the encryption exception violations work and cause a hardware exception.  Check the simulation for CEXC_CAUSE[4:0].
You can run the tests individually by adding custom tests, in a terminal set CUSTOM_TESTS_DIR
```
export CUSTOM_TESTS_DIR=/home/<path>/proteus/src/main/scala/riscv/plugins/cheriEncrypt/tests/hardwareExceptions
```

 and set in the make file as follows:
```
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'X_<test>.S')
```
Set up: 32 byte batch size, 8 depth fifo, see cheriEncrypt/core.scala, Key table with 3 slots

* **X_EncCapLenViolationa_32_CSealEncrypt.S** - *tests the first CSealEncrypt.scala EncCapLenViolation: check that cap length is at least 1 batch size + 1 tag + 1 IV. Test scenario: CSealEncrypt with 1 batch of data and no allocation for AT/IV*

* **X_EncCapLenViolationb_32_CSealEncrypt.S** - *tests the second CSealEncrypt.scala EncCapLenViolation: checks tagAddrReg = dataAddrReg + batch length. Test scenario: CSealEncrypt with 2 batches of data but only 1 allocation for AT/IV*

* **X_EncKeyTableViolation_32_CSealEncrypt.S** - *tests CSealEncrypt.scala EncKeyTableViolation: checks not run out of slots in key table. Test scenario: CSealEncrypt 4 (in pairs) times with different otypes, to create a key table violation with only 3 slots available.*

* **X_PermitEncryptionViolation_32_sealAndInvoke.S** - *tests CInvokeEncrypt.scala PermitEncryptionViolation: checks both sealed capabilities has same encrypt permission before invoking. Test Scenario: CsealEncrypt with one capability encrypted and one capability not encrypted.*

* **X_EncTagViolation_32_sealAndInvoke.S** - *tests CInvokeEncrypt.scala EncTagViolation: if an authentication tag (AT) error occurs during decryption a hardware exception occurs. Test scenario: After CsealEncrypt of two capabilities change the data in one capability through root access to mimic data being tampered with. During decrypt after CInvokeEncrypt, this will result in an AT error.*

## Benchmarking Tests

These tests run the benchmarking tests. In a terminal set CUSTOM_TESTS_DIR
```
export CUSTOM_TESTS_DIR=/home/<path>/proteus/src/main/scala/riscv/plugins/cheriEncrypt/tests/benchmark
```

 and set one of these in the make file as follows, depending upon batch size set:
```
#32 byte batch size
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'sealBenchmark1_*.S')
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'invokeBenchmark1_*.S')
#64 byte batch size
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'sealBenchmark2_*.S')
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'invokeBenchmark2_*.S')
#128 byte batch size
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'sealBenchmark3_*.S')
#256 byte batch size
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'sealBenchmark4_*.S')
```
## Large Enclave Tests

These tests asess performance of enclaves with a larger code base (128KiB/256KiB). Two types of computation scenario are considered:
* (1) a program containing repeated instructions to read and write data to a consecutive block of memory within the data section of the enclave.
* (2) a program containing repeated instruction sequences without accessing memory. 

In a terminal set CUSTOM_TESTS_DIR
```
export CUSTOM_TESTS_DIR=/home/<path>/proteus/src/main/scala/riscv/plugins/cheriEncrypt/tests/large_enclaves
```

 Set the batch size in `cheriEncrypt/Core.scala` and the `testmultibatch` file, and set one of these in the make file as follows, depending upon which scenario to run:
```
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'testmultibatch_128.S')
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'testmultibatch_128_nodata.S')
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'testmultibatch_256.S')
ALL_ISA_TESTS = $(shell find $(TEST_DIRS) -name 'testmultibatch_256_nodata.S')
```
To run the tests without encryption modify `test_macros_capEncrypt.h` as directed.