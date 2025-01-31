#include "riscv_test.h"
#include "test_macros_cap.h"
#include "../test_macros_capEncrypt.h"
# see plugins/cheri/tests for cheriEncrypt.h 
# also see plugins/cheri/tests for permsEncrypt.S to test the permissions bit
#include "cheriEncrypt.h"

//Test: fixed code size 256KiB (262144 bytes), vary batch size as required
//change the BATCH_SIZE, (can also change DATA_SEC, PAD_SIZE) of this file 
//must be power of two
//BATCH_SIZE can not be greater than code or data section size
//If you change the batch size here, you need to change the batch size of the hardware
//if using GTKwave, check s6 for software measured clk cycle latency.
//To run without encryption, see ../test_macros_capEncrypt.h
#define BATCH_SIZE 32

#define DATA_SEC 4096//set 1024 to 4096, this needs to be sum of four below
#define PAD_SIZE 3072 //0
//fixed - do not change
#define CSP_SIZE 16
#define DATA_SIZE 992//(992 -> 248 words max)
#define STACK_SIZE 16

//fixed - do not change
#define DATA_NUM_WORDS 		(CSP_SIZE + DATA_SIZE + STACK_SIZE)/4
#define PAD_NUM_WORDS           PAD_SIZE/4
#define TAG_DATA_SIZE 		32*DATA_SEC/BATCH_SIZE 
#define TAG_DATA_NUM_WORDS  	TAG_DATA_SIZE/4

//fixed - do not change
#define CODE_SEC 262144 
#define NUM_CODE_BATCHES CODE_SEC/BATCH_SIZE
#define TAG_CODE_NUM_WORDS 32*NUM_CODE_BATCHES/4

RVTEST_RV32U
RVTEST_CODE_BEGIN

    INIT_ROOT_CAP

    TEST_CASE_START(1)
	# 1. Set up first code capability to be sealed in c1
        la t0, capcode_mem_start
	CSetAddr c1, ROOT, t0
#ifdef PERFORM_ENCRYPT
        la t1, capcode_mem_end
#else
        la t1, capcode_pad_end
#endif
        sub t0, t1, t0 # Length
        CSetBoundsExact c1, c1, t0

	# 2. Set up second data capability to be sealed in c2
	la t0, capdata_mem_start
	CSetAddr c2, ROOT, t0
#ifdef PERFORM_ENCRYPT
        la t1, capdata_mem_end
#else
        la t1, capdata_pad_end
#endif
        sub t0, t1, t0 # Length
        CSetBoundsExact c2, c2, t0
	#clear execute permissions for invoke to work
        li t0, ~(1 << PERM_PERMIT_EXECUTE)
        CAndPerm c2, c2, t0

	# 3. Set up o-type seal in c29
	li t1, 0x04
        CSetOffset c29, ROOT, t1
        #set seal length to 1, and clear perms except seal
	li t1, 0x01
        CSetBoundsExact c29, c29, t1
        li t1, (1 << PERM_PERMIT_SEAL)
        CAndPerm c29, c29, t1

#ifdef PERFORM_ENCRYPT
#else
	# 4. clear encryption permission for code and data
	li t0, ~(1 << PERM_PERMIT_ENCRYPT)
        CAndPerm c1, c1, t0
	CAndPerm c2, c2, t0
#endif

	# 5. Seal and encrypt code and data , c3 and c4

        GET_CLK_CYCLES(s4)

	CSealEncrypt c3, c1, c29

	GET_CLK_CYCLES(s5)
	#clock cycles taken in s6
	sub s6, s5, s4

	GET_CLK_CYCLES(s4)

	CSealEncrypt c4, c2, c29

	GET_CLK_CYCLES(s5)
	#clock cycles taken in s6
	sub s6, s5, s4
	
	# 6. Set up return address in c6
        la t0, enclaveret
        CSetOffset c6, ROOT, t0

#do invoke 3 times
        li t5, 0x3
dosub:
	GET_CLK_CYCLES(s4)
	# 7. Invoke, change domains, run enclave code
        CInvokeEncrypt c3, c4

enclaveret:
	GET_CLK_CYCLES(s5)
	#clock cycles taken in s6
	sub s6, s5, s4
	
	addi t5, t5, -1 
	beqz t5, 1f
	j dosub

1:
	# 8. check if get LAST same value back written to encrypted data memory
	bne t1, t2, fail;
	TEST_PASSFAIL


#enclave
#code
#align to BATCH_SIZE bytes
#fixed enclave code size of 262144 bytes
.balign BATCH_SIZE
    capcode_mem_start:
        #include "enclave_nodata/enclave_entry_64.S" //
        enclave_body:
        #include "enclave_nodata/enclave_body_131072.S" //
        #include "enclave_nodata/enclave_body_65536.S" //
        #include "enclave_nodata/enclave_body_32768.S" //
        #include "enclave_nodata/enclave_body_16384.S" //
        #include "enclave_nodata/enclave_body_8192.S" //
        #include "enclave_nodata/enclave_body_4096.S" //
	#include "enclave_nodata/enclave_body_2048.S" //
	#include "enclave_nodata/enclave_body_1024.S" //
	#include "enclave_nodata/enclave_body_512.S" //
	#include "enclave_nodata/enclave_body_256.S" //
        #include "enclave_nodata/enclave_body_128.S" //

	#include "enclave_nodata/enclave_return_8.S" //
    capcode_code_end:

    #allocate padding bytes space to make data size in whole batches (1 batch is 32 bytes)
    .fill 14, 4, 0x00
    capcode_pad_end:

    #allocate batches at 32 bytes bytes space for IV and authentication tag (no.x32/4)
       #.fill repeat , size , value
       #size in bytes
        .fill TAG_CODE_NUM_WORDS, 4, 0x00
    capcode_mem_end:
RVTEST_CODE_END

#data
.data
#align to BATCH_SIZE bytes
.balign BATCH_SIZE
RVTEST_DATA_BEGIN
    capdata_mem_start:
       #.fill repeat , size , value
       #size in bytes
       .fill DATA_NUM_WORDS, 4, 0x22
    capdata_data_end:

    #allocate padding bytes space to make data size in whole batches (1 batch is 32 bytes)
    .fill PAD_NUM_WORDS, 4, 0x00
    capdata_pad_end:

    #allocate bytes space for IV and authentication tag
       #.fill repeat , size , value
       #size in bytes
       .fill TAG_DATA_NUM_WORDS, 4, 0x00
    capdata_mem_end:
RVTEST_DATA_END


