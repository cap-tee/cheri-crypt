#include "riscv_test.h"
#include "test_macros_cap.h"
# see plugins/cheri/tests for cheriEncrypt.h 
# also see plugins/cheri/tests for permsEncrypt.S to test the permissions bit
#include "cheriEncrypt.h"

RVTEST_RV32U
RVTEST_CODE_BEGIN

    INIT_ROOT_CAP

    TEST_CASE_START(1)
	# 1. Set up first code capability to be sealed in c1
        la t0, capcode_mem_start
	CSetAddr c1, ROOT, t0
        la t1, capcode_mem_end
        sub t0, t1, t0 # Length
        CSetBoundsExact c1, c1, t0

	# 2. Set up second data capability to be sealed in c2
	la t0, capdata_mem_start
	CSetAddr c2, ROOT, t0
        la t1, capdata_mem_end
        sub t0, t1, t0 # Length
        CSetBoundsExact c2, c2, t0
	#clear execute permissions for invoke to work
        li t0, ~(1 << PERM_PERMIT_EXECUTE)
        CAndPerm c2, c2, t0

	# 3. Set up third data capability outside enclave in c5
	la t0, outside_mem_start
	CSetAddr c5, ROOT, t0
        la t1, outside_mem_end
        sub t0, t1, t0 # Length
        CSetBoundsExact c5, c5, t0

	# 4. Set up o-type seal in c29
	li t1, 0x04
        CSetOffset c29, ROOT, t1

	# 5. Set code and data to be encrypted

	# 6. Seal and encrypt code and data , c3 and c4
	CSealEncrypt c3, c1, c29
	CSealEncrypt c4, c2, c29
	
	# 7. Set up return address in c6 DOES THIS NEED TO BE FROM PCC, USE DIFF INSTRUCTION
        la t0, enclaveret
        CSetOffset c6, ROOT, t0

#do invoke 10 times
        li t5, 0xa
dosub:
	# 8. Invoke, change domains, run enclave code
        CInvokeEncrypt c3, c4
enclaveret:
	addi t5, t5, -1 
	beqz t5, 1f
	j dosub

1:
	TEST_PASSFAIL

#Change batch size to 64bytes
#encryption length of batch is 4 x 16 bytes(128bits) = 64 bytes 
#each instruction is 4 bytes (8 x 4 = 32 bytes)
#this means we need to pad 32 bytes
#and leave room for 1 tag value and 1 IV value (32 bytes)
#code
#align to 64 bytes
.balign 64
    capcode_mem_start:
	# 1. set the return address for when the enclave completes
	 Cmove cra, c6

	# 2. read/write to the enclave data section c31
	#write first word using cap
	li t1, 0x44
	sw.cap t1, (c31)
	
	# 3. read/write to data outside the enclave
	#read first word using cap
	lw.cap t2, (c5) 
        #add 1 to it
	addi t2, t2, +1
	#write first word using cap
	sw.cap t2, (c5)

	# 4. return from enclave
	 #clear data capability tag from register and return from enclave
	 CClearTag c31, c31
	 CJALR cra
    capcode_code_end:

    #allocate padding bytes space to make data size in whole batches 
	#pad 32 bytes
       #.fill repeat , size , value
       .fill 8, 4, 0x00
    capcode_pad_end:

    #allocate 32 bytes space for IV and authentication tag
       #.fill repeat , size , value
       #size in bytes
       .fill 8, 4, 0x00
    capcode_mem_end:

RVTEST_CODE_END

#data
.data
RVTEST_DATA_BEGIN
    # 1 batches 16 * 4 = 64 bytes of data 
#align to 64 bytes
.balign 64
    capdata_mem_start:
       #.fill repeat , size , value
       #size in bytes
       .fill 16, 4, 0x22
    capdata_data_end:

    #allocate padding bytes space to make data size in whole batches (1 batch is 64 bytes)
    #NO PADDING NEEDED
    capdata_pad_end:

    #allocate 32 bytes space for 1 x IV and authentication tag
       #.fill repeat , size , value
       #size in bytes
       .fill 8, 4, 0x00
    capdata_mem_end:


    outside_mem_start:
       #.fill repeat , size , value
       #size in bytes
       .fill 16, 4, 0x66
   outside_mem_end:

RVTEST_DATA_END

#80000100 <capcode_mem_start>:
#80000100: db 00 a3 fe  	<unknown>
#80000104: 13 03 40 04  	addi	t1, zero, 68
#80000108: 5b 85 6f f8  	<unknown>
#8000010c: db 83 a2 fa  	<unknown>
#80000110: 93 83 13 00  	addi	t2, t2, 1
#80000114: 5b 85 72 f8  	<unknown>
#80000118: db 8f bf fe  	<unknown>
#8000011c: db 80 c0 fe  	<unknown>

#80000120 <capcode_code_end>:
#		...
#Disassembly of section .data:

#80000140 <capdata_mem_start>:
#80000140: 22 00        	<unknown>
#80000142: 00 00        	<unknown>
#80000144: 22 00        	<unknown>
#80000146: 00 00        	<unknown>
#80000148: 22 00        	<unknown>
#8000014a: 00 00        	<unknown>
#8000014c: 22 00        	<unknown>
#8000014e: 00 00        	<unknown>
#80000150: 22 00        	<unknown>
#80000152: 00 00        	<unknown>
#80000154: 22 00        	<unknown>
#80000156: 00 00        	<unknown>
#80000158: 22 00        	<unknown>
#8000015a: 00 00        	<unknown>
#8000015c: 22 00        	<unknown>
#8000015e: 00 00        	<unknown>
#80000160: 22 00        	<unknown>
#80000162: 00 00        	<unknown>
#80000164: 22 00        	<unknown>
#80000166: 00 00        	<unknown>
#80000168: 22 00        	<unknown>
#8000016a: 00 00        	<unknown>
#8000016c: 22 00        	<unknown>
#8000016e: 00 00        	<unknown>
#80000170: 22 00        	<unknown>
#80000172: 00 00        	<unknown>
#80000174: 22 00        	<unknown>
#80000176: 00 00        	<unknown>
#80000178: 22 00        	<unknown>
#8000017a: 00 00        	<unknown>
#8000017c: 22 00        	<unknown>
#8000017e: 00 00        	<unknown>

#80000180 <capdata_pad_end>:
#		...
#800001c0 <capdata_mem_end>:
#		...
#80000200 <outside_mem_start>:
#80000200: 66 00        	<unknown>
#80000202: 00 00        	<unknown>
#80000204: 66 00        	<unknown>
#80000206: 00 00        	<unknown>
#80000208: 66 00        	<unknown>
#8000020a: 00 00        	<unknown>
#8000020c: 66 00        	<unknown>





