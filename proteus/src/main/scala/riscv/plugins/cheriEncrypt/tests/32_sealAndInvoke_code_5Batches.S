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
	CSealEncrypt c3, c1, c29
	CSealEncrypt c4, c2, c29
	
	# 6. Set up return address in c6 DOES THIS NEED TO BE FROM PCC, USE DIFF INSTRUCTION
        la t0, enclaveret
        CSetOffset c6, ROOT, t0

#do invoke 10 times
        li t5, 0xa
dosub:
	# 7. Invoke, change domains, run enclave code
        CInvokeEncrypt c3, c4
enclaveret:
	addi t5, t5, -1 
	beqz t5, 1f
	j dosub

1:
	# 8. check if get same value back written to encrypted data memory
	bne t1, t2, fail;
	TEST_PASSFAIL


#enclave
#code length 5 batches
#align to 32 bytes
.balign 32
    capcode_mem_start:
	# 1. set the return address for when the enclave completes
	 Cmove cra, c6

	# 2a. write 1st word 
	li t1, 0x44
	sw.cap t1, (c31)

	# 2b. write 2nd word
	CincoffsetImm c31, c31, 0x04
	li t1, 0x45
	sw.cap t1, (c31)

	# 2c. write 3rd word
	CincoffsetImm c31, c31, 0x04
	li t1, 0x46
batch2:	sw.cap t1, (c31)

	# 2c. write 4th word
	CincoffsetImm c31, c31, 0x04
	li t1, 0x47
	sw.cap t1, (c31)

	# 2c. write 5th word
	CincoffsetImm c31, c31, 0x04
	li t1, 0x48
	sw.cap t1, (c31)

	# 2c. write 6th word
	CincoffsetImm c31, c31, 0x04
batch3:	li t1, 0x49
	sw.cap t1, (c31)

	# 2c. write 7th word
	CincoffsetImm c31, c31, 0x04
	li t1, 0x4a
	sw.cap t1, (c31)

	# 3a. read 1st word
	CincoffsetImm c31, c31, -0x18 
	lw.cap t2, (c31) 

	# 3b. read 2nd word
	CincoffsetImm c31, c31, 0x04 
batch4:	lw.cap t2, (c31) 

	# 3c. read 3rd word
	CincoffsetImm c31, c31, 0x04 
	lw.cap t2, (c31) 

	# 3d. read 4th word
	CincoffsetImm c31, c31, 0x04 
	lw.cap t2, (c31) 

	# 3e. read 5th word
	CincoffsetImm c31, c31, 0x04 
	lw.cap t2, (c31) 

	# 3e. read 6th word
	CincoffsetImm c31, c31, 0x04 
batch5:	lw.cap t2, (c31) 

	# 3e. read 7th word
	CincoffsetImm c31, c31, 0x04 
	lw.cap t2, (c31) 
	
	# 3. return from enclave
	 #clear data capability tag from register and return from enclave
	 CClearTag c31, c31
	 CJALR cra

capcode_code_end:

    #allocate padding bytes space to make data size in whole batches (1 batch is 32 bytes)
    .fill 3, 4, 0x00
    capcode_pad_end:

    #allocate 160 bytes space for 5 x IV and authentication tag
       #.fill repeat , size , value
       #size in bytes
       .fill 40, 4, 0x00
    capcode_mem_end:
RVTEST_CODE_END

#data
.data
#align to 32 bytes
.balign 32
RVTEST_DATA_BEGIN
#64 bytes 16 * 4   2 batches
    capdata_mem_start:
       #.fill repeat , size , value
       #size in bytes
       .fill 16, 4, 0x22
    capdata_data_end:

    #allocate padding bytes space to make data size in whole batches (1 batch is 32 bytes)
    #NO PADDING NEEDED
    capdata_pad_end:

    #allocate 64 bytes space for 2 x IV and authentication tag
       #.fill repeat , size , value
       #size in bytes
       .fill 16, 4, 0x00
    capdata_mem_end:
RVTEST_DATA_END


