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
	li t0, 0x02
        CSetOffset c29, ROOT, t0
        #set seal length to 1, and clear perms except seal
	li t0, 0x01
        CSetBoundsExact c29, c29, t0
        li t0, (1 << PERM_PERMIT_SEAL)
        CAndPerm c29, c29, t0

#ifdef PERFORM_ENCRYPT
       nop
       nop
       nop
#else
	# 4. clear encryption permission for code and data
	li t0, ~(1 << PERM_PERMIT_ENCRYPT)
        CAndPerm c1, c1, t0
	CAndPerm c2, c2, t0
#endif

	# 5. Seal and encrypt code and data , c3 and c4
	CSealEncrypt c3, c1, c29
	CSealEncrypt c4, c2, c29
	
	# 6. Set up return address in c6
        la t0, enclaveret
        CSetOffset c6, ROOT, t0

	# 7. Invoke, change domains, run enclave code
        CInvokeEncrypt c3, c4

enclaveret:
	#return from enclave here
	TEST_PASSFAIL

#enclave
#code
#align to 32 bytes
.balign 32
    capcode_mem_start:
	# 1. set the return address for when the enclave completes
	 Cmove cra, c6

	#2. Do jump routine
	li t5, 0x4
dosub:
	addi t5, t5, -1 
	beqz t5, 1f
	j dosub

	# 3. return from enclave
	 #clear data capability tag from register and return from enclave
1:	 CClearTag c31, c31
	 CJALR cra
    capcode_code_end:

    #allocate padding bytes space to make data size in whole batches (1 batch is 32 bytes)
    .fill 1, 4, 0x00
    capcode_pad_end:

    #allocate 32 bytes space for IV and authentication tag
       #.fill repeat , size , value
       #size in bytes
       .fill 8, 4, 0x00
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
