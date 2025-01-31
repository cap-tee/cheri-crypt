#Hardware exception testing
#Exception: PermitEncryptionViolation
#What Test: tests CInvokeEncrypt.scala PermitEncryptionViolation: checks both sealed capabilities has same encrypt permission before invoking.
#Set up: 32 byte batch size, 8 depth fifo, see cheriEncrypt/core.scala, Key table with 3 slots
#Test scenario: CsealEncrypt with one capability encrypted and one capability not encrypted.

# check TrapHandler_exceptionSignals_trapCause[3:0] in simulations, 0A for a CHERI exception
# and CEXC_CAUSE[4:0] for specific cause

#include "riscv_test.h"
#include "test_macros_cap.h"
# see plugins/cheri/tests for cheriEncrypt.h 
# also see plugins/cheri/tests for permsEncrypt.S to test the permissions bit
#include "cheriEncrypt.h"
#include "../test_macros_capEncrypt.h"


RVTEST_RV32U
RVTEST_CODE_BEGIN

    INIT_ROOT_CAP

    TEST_CASE_START(1)

	# 1. set up trap vector
        CSpecialR c1, pcc
        la t0, trap_vec
        CSetOffset c1, c1, t0
        CSetBoundsImm c1, c1, 16 * 4
        CSpecialW mtcc, c1

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

	# 3. Set up o-type seal in c29
	li t1, 0x04
        CSetOffset c29, ROOT, t1
        #set seal length to 1, and clear perms except seal
	li t1, 0x01
        CSetBoundsExact c29, c29, t1
        li t1, (1 << PERM_PERMIT_SEAL)
        CAndPerm c29, c29, t1

	# 4. Set code only to be not encrypted
	li t0, ~(1 << PERM_PERMIT_ENCRYPT)
        CAndPerm c1, c1, t0

	# 5. Seal and encrypt code and data , c3 and c4
	CSealEncrypt c3, c1, c29
	CSealEncrypt c4, c2, c29
	
	# 6. Set up return address in c6
        la t0, enclaveret
        CSetOffset c6, ROOT, t0

        CInvokeEncrypt c3, c4
enclaveret:
	j fail

# 8. hardware exception if get to here!
trap_vec:
        #check is CHERI cause
        csrr tp, mcause
	li t6, CHERI_CAUSE
        bne tp, t6, fail
	#check reason is encryption permission violation
        csrr tp, mccsr
        li t6, cause_field
        and tp, tp, t6
        li t6, (CAUSE_Permit_Encryption_Violation << 5)
	bne tp, t6, fail

	TEST_PASSFAIL


#enclave
#code
#align to 32 bytes
.balign 32
    capcode_mem_start:
	# 1. set the return address for when the enclave completes
	 Cmove cra, c6

	# do something with the data section c31
	#write first word using cap
	li t1, 0x44
	sw.cap t1, (c31)
	#read first word using cap
	lw.cap t2, (c31) 

	# 3. return from enclave
	 #clear data capability tag from register and return from enclave
	 CClearTag c31, c31
	 CJALR cra
capcode_code_end:

    #allocate padding bytes space to make data size in whole batches (1 batch is 32 bytes)
    .fill 2, 4, 0x00
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


