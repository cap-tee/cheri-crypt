#Hardware exception testing
#Exception: EncKeyTableViolation
#Set up: 32 byte batch size, 8 depth fifo, see cheriEncrypt/core.scala, Key table with 3 slots
#test scenario: CSealEncrypt 4 (in pairs) times with different otypes, to create a key table violation with only 3 slots available

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

        # Set up capability to be encrypted in c1
        la t0, cap_mem_start
        CSetAddr c1, ROOT, t0
        la t1, cap_mem_end
        sub t0, t1, t0 # Length
        CSetBoundsExact c1, c1, t0

	#set up o-type seal in c29
	li t0, 0x02
        CSetOffset c29, ROOT, t0
        #ToDo - set seal length to 4, and clear perms except seal
        li t0, 0x04
        CSetBoundsExact c29, c29, t0
        li t0, (1 << PERM_PERMIT_SEAL)
        CAndPerm c29, c29, t0

	#do a CSealEncrypt with encryption
        CSealEncrypt c4, c1, c29
        CSealEncrypt c4, c1, c29

#do CSealEncrypt 3 more times to create a key table violation with only 3 slots available
        li t5, 0x3
dosub:
	CIncOffsetImm c29, c29, 0x1
        CSealEncrypt c4, c1, c29
        CSealEncrypt c4, c1, c29
enclaveret:
	addi t5, t5, -1 
	beqz t5, 1f
	j dosub
1:
	j fail

# 8. hardware exception if get to here!
trap_vec:
        #check is CHERI cause
        csrr tp, mcause
	li t6, CHERI_CAUSE
        bne tp, t6, fail
	#check reason is EncKeyTable Violation
        csrr tp, mccsr
        li t6, cause_field
        and tp, tp, t6
        li t6, (CAUSE_EncKeyTable_Violation << 5)
	bne tp, t6, fail

	TEST_PASSFAIL

#align to 32 bytes (16 x 4 / 32) = 1 batches of data with allocation for AT/IV
.balign 32
    cap_mem_start:
       #.fill repeat , size , value
       #size in bytes
        .fill 16, 4, 0x22
    cap_mem_end:

RVTEST_CODE_END
