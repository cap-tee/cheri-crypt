#Hardware exception testing
#Exception: EncCapLenViolation
#What Test: tests the second CSealEncrypt.scala EncCapLenViolation: checks tagAddrReg = dataAddrReg + batch length. 
#Set up: 32 byte batch size, 8 depth fifo, see cheriEncrypt/core.scala, Key table with 3 slots
#Test scenario: CSealEncrypt with 1 batch of data and no allocation for AT/IV

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
        #ToDo - set seal length to 1, and clear perms except seal
        li t0, 0x01
        CSetBoundsExact c29, c29, t0
        li t0, (1 << PERM_PERMIT_SEAL)
        CAndPerm c29, c29, t0

	#do a CSealEncrypt with encryption
        CSealEncrypt c4, c1, c29
	j fail

# 8. hardware exception if get to here!
trap_vec:
        #check is CHERI cause
        csrr tp, mcause
	li t6, CHERI_CAUSE
        bne tp, t6, fail
	#check reason is CEncCapLen Violation
        csrr tp, mccsr
        li t6, cause_field
        and tp, tp, t6
        li t6, (CAUSE_EncCapLen_Violation << 5)
	bne tp, t6, fail

	TEST_PASSFAIL

#align to 32 bytes (8 x 4 / 32) = 1 batches of data no allocation for AT/IV
.balign 32
    cap_mem_start:
       #.fill repeat , size , value
       #size in bytes
        .fill 8, 4, 0x22
    cap_mem_end:

RVTEST_CODE_END
