#include "riscv_test.h"
#include "test_macros_cap.h"
# see plugins/cheri/tests for cheriEncrypt.h 
# also see plugins/cheri/tests for permsEncrypt.S to test the permissions bit
#include "cheriEncrypt.h"

RVTEST_RV32U
RVTEST_CODE_BEGIN

    INIT_ROOT_CAP
    
    TEST_CASE_START(1)
        # Set up capability to be encrypted in c1
        la t0, cap_mem_start
        CSetAddr c1, ROOT, t0
        la t1, cap_mem_end
        sub t0, t1, t0 # Length
        CSetBoundsExact c1, c1, t0

	#store 1st 4 data
        li t0, 0xaa
        sw.cap t0, 0(c1)

        li t0, 0x04
        CSetOffset c1, c1, t0
        li t0, 0xab
        sw.cap t0, 0(c1)

        li t0, 0x08
        CSetOffset c1, c1, t0
        li t0, 0xac
        sw.cap t0, 0(c1)

        li t0, 0x0c
        CSetOffset c1, c1, t0
        li t0, 0xad
        sw.cap t0, 0(c1)

        #store 80th value (80x4-4)
        li t0, 0x13c
        CSetOffset c1, c1, t0
        li t0, 0xae
        sw.cap t0, 0(c1)

	#load first 4 data
        li t0, 0x00
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)
        li t0, 0xaa
	bne t1, t0, fail;

        li t0, 0x04
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)
        li t0, 0xab
	bne t1, t0, fail;

        li t0, 0x08
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)
        li t0, 0xac
	bne t1, t0, fail;

        li t0, 0x0c
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)
        li t0, 0xad
	bne t1, t0, fail;

        #load 80th value (80x4-4)
        li t0, 0x13c
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)
        li t0, 0xae
	bne t1, t0, fail;

	#reset offset
        li t0, 0x00
        CSetOffset c1, c1, t0


	#set up o-type seal in c29
	li t0, 0x02
        CSetOffset c29, ROOT, t0
        #ToDo - set seal length to 1, and clear perms except seal
        li t0, 0x01
        CSetBoundsExact c29, c29, t0
        li t0, (1 << PERM_PERMIT_SEAL)
        CAndPerm c29, c29, t0

 	#first do a normal CSeal
        CSeal c2, c1, c29

        #then do a normal seal with CSealEncrypt to compare
        li t0, ~(1 << PERM_PERMIT_ENCRYPT)
        CAndPerm c2, c1, t0
        CSealEncrypt c3, c2, c29

	#then do a CSealEncrypt with encryption
        CSealEncrypt c4, c1, c29

       #c4 is sealed but c1 is not, so use c1 to check the memory contents for encryption
	#register contents should be different, fail if they are the same
        #load first 4 data
        li t0, 0x00
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)
        li t0, 0xaa
	beq t1, t0, fail;

        li t0, 0x04
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)
        li t0, 0xab
	beq t1, t0, fail;

        li t0, 0x08
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)
        li t0, 0xac
	beq t1, t0, fail;

        li t0, 0x0c
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)
        li t0, 0xad
	beq t1, t0, fail;

        #load 77th value (80x4-16)
        li t0, 0x130
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)

        #load 78th value (80x4-12)
        li t0, 0x134
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)

        #load 79th value (80x4-8)
        li t0, 0x138
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)

        #load 80th value (80x4-4)
        li t0, 0x13c
        CSetOffset c1, c1, t0
        lw.cap t1, 0(c1)
        li t0, 0xae
	beq t1, t0, fail;

	#reset offset
        li t0, 0x00
        CSetOffset c1, c1, t0


        # Check if c3 contains a sealed cap
        CGetSealed t0, c3
        beq t0, zero, fail

        # Check if c4 contains a sealed cap
        CGetSealed t0, c4
        beq t0, zero, fail

    TEST_PASSFAIL

#align to 32 bytes (80 x 4 / 32) = 10 batches of data
.balign 32
    cap_mem_start:
       #.fill repeat , size , value
       #size in bytes
        .fill 80, 4, 0x22
    cap_mem_end:

RVTEST_CODE_END
