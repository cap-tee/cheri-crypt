#include "riscv_test.h"

#include "test_macros_cap.h"
#include "test_macros.h"
#include "cheri.h"
#include "cheriEncrypt.h"

RVTEST_RV32U
RVTEST_CODE_BEGIN

    INIT_ROOT_CAP


#----------------------------------
#ENCRYPT - Add tests to check encryption permission bit
#----------------------------------
    # Check can clear encrypt perms
    TEST_CASE_START(1)
        CHECK_PERMS_ENCRYPT_SET(ROOT)
        li t0, ~(1 << PERM_PERMIT_ENCRYPT)
        CAndPerm c1, ROOT, t0
        CHECK_PERMS_ENCRYPT_UNSET(c1)
#---------------------------------
    # Check encrypt perms is correctly set after sealing
    TEST_CASE_START(2)
        SEAL_ROOT(c1, 100)
        CHECK_PERMS_ENCRYPT_SET(c1)
        
    TEST_CASE_START(3)
        li t0, ~(1 << PERM_PERMIT_ENCRYPT)
        CAndPerm c1, ROOT, t0
        SEAL(c1, c1, 100)
        CHECK_PERMS_ENCRYPT_UNSET(c1)
#-----------------------------------------
    # Check unsealing a capability results in original capability including encrypt bit
    TEST_CASE_START(4)
        SEAL_ROOT(c1, 1234)
        li t0, 1234
        CSetOffset c2, ROOT, t0
        CUnseal c3, c1, c2
        CHECK_CAP_EQ(c3, ROOT)

    TEST_CASE_START(5)
        li t0, ~(1 << PERM_PERMIT_ENCRYPT)
        CAndPerm c1, ROOT, t0
        SEAL(c2, c1, 100)
        CHECK_PERMS_ENCRYPT_UNSET(c2)
        li t0, 100
        CSetOffset c3, ROOT, t0
        CUnseal c2, c2, c3
	CHECK_CAP_EQ(c2, c1)
#-----------------------------------------

    TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
