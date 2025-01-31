#ifndef TEST_MACROS_CAPENCRYPT_H
#define TEST_MACROS_CAPENCRYPT_H

#include "test_macros.h"

//comment this out to run large_enclaves tests without encryption
#define PERFORM_ENCRYPT

#define CHERI_CAUSE 0x0A
#define cause_field 0x3e0//extract cause field of xccsr reg
#define CAUSE_Permit_Encryption_Violation 0x1d
#define CAUSE_EncKeyTable_Violation 0x1e
#define CAUSE_EncCapLen_Violation 0x0b
#define CAUSE_EncTag_Violation 0x1f

//get timer to measure number of clock cycles - time value in rd
#define GET_CLK_CYCLES(rd) \
 4: rdcycleh s2; \
    rdcycle rd; \
    rdcycleh s3; \
    bne  s2, s3, 4b

#define SEAL_ENCRYPT(cd, cs, type) \
    li t0, type; \
    CSetOffset c29, ROOT, t0; \
    CSealEncrypt cd, cs, c29

#define SEAL_ROOT_ENCRYPT(cd, type) SEAL_ENCRYPT(cd, ROOT, type)

#endif
