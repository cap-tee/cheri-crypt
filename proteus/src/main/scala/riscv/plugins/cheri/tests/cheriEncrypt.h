#ifndef CHERIENCRYPT_H
#define CHERIENCRYPT_H

#include "riscv_test.h"
#include "cheri.h"
#include "test_macros.h"
#include "test_macros_cap.h"


//ENCRYPT - Add encrypt permission bit to tests
//when set no encryption, when unset encrypt
//#define PERM_PERMIT_NO_ENCRYPT 12
#define PERM_PERMIT_ENCRYPT 12

//ENCRYPT - Test macros
#define CHECK_PERMS_ENCRYPT_SET(cr) \
CGetPerm x30, cr; \
li  x29, (1 << PERM_PERMIT_ENCRYPT); \
and x28, x29, x30; \
beq x28, x29, 1f; \
RESTORE_SAFE_STATE; \
j fail; \
1:

#define CHECK_PERMS_ENCRYPT_UNSET(cr) \
CGetPerm x30, cr; \
li  x29, (1 << PERM_PERMIT_ENCRYPT); \
and x28, x29, x30; \
beq x28, zero, 1f; \
RESTORE_SAFE_STATE; \
j fail; \
1:

#endif
