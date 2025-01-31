//write/read 48 words
#include "enclave_body_1024.S"
//write/read 48 words
#include "enclave_body_1024_last.S"
#go back to start of data section
CincoffsetImm c31, c31, -0x180 //4 x 48 x 2 = 384, 180 hex (c0 x2)

