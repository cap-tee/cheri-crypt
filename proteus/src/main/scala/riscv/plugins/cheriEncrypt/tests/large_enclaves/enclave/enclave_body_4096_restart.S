//write/read 96 words
#include "enclave_body_2048.S"
//write/read 96 words
#include "enclave_body_2048_last.S"
#go back to start of data section
CincoffsetImm c31, c31, -0x300 //4 x 96 x 2 = 768, 300 hex


