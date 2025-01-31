#16 inst = 64
# The data section is as follows:
# csp 
# enclave_data
# stack 

enclave_entry:

# 1. set the return address for when the enclave completes
     Cmove cra, c6

# 2. check data section size is what we think
     CGetLen t2, c31 # Data section length
     li t1, DATA_SEC
     bne t2, t1, 1f

     li t1, CSP_SIZE + DATA_SIZE + STACK_SIZE + PAD_SIZE
     bne t2, t1, 1f

# 3. Create stack
     li t1, CSP_SIZE + DATA_SIZE #lower stack bound
     li t2, STACK_SIZE # stack size
     CSetOffset csp, c31, t1 # set lower stack bound
     CSetBoundsExact csp, csp, t2 #set stack size
     CSetOffset csp, csp, t2 # set pointer to top of stack

# 4. Store stack pointer
     sc.cap csp, (c31)

# 5. Set upper data bound so doesn't go into stack and move to start of data section
     CSetBoundsExact c31, c31, t1 #set data size to lower stack bound
     li t1, CSP_SIZE #start
     Cincoffset c31, c31, t1 #move

# 6. set first data value to write to memory
     li t1, 0x34

