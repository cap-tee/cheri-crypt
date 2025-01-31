#16 instructions = 64 bytes

#add 1
 mv t2, t1
 add t1, t1, 0x1
 add t2, t2, 0x1
1: bne t2, t1, 2f 

#add 2
 add t1, t1, 0x1
 add t2, t2, 0x1
 add t1, t1, 0x1
 add t2, t2, 0x1
 bne t2, t1, 2f

#sub 2
 add t1, t1, -0x1
 add t2, t2, -0x1
 add t1, t1, -0x1
 add t2, t2, -0x1
2: bne t2, t1, 1f

#pad next 
 NOP
 NOP

