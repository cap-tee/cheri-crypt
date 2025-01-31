#16 instructions = 64 bytes

#write 1st
 add t1, t1, 0x1
 sw.cap t1, (c31)
#read
 lw.cap t2, (c31)
1: bne t2, t1, 2f 

#write 2nd word
 CincoffsetImm c31, c31, 0x04
 add t1, t1, 0x1
 sw.cap t1, (c31)
#read
 lw.cap t2, (c31)
 bne t2, t1, 2f

#write 3rd word
 CincoffsetImm c31, c31, 0x04
 add t1, t1, 0x1
 sw.cap t1, (c31)
#read
 lw.cap t2, (c31)
2: bne t2, t1, 1f

#prepare next 
 CincoffsetImm c31, c31, 0x04
 NOP

