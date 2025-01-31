package riscv.plugins.cheriEncrypt

import spinal.core._

/** This defines the op codes for the two new instructions CSealEncrypt and CInvokeEncrypt */

/** For R type, opcode format is: */
/** [31:25] funct7 [24:20] rs2 [19:15] rs1 [14:12] funct3 [11:7] rd [6:0] opcode */
/** The funct7 and funct3 fields select the type of operation */
/** most of the cheri instructions use opcode 1011011 (custom_2/rv128) which is reserved for custom
  * instructions
  */
/** together with a range of funct7 and funct3 */
/** funct3 is mostly used for decoding immediate instructions */
/** when rs2 is not used the code uses rs2field as well */
/** for two inputs and no cd output, such as for CInvokeEncrypt, the cd field forms part of the
  * instruction encoding
  */
object Opcodes {

  /** chosen code (03hex for funct7 field) not used anywhere else */
  /** defined in llvm-cheri as def CSealEncrypt : Cheri_rr<0x3, "csealencrypt", GPCR, GPCR, GPCR>;
    */
  val CSealEncrypt = M"0000011----------000-----1011011"

  /** chosen code (02hex for cd field) not used anywhere else */
  /** defined in llvm-cheri as def CInvokeEncrypt : RVInstCheriTwoSrc<0x7e, 0x2, 0, OPC_CHERI,
    * (outs),
    */
  /** (ins GPCR:$rs1, GPCR:$rs2), "cinvokeencrypt", "$rs1, $rs2">; */
  val CInvokeEncrypt = M"1111110----------000000101011011"
}
