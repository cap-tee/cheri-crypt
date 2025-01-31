package riscv.plugins.cheriEncrypt.AESEngine

import spinal.core._
import spinal.lib._
import spinal.lib.fsm.{EntryPoint, State, StateMachine}

//import spinal.crypto.symmetric.{SymmetricCryptoBlockConfig, SymmetricCryptoBlockIO}
//import spinal.crypto.devtype._
//import spinal.crypto._
class AESCore_Std(keyWidth: BitCount) extends Component {

  assert(List(128, 192, 256).contains(keyWidth.value), "AES support only 128/192/256 keys width")

  val io = new Bundle {
    val di, ki = in Bits (128 bits)
    val Rrg = in Bits (10 bits)
    val RrgCnt = in UInt (4 bits)
    val do_data = out Bits (128 bits)
    val ko = out Bits (128 bits)
  }

  val sb = Bits(128 bits)
  val sr = Bits(128 bits)
  val mx = Bits(128 bits)
  val so = Bits(32 bits).noCombLoopCheck
  val koReg = Bits(128 bits).noCombLoopCheck

  // data vector of 128-bit, 32-bits
  val myVector = Vec(Bits(8 bits), 16)
  // val dataState = Reg(Vec(Bits(8 bits), 4))

  // create memory for the SBOX and RCON
  val sBoxMem = Mem(Bits(8 bits), AES.SubBytes.map(B(_, 8 bits)))
  val rconMem = Mem(Bits(8 bits), AES.rcon(keyWidth).map(B(_, 8 bits)))
  // subdivide the 128-bit data into 16 8-bit vectors
  myVector := io.di.subdivideIn(8 bits)

  val Sbox = new Area {
    sb(127 downto 120) := sBoxMem(myVector(15).asUInt)
    sb(119 downto 112) := sBoxMem(myVector(14).asUInt)
    sb(111 downto 104) := sBoxMem(myVector(13).asUInt)
    sb(103 downto 96) := sBoxMem(myVector(12).asUInt)
    sb(95 downto 88) := sBoxMem(myVector(11).asUInt)
    sb(87 downto 80) := sBoxMem(myVector(10).asUInt)
    sb(79 downto 72) := sBoxMem(myVector(9).asUInt)
    sb(71 downto 64) := sBoxMem(myVector(8).asUInt)
    sb(63 downto 56) := sBoxMem(myVector(7).asUInt)
    sb(55 downto 48) := sBoxMem(myVector(6).asUInt)
    sb(47 downto 40) := sBoxMem(myVector(5).asUInt)
    sb(39 downto 32) := sBoxMem(myVector(4).asUInt)
    sb(31 downto 24) := sBoxMem(myVector(3).asUInt)
    sb(23 downto 16) := sBoxMem(myVector(2).asUInt)
    sb(15 downto 8) := sBoxMem(myVector(1).asUInt)
    sb(7 downto 0) := sBoxMem(myVector(0).asUInt)
  }

  sr := sb(127 downto 120) ## sb(87 downto 80) ## sb(47 downto 40) ## sb(7 downto 0) ##
    sb(95 downto 88) ## sb(55 downto 48) ## sb(15 downto 8) ## sb(103 downto 96) ##
    sb(63 downto 56) ## sb(23 downto 16) ## sb(111 downto 104) ## sb(71 downto 64) ##
    sb(31 downto 24) ## sb(119 downto 112) ## sb(79 downto 72) ## sb(39 downto 32)

  val MixCol = new Area {
    mx(127 downto 96) := AES.MixColumns(sr(127 downto 96))
    mx(95 downto 64) := AES.MixColumns(sr(95 downto 64))
    mx(63 downto 32) := AES.MixColumns(sr(63 downto 32))
    mx(31 downto 0) := AES.MixColumns(sr(31 downto 0))
  }

  when(io.Rrg(0) === True) {
    io.do_data := sr ^ io.ki
  } otherwise {
    io.do_data := mx ^ io.ki
  }

  val newKey = new Area {
    so(31 downto 24) := sBoxMem(io.ki(23 downto 16).asUInt)
    so(23 downto 16) := sBoxMem(io.ki(15 downto 8).asUInt)
    so(15 downto 8) := sBoxMem(io.ki(7 downto 0).asUInt)
    so(7 downto 0) := sBoxMem(io.ki(31 downto 24).asUInt)

    koReg(127 downto 96) := io.ki(127 downto 96) ^ ((so(31 downto 24) ^ rconMem(io.RrgCnt)) ## so(
      23 downto 0
    ))
    koReg(95 downto 64) := io.ki(95 downto 64) ^ koReg(127 downto 96)
    koReg(63 downto 32) := io.ki(63 downto 32) ^ koReg(95 downto 64)
    koReg(31 downto 0) := io.ki(31 downto 0) ^ koReg(63 downto 32)

    io.ko := koReg

  }

  // val newKey = new Area {
  // keyWidth.value match {
  // case 128 =>

  // case _   => SpinalError(s"Only support 12-bit keysize at this stage")
  // }

  // io.ko := koReg
  // }

}

//object AESverilog {
//def main(args: Array[String]) {
//SpinalVerilog(new AESCore_Std(keyWidth = 128 bits))
//}
//}
