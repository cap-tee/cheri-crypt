package riscv.plugins.cheriEncrypt.AESEngine
import spinal.core._
import spinal.lib._
//import spinal.crypto.symmetric.aes._
//import spinal.crypto.symmetric.{SymmetricCryptoBlockCmd, SymmetricCryptoBlockConfig, SymmetricCryptoBlockIO}
//import spinal.crypto.devtype._
//import spinal.crypto._
import spinal.core.{BitCount, Component}
import spinal.lib.fsm.{EntryPoint, State, StateMachine}

/** take the AES-GCM as a blackbox, replaced by verilog files* */
class gfm128_16(dataWidth: BitCount) extends BlackBox {

  // val io = new Bundle {
  val v_in = in Bits (128 bits)
  val z_in = in Bits (128 bits)
  val b_in = in Bits (16 bits)
  val v_out = out Bits (128 bits)
  val z_out = out Bits (128 bits)

  /** Map the clk* */
  // mapCurrentClockDomain(clk)
  // mapCurrentClockDomain(rst)
  // mapClockDomain(clkDomain, io.clkA)
  /** Add all rtl dependencies* */
  addRTLPath("./rtl/gfm128_16.v")
}

object GHASHverilog {
  def main(args: Array[String]) {
    val report = SpinalVerilog(new gfm128_16(dataWidth = 128 bits))
    report.mergeRTLSource("ghash")
    // SpinalVerilog(new gcm_aes_v0)
  }
}
