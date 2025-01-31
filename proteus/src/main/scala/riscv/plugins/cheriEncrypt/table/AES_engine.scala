package riscv.plugins.cheriEncrypt.table
import spinal.core._
import spinal.lib._
//import spinal.crypto.symmetric.aes._
//import spinal.crypto.symmetric.{SymmetricCryptoBlockCmd, SymmetricCryptoBlockConfig, SymmetricCryptoBlockIO}
//import spinal.crypto.devtype._
//import spinal.crypto._
import spinal.core.{BitCount, Component}
import spinal.lib.fsm.{EntryPoint, State, StateMachine, StateParallelFsm}

class AES_engine(dataWidth: BitCount) extends Component {

  val io = new Bundle {
    val Din, Key = in Bits (128 bits)
    val Drdy, Krdy, EN = in Bool ()
    val Dout = out Bits (128 bits)
    val BSY, Dvld = out Bool ()
  }

  val AES_ENC = new AESCore_Std(dataWidth)

  /** define inputs/outputs registers to AES */
  val Drg: Bits = Reg(Bits(dataWidth)) init (0)
  val Krg: Bits = Reg(Bits(dataWidth)) init (0)
  val KrgX: Bits = Reg(Bits(dataWidth)) init (0)
  val Rrg: Bits = Reg(Bits(10 bits)) init (1)
  val RrgCnt: UInt = Reg(UInt(4 bits)) init (0)
  val Dvldrg: Bool = Reg(Bool()) init (False)
  val BSYrg: Bool = Reg(Bool()) init (False)
  val Dvldrg1: Bool = Reg(Bool()) init (False)

  val Dnext = Bits(dataWidth)
  val Knext = Bits(dataWidth)

  when(io.EN === True) {
    when(BSYrg === False) {
      when(io.Krdy === True) {
        Krg := io.Key
        KrgX := io.Key
        Dvldrg := False
        Dvldrg1 := False
      } elsewhen (io.Drdy === True) {
        Rrg := Rrg(8 downto 0) ## Rrg(9)
        RrgCnt := RrgCnt + 1
        KrgX := Knext
        Drg := io.Din ^ Krg
        Dvldrg := False
        Dvldrg1 := False
        BSYrg := True
      } elsewhen (Dvldrg === True) {
        Dvldrg1 := False
      }
    } elsewhen (BSYrg === True) {
      Drg := Dnext
      when(Rrg(0) === True) {
        KrgX := Krg
        Dvldrg := True
        Dvldrg1 := True
        BSYrg := False
        RrgCnt := 0
      } otherwise {
        Rrg := Rrg(8 downto 0) ## Rrg(9)
        RrgCnt := RrgCnt + 1
        KrgX := Knext
      }
    }
  }

  AES_ENC.io.di := Drg
  AES_ENC.io.ki := KrgX
  AES_ENC.io.Rrg := Rrg
  AES_ENC.io.RrgCnt := RrgCnt
  Dnext := AES_ENC.io.do_data
  Knext := AES_ENC.io.ko

  io.Dvld := Dvldrg1
  io.Dout := Drg
  io.BSY := BSYrg
}

//object AESengine_verilog {
//def main(args: Array[String]) {
//SpinalVerilog(new AES_engine(dataWidth = 128 bits))
//}
//}
