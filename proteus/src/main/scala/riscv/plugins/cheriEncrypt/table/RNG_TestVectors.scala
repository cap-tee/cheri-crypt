package riscv.plugins.cheriEncrypt.table
import spinal.core._
//import spinal.crypto.symmetric.SymmetricCryptoBlockConfig
import spinal.lib.fsm.{EntryPoint, State, StateMachine}
import spinal.lib._

class RNG_TestVectors(keyWidth: BitCount, oTypeWidth: UInt) extends Component {
  val config = KeyGenConfig(
    keyWidth = 128 bits,
    oTypeWidth = 12
  )

  val io = new Bundle {
    val in_start = in Bool ()
    val io = master(KeyGeneratorIO(config))
  }

  val otypeReg: UInt = Reg(UInt(12 bits)) init (0)
  // val RNG_validReg: Bool = Reg(Bool) init(False)

  val otypeValue1 = UInt(12 bits); otypeValue1 := U"hf01";
  // val otypeValue2 = UInt(64 bits);  otypeValue2 := U"f02";
  // val otypeValue3 = UInt(64 bits);  otypeValue3 := U"f03";
  // val otypeValue4 = UInt(64 bits);  otypeValue4 := U"f04";

  io.io.cmd.valid := False

  when(io.in_start) {
    otypeReg := otypeValue1
    io.io.cmd.valid := True
  }

  io.io.cmd.otype := otypeReg

}
