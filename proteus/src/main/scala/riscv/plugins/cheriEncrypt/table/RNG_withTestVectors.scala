package riscv.plugins.cheriEncrypt.table

import spinal.core.Component
import spinal.core._
//import spinal.crypto.symmetric.SymmetricCryptoBlockConfig
import spinal.lib.fsm.{EntryPoint, State, StateMachine}
import spinal.lib._

class RNG_withTestVectors extends Component {
  val io = new Bundle {
    val in_start = in Bool ()
    val out_valid = out Bool ()
    val out_data = out(Bits(128 bits))
  }

  val RNG_core = new KeyGenerator(KeyGenConfig(keyWidth = 128 bits, oTypeWidth = 12))
  val testVectors = new RNG_TestVectors(keyWidth = 128 bits, oTypeWidth = 12)

  testVectors.io.in_start := io.in_start
  RNG_core.io <> testVectors.io.io

  io.out_valid := RNG_core.io.rsp.valid
  io.out_data := RNG_core.io.rsp.payload.key

}
