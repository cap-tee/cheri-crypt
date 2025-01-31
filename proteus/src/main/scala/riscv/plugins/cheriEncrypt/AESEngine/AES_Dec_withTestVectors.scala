package riscv.plugins.cheriEncrypt.AESEngine

import spinal.core.Component
import spinal.core._
//import spinal.crypto.symmetric.SymmetricCryptoBlockConfig
import spinal.lib.fsm.{EntryPoint, State, StateMachine}
import spinal.lib._

/** NIST test vectors for AES-CTR-GCM (counter mode for GCM) including GHASH algorithm encryption /
  * decryption
  */

class AES_Dec_withTestVectors extends Component {

  val io = new Bundle {
    val in_start = in Bool ()
    val out_valid = out Bool ()
    val out_data = out(Bits(128 bits))
    val out_dataValid = out Bool ()
    val out_tagValid = out Bool ()
    val out_passBlock = out Bool ()
    val out_passTag = out Bool ()
  }

  val crypto_core = new AES_Dec(dataWidth = 128 bits)
  val testVectors = new AES_Dec_TestVectors(dataWidth = 128 bits)
  // val testVectors = new AES_core_aadTestVectors(dataWidth = 128 bits)

  // set inputs
  testVectors.io.in_start := io.in_start
  crypto_core.io <> testVectors.io.io

  // testVectors.io.coreClk <> io.coreClk
  // testVectors.io.coreReset <> io.coreReset

  // set outouts
  io.out_data := crypto_core.io.rsp.payload.Out_data
  io.out_dataValid := crypto_core.io.rsp.data_vld
  io.out_passBlock := testVectors.io.out_passBlock
  io.out_tagValid := crypto_core.io.rsp.tag_vld
  io.out_passTag := testVectors.io.out_passTag
  io.out_valid := crypto_core.io.rsp.valid
}
