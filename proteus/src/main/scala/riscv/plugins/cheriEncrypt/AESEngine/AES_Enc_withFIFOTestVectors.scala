package riscv.plugins.cheriEncrypt.AESEngine
import spinal.core.Component
import spinal.core._
import spinal.core.BitCount
//import spinal.crypto.symmetric.SymmetricCryptoBlockConfig
import spinal.lib._
//import spinal.crypto.symmetric.aes._

class AES_Enc_withFIFOTestVectors() extends Component {
  val io = new Bundle {
    val in_start = in Bool ()
    val out_data = out(Bits(128 bits))
    val out_valid = out Bool ()
    val out_pass = out Bool ()
  }

  // create AES crypto block
  val crypto_core = new AES_Enc(128 bits)
  val testVectors = new AES_Enc_FIFOTestVectors_MultiEnc(128 bits)

  // set inputs
  testVectors.io.in_start := io.in_start
  testVectors.io.in_ready := crypto_core.io.cmd.ready

  // cmd output
  crypto_core.io.cmd.payload.block := testVectors.io.out_block
  crypto_core.io.cmd.payload.key := testVectors.io.out_key
  crypto_core.io.cmd.valid := testVectors.io.out_valid
  crypto_core.io.cmd.payload.vector_vld := testVectors.io.out_vector_vld
  crypto_core.io.cmd.payload.pt_vld := testVectors.io.out_pt_vld
  crypto_core.io.cmd.payload.aad_vld := testVectors.io.out_aad_vld
  crypto_core.io.cmd.payload.key_vld := testVectors.io.out_key_vld
  crypto_core.io.cmd.payload.last_word := testVectors.io.out_last_word
  crypto_core.io.data_size := testVectors.io.out_data_size

  // set outputs
  io.out_data := crypto_core.io.rsp.payload.Out_data
  io.out_valid := crypto_core.io.rsp.valid

  io.out_pass := testVectors.io.out_pass

  testVectors.io.in_aesoutput_data := crypto_core.io.rsp.payload.Out_data
  testVectors.io.in_aesoutput_dataValid := crypto_core.io.rsp.valid
  testVectors.io.in_data_vld := crypto_core.io.rsp.payload.data_vld
  testVectors.io.in_tag_vld := crypto_core.io.rsp.payload.tag_vld

}
