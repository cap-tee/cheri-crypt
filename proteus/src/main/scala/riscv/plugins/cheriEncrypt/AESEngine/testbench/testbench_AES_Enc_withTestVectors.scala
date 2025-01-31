package riscv.plugins.cheriEncrypt.AESEngine.testbench
import spinal.core._
import riscv.plugins.cheriEncrypt._
import AESEngine.{AES_Enc_withTestVectors, AES_Enc_TestVectors, AES_Enc, AES_engine, gfm128_16}

// simulation libraries needed for testbench
import spinal.sim._
import spinal.core.sim._

object testbench_AES_Enc_withTestVectors {

  def main(args: Array[String]): Unit = {
    SimConfig.withWave
      .compile(new AES_Enc_withTestVectors())
      .doSim("testbench_AES_Enc_TestVectors") {
        // SimConfig.withWave.compile(new AESgcm_GHASH_withFIFOTestVectors()).doSim("testbench_AESgcm_GHASH_withFIFOTestVectors") {
        dut =>
          // dut.clk := dut.io.coreClk
          dut.io.in_start #= false
          // create clock
          dut.clockDomain.forkStimulus(10)
          // dut.io.coreReset #= true
          dut.clockDomain.assertReset()
          sleep(80)
          // dut.io.coreReset #= false
          dut.clockDomain.deassertReset()
          sleep(100)
          // dut.io.coreReset #= true
          sleep(5) // JTD changed here for better sync input
          // init to start
          dut.io.in_start #= true
          // wait for long time
          sleep(350)
          dut.io.in_start #= false
          // wait for long time
          sleep(20000)

      }
  }
}
