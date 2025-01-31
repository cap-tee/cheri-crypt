package riscv.plugins.cheriEncrypt.AESEngine.testbench
import spinal.core._
import riscv.plugins.cheriEncrypt._
import AESEngine.{AES_Dec_withFIFOTestVectors, AES_Dec, AES_engine, gfm128_16}
// simulation libraries needed for testbench
import spinal.sim._
import spinal.core.sim._

object testbench_AES_Dec_withFIFOTestVectors {

  def main(args: Array[String]): Unit = {
    SimConfig.withWave
      .compile(new AES_Dec_withFIFOTestVectors())
      .doSim("testbench_AES_Dec_withFIFOTestVectors") {
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
          sleep(10)
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
