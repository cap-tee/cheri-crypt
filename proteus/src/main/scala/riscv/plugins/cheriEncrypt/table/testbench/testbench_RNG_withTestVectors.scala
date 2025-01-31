package riscv.plugins.cheriEncrypt.table.testbench
import spinal.core._
import riscv.plugins.cheriEncrypt._
import table.{RNG_withTestVectors, RNG_TestVectors, AESCore_Std, AES_engine, KeyGenerator}

// simulation libraries needed for testbench
import spinal.sim._
import spinal.core.sim._

object testbench_RNG_withTestVectors {

  def main(args: Array[String]): Unit = {
    SimConfig.withWave.compile(new RNG_withTestVectors()).doSim("testbench_RNG_TestVectors") {
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
