package riscv.plugins.cheriEncrypt.AESEngine.testbench

import spinal.core._
import spinal.core.sim._
import spinal.lib._
import scala.util.Random
import riscv.plugins.cheriEncrypt._
import AESEngine.SingleClockFifo

object FifoTestbench {
  def main(args: Array[String]): Unit = {
    // Configure the simulation
    SimConfig.withWave.compile(new SingleClockFifo(width = 8, depth = 5)).doSim { dut =>
      // Clock and reset generation
      dut.clockDomain.forkStimulus(period = 10)

      // Initial conditions
      dut.io.push.valid #= false
      dut.io.pop.ready #= false
      dut.clockDomain.waitSampling()

      // Push some data into the FIFO
      fork {
        for (i <- 0 until 10) {
          dut.io.push.valid #= true
          dut.io.push.payload #= i
          dut.clockDomain.waitSampling()
        }
        dut.io.push.valid #= false
      }

      // Wait a bit before popping data
      dut.clockDomain.waitSampling(5)

      // Pop data from the FIFO
      fork {
        dut.io.pop.ready #= true
        for (i <- 0 until 10) {
          dut.clockDomain.waitSampling()
          assert(dut.io.pop.valid.toBoolean, "Data should be available to pop")
          println(s"Received data: ${dut.io.pop.payload.toInt}")
        }
        dut.io.pop.ready #= false
      }

      // Run the simulation for a few more cycles to observe the FIFO behavior
      dut.clockDomain.waitSampling(20)
    }
  }
}
