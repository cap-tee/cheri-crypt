package riscv.plugins.cheriEncrypt.table.testbench
//import toplevel component to test
import spinal.core._
import riscv.plugins.cheriEncrypt._
import table.{TableKeyGenTop, KeyGenConfig, TableConfig}

// simulation libraries needed for testbench
import spinal.sim._
import spinal.core.sim._

//TableKeyGenTop Testbench
object DutTableKeyGenTop {

  /** specify generic values */

  val keyGenConfig = new KeyGenConfig(keyWidth = BitCount(128), oTypeWidth = (12))
  val tableConfig = new TableConfig(
    keyWidth = BitCount(128),
    oTypeWidth = (12),
    IVWidth = BitCount(64),
    numTableEntries = 3
  )
  def main(args: Array[String]): Unit = {
    SimConfig.withWave
      .compile(new TableKeyGenTop(tableConfig, keyGenConfig))
      .doSim("TableKeyGenTop") { dut =>
        dut.io.cmd.genKey #= false
        dut.io.cmd.storeNextIVCount #= false
        dut.io.decrypt_error #= false
        // #= 0xFFF
        dut.io.cmd.payload.otype #= 0xfff // 18446744073709551615 for 64 bits, 4095 for 12 bits
        dut.io.cmd.valid #= false
        dut.io.cmd.getKey #= false
        // create clock
        dut.clockDomain.forkStimulus(10)
        // wait for after reset goes low
        dut.clockDomain.waitSampling()
        // let sim run for nano seconds
        sleep(5)
        // start
        dut.io.cmd.genKey #= true
        dut.io.cmd.payload.otype #= 0x02
        dut.io.cmd.valid #= true
        sleep(10)
        // stop
        dut.io.cmd.genKey #= false
        dut.io.cmd.payload.otype #= 0xfff
        dut.io.cmd.valid #= false
        sleep(200)
        // start
        dut.io.cmd.genKey #= true
        dut.io.cmd.payload.otype #= 0x04
        dut.io.cmd.valid #= true
        sleep(10)
        // stop
        dut.io.cmd.genKey #= false
        dut.io.cmd.payload.otype #= 0xfff
        dut.io.cmd.valid #= false
        sleep(200)
        // start
        dut.io.cmd.genKey #= true
        dut.io.cmd.payload.otype #= 0x05
        dut.io.cmd.valid #= true
        sleep(10)
        // stop
        dut.io.cmd.genKey #= false
        dut.io.cmd.payload.otype #= 0xfff
        dut.io.cmd.valid #= false
        sleep(200)
        // start
        dut.io.cmd.genKey #= true
        dut.io.cmd.payload.otype #= 0x06
        dut.io.cmd.valid #= true
        sleep(10)
        // stop
        dut.io.cmd.genKey #= false
        dut.io.cmd.payload.otype #= 0xfff
        dut.io.cmd.valid #= false
        // let sim run for no. of cycles
        sleep(200)

        // gen key with an existing otype for the 2nd time
        // start
        dut.io.cmd.genKey #= true
        dut.io.cmd.payload.otype #= 0x05
        dut.io.cmd.valid #= true
        sleep(10)
        // stop
        dut.io.cmd.genKey #= false
        dut.io.cmd.payload.otype #= 0xfff
        dut.io.cmd.valid #= false
        sleep(200)
        // ask for key with an existing otype for the first time
        dut.io.cmd.getKey #= true
        dut.io.cmd.payload.otype #= 0x05
        dut.io.cmd.valid #= true
        sleep(10)
        // stop
        dut.io.cmd.getKey #= false
        dut.io.cmd.payload.otype #= 0xfff
        dut.io.cmd.valid #= false
        sleep(40)
        // todo add decrypt_error test here
        dut.io.decrypt_error #= true
        sleep(10)
        dut.io.decrypt_error #= false
        sleep(100)
        // gen key with an existing otype for the 3rd time
        dut.io.cmd.genKey #= true
        dut.io.cmd.payload.otype #= 0x05
        dut.io.cmd.valid #= true
        sleep(10)
        // stop
        dut.io.cmd.genKey #= false
        dut.io.cmd.payload.otype #= 0xfff
        dut.io.cmd.valid #= false
        sleep(200)

        // ask for key with NO existing otype
        // start
        dut.io.cmd.getKey #= true
        dut.io.cmd.payload.otype #= 0xc
        dut.io.cmd.valid #= true
        sleep(10)
        // stop
        dut.io.cmd.getKey #= false
        dut.io.cmd.payload.otype #= 0xfff
        dut.io.cmd.valid #= false
        sleep(100)

        // store the NewNextIVCounter for an existing otype
        dut.io.cmd.payload.NewNextIVCount #= 0x58
        dut.io.cmd.payload.otype #= 0x05
        dut.io.cmd.storeNextIVCount #= true
        dut.io.cmd.valid #= true
        sleep(10)
        // stop
        dut.io.cmd.payload.otype #= 0xfff
        dut.io.cmd.storeNextIVCount #= false
        dut.io.cmd.valid #= false
        sleep(100)

        // todo add two more tests on 2nd August 2024
        // gen key with an existing otype for the 4th time (second new time)
        // check returns stored IV count value and existing key which is only used once
        dut.io.cmd.genKey #= true
        dut.io.cmd.payload.otype #= 0x05
        dut.io.cmd.valid #= true
        sleep(10)
        // stop
        dut.io.cmd.genKey #= false
        dut.io.cmd.payload.otype #= 0xfff
        dut.io.cmd.valid #= false
        sleep(200)

        // gen key with an existing otype for the 5th time (third new time)
        // check IV count value is reset and a new key is generated
        dut.io.cmd.genKey #= true
        dut.io.cmd.payload.otype #= 0x05
        dut.io.cmd.valid #= true
        sleep(10)
        // stop
        dut.io.cmd.genKey #= false
        dut.io.cmd.payload.otype #= 0xfff
        dut.io.cmd.valid #= false
        sleep(200)

        // store the NewNextIVCounter for no existing otype
        dut.io.cmd.payload.NewNextIVCount #= 0x58
        dut.io.cmd.payload.otype #= 0x0c
        dut.io.cmd.storeNextIVCount #= true
        dut.io.cmd.valid #= true
        sleep(10)
        // stop
        dut.io.cmd.payload.otype #= 0xfff
        dut.io.cmd.storeNextIVCount #= false
        dut.io.cmd.valid #= false
        // let sim run for no. of cycles
        sleep(100)
      }
  }
}
