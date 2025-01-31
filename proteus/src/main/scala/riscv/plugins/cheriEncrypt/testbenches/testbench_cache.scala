//import toplevel component to test

import riscv.plugins.cheriEncrypt.testbenches.cacheControl
import spinal.core._
import riscv.plugins.cheriEncrypt.{cache, cacheConfig}

// simulation libraries needed for testbench
import spinal.sim._
import spinal.core.sim._

//Testbench for cache, we use cache control here to generate registers on input
// to align simulation signals
//Main Scenarios to test: (resulting action not tested here because no state machine yet)
//1. Write to cache from processor and miss -> write to memory (if dirty bits), get from memory, then write data
//2. Write to cache from processor and hit -> flag dirty bit
//3. Read from cache by processor and hit -> get data
//4. Read from cache by processor and miss -> write to memory (if dirty bits), get data from memory to cache, then get data
//5. Write to cache, data from memory ->write to cache and clear dirty bit

//Setup:
//A. 5.reset dirty bit cache RAM
//B. 5.Write a word into cache as a baseline scenario as if retrieved from memory

//Actual tests here:
//3a. Read from cache by processor same word back out and hit (dirty bit not yet set)
//->output zero dirty bit and hit and data rsp

//2a. Write to cache from processor and hit (no dirty bit set already)
//-> write dirty bit, but doesn't yet show on output rsp, doesn't matter because hit
// if really need to know will have to do separate read.

//2b. Write to cache from processor and hit (dirty bit already set)
//-> dirty bit rsp as already set

//3b. Read from cache by processor and hit (with dirty bit set)
//->output dirty bit and hit rsp

//4b. Read from cache by processor and miss (dirty bit already set)
//->output dirty bit and miss rsp

// 1b. Write to cache from processor and miss (dirty bit already set)
// -> will output dirty bit and miss rsp
// manually check new data not written

// 4a.read one word from diff cache line to create a miss, (dirty bit not set yet)
//->output zero dirty bit and miss rsp
// 4b.followed by read one word from orig cache line to create a miss, (with dirty bit already set)
//->output dirty bit and miss rsp
// 4a.followed by read one word from diff cache line to create a miss,  (dirty bit not set yet)
//->output zero dirty bit and miss rsp

// 1a.write one word from diff cache line to create a miss, (with dirty bit not already set)
// ->so should not set dirty bit
// 1b.followed by write one word from orig cache line to create a miss, (with dirty bit set already)
// ->miss and dirty bit rsp
// 1a.followed by write one word from diff cache line to create a miss, (with dirty bit not already set)
// ->so should not set dirty bit

// memory write to reset the dirty bit

object Dutcache {

  /** specify generic values */

  val cacheConfig = new cacheConfig(
    addrWidth = 32 bits,
    dataWidth = 32 bits,
    maskWidth = 4 bits,
    sizeCacheLine = 16, // bytes
    numCacheLines = 4
  )
  def main(args: Array[String]): Unit = {
    SimConfig.withWave
      .compile(new cacheControl(cacheConfig))
      .doSim("cache") { dut =>
        dut.io.cmd.valid #= false
        dut.io.cmd.payload.address #= 0x0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        // create clock
        dut.clockDomain.forkStimulus(10)
        // wait for after reset goes low
        dut.clockDomain.waitSampling()
        // let sim run for nano seconds
        sleep(10)
        // set up test variables to check
        // expected variables
        var ex_rtag = 0
        var ex_rlineaddr = 0
        var ex_wbackaddr = 0
        var ex_procread = false
        var ex_hit = false
        var ex_rdirty = false
        var ex_valid = false
        var ex_rdata = 0
        // actual variables
        var ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        var ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        var ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        var ac_procread = dut.io.rsp.payload.procread.toBoolean
        var ac_hit = dut.io.rsp.payload.hit.toBoolean
        var ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        var ac_valid = dut.io.rsp.valid.toBoolean
        var ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        // A. reset dirty bit cache RAM
        // clear dirty bits from cache by doing a write from memory to all cache lines
        // this will also load the tag into the tag RAM
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0xa00 // 101000|00|00|00 = 28hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x00
        dut.io.cmd.payload.wmask #= 0xf
        dut.io.cmd.payload.memwrite #= true
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= true
        sleep(10)
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0xa10 // 101000|01|00|00 = 28hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x00
        dut.io.cmd.payload.wmask #= 0xf
        dut.io.cmd.payload.memwrite #= true
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= true
        sleep(10)
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0xa20 // 101000|10|01|00 = 28hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x00
        dut.io.cmd.payload.wmask #= 0xf
        dut.io.cmd.payload.memwrite #= true
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= true
        sleep(10)
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0xa30 // 101000|11|00|00 = 28hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x00
        dut.io.cmd.payload.wmask #= 0xf
        dut.io.cmd.payload.memwrite #= true
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= true
        sleep(10)

        // B. Write a word into cache as a baseline scenario as if retrieved from memory
        // write one word from memory
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0xa14 // 101000|01|01|00 = 28hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x08
        dut.io.cmd.payload.wmask #= 0xf
        dut.io.cmd.payload.memwrite #= true
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= true
        sleep(10)
        // stop
        dut.io.cmd.valid #= false
        dut.io.cmd.payload.address #= 0x0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(50)
        // 3a. Read from cache by processor same word back out and hit (dirty bit not yet set)
        // ->output zero dirty bit and hit and data rsp
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0xa14 // 101000|01|01|00 = 28hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // stop
        dut.io.cmd.valid #= false
        dut.io.cmd.payload.address #= 0x0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // --------------------
        // validate - check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex 101000|01|01|00 = 28hex|1st line | 1st word | byte 0
        ex_rlineaddr = 2576 // A10 hex 28hex|1st line | zeros
        ex_wbackaddr = 2576 // A10 hex 28hex|1st line | zeros
        ex_procread = true // should be true as we just done a read
        ex_hit = true // given same address to read, as to write so should be true
        ex_rdirty = false // data not written so should be false
        ex_valid = true //
        ex_rdata = 0x08.toInt // data written to cache prev.
        // actual outputs
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(s"validate 3a read one word from cache.....")
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ac_rdirty)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        sleep(10)
        // --------------------

        sleep(10)

        // 2a. Write to cache from processor and hit (no dirty bit set already)
        // -> write dirty bit, but doesn't yet show on output rsp, doesn't matter because hit
        // if really need to know will have to do separate read.
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0xa14 // 101000|01|01|00 = 28hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x09
        dut.io.cmd.payload.wmask #= 0xf
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= true
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // immediately followed by a read to check the dirty bit has changed
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0xa14 // 101000|01|01|00 = 28hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false // ToDo true or false??
        sleep(10)
        // --------------------
        // check get hit
        // validate - check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex
        ex_rlineaddr = 2576 // A10 hex  28hex|1st line | zeros
        ex_wbackaddr = 2576 // A10 hex  28hex|1st line | zeros
        ex_procread = false // should be false as we just done a write
        ex_hit = true // given same address to read, as to write so should be true
        ex_rdirty = false // dirty in ram but not yet at output, this does not matter
        ex_valid = true //
        ex_rdata =
          0x08.toInt // dont care what this is as done write, should be current value not what just written
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(s"validate 2a Write and hit (no dirty bit set already) no dirty bit on output.....")
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ex_rdirty)
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_wbackaddr == ex_wbackaddr, s"Got $ac_wbackaddr, expected $ex_wbackaddr")
        println(s"Got ac_wbackaddr:  ", ac_wbackaddr)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        // --------------------
        // stop
        dut.io.cmd.valid #= false
        dut.io.cmd.payload.address #= 0x0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10) // cache2
        // --------------------
        // check dirty bit has changed on a read
        // validate - check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex
        ex_rlineaddr = 2576 // A10 hex  28hex|1st line | zeros
        ex_wbackaddr = 2576 // A10 hex  28hex|1st line | zeros
        ex_procread = true // should be true as we just done a read
        ex_hit = true // given same address to read, as to write so should be true
        ex_rdirty = true // data written so should be true
        ex_valid = true // read data should be true
        ex_rdata = 0x09.toInt // data written to memory
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(s"Validate 2a with separate read.....")
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ex_rdirty)
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_wbackaddr == ex_wbackaddr, s"Got $ac_wbackaddr, expected $ex_wbackaddr")
        println(s"Got ac_wbackaddr:  ", ac_wbackaddr)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        sleep(10)
        // --------------------
        // 2b. Write to cache from processor and hit (dirty bit already set)
        // -> dirty bit rsp as already set
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0xa14 // 101000|01|01|00 = 28hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x09
        dut.io.cmd.payload.wmask #= 0xf
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= true
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // stop
        dut.io.cmd.valid #= false
        dut.io.cmd.payload.address #= 0x0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // --------------------
        // check dirty bit is now set on a write
        // validate - check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex
        ex_rlineaddr = 2576 // A10 hex  28hex|1st line | zeros
        ex_wbackaddr = 2576 // A10 hex  28hex|1st line | zeros
        ex_procread = false // should be false as we just done a write
        ex_hit = true // given same address to read, as to write so should be true
        ex_rdirty = true // data written so should be true
        ex_valid = true // read data should be true
        ex_rdata = 0x09.toInt // data written to cache memory
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(
          s"validate 2b. Write and hit (dirty bit already set) -> dirty bit rsp as already set....."
        )
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ex_rdirty)
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_wbackaddr == ex_wbackaddr, s"Got $ac_wbackaddr, expected $ex_wbackaddr")
        println(s"Got ac_wbackaddr:  ", ac_wbackaddr)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        sleep(10)
        // --------------------

        // 3b. Read from cache by processor and hit (with dirty bit set)
        // ->output dirty bit and hit rsp
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0xa14 // 101000|01|01|00 = 28hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x09
        dut.io.cmd.payload.wmask #= 0xf
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // stop
        dut.io.cmd.valid #= false
        dut.io.cmd.payload.address #= 0x0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // --------------------
        // check dirty bit is now set and hit
        // validate - check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex
        ex_rlineaddr = 2576 // A10 hex  28hex|1st line | zeros
        ex_wbackaddr = 2576 // A10 hex  28hex|1st line | zeros
        ex_procread = true // should be true as we just done a read
        ex_hit = true // given same address to read, as to write so should be true
        ex_rdirty = true // data written so should be true
        ex_valid = true // read data should be true
        ex_rdata = 0x09.toInt // data written to cache memory
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(
          s"validate 3b. Read and hit (with dirty bit set)->output dirty bit and hit rsp....."
        )
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ex_rdirty)
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_wbackaddr == ex_wbackaddr, s"Got $ac_wbackaddr, expected $ex_wbackaddr")
        println(s"Got ac_wbackaddr:  ", ac_wbackaddr)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        sleep(10)
        // --------------------

        // 4a. Read from cache by processor and miss (dirty bit already set)
        // ->output dirty bit and miss rsp
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0x114 // 000100|01|01|00 = 4hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // stop
        dut.io.cmd.valid #= false
        dut.io.cmd.payload.address #= 0x0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // --------------------
        // validate - check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex - current tag in ram
        ex_rlineaddr = 0x110.toInt // 110 hex 4hex|1st line | zeros
        ex_wbackaddr = 0xa10.toInt // from current tag in ram A10 hex 28hex|1st line | zeros
        ex_procread = true // should be true as we just done a read
        ex_hit = false // given diff address to read outside cache, so should be false
        ex_rdirty =
          true // although diff upper address, same cache line so will be true from previous write
        ex_valid = true //  should be true
        ex_rdata = 0x09.toInt // data in memory, cache line and word same so will be same as prev.
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(s"validate 4a. Read and miss (dirty bit already set).....")
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ac_rdirty)
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_wbackaddr == ex_wbackaddr, s"Got $ac_wbackaddr, expected $ex_wbackaddr")
        println(s"Got ac_wbackaddr:  ", ac_wbackaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        sleep(10)
        // --------------------

        // 1b. Write to cache from processor and miss (dirty bit already set)
        // -> will output dirty bit and miss rsp
        // manually check new data not written
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0x214
        dut.io.cmd.payload.wdata #= 0x06
        dut.io.cmd.payload.wmask #= 0xf
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= true
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // stop
        dut.io.cmd.valid #= false
        dut.io.cmd.payload.address #= 0x0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // --------------------
        // validate - check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex - current tag in ram
        ex_rlineaddr = 0x210.toInt // // 001000|01|01|00 = 4hex|1st line | 1st word | byte 0
        ex_wbackaddr = 0xa10.toInt // from current tag in ram A10 hex 28hex|1st line | zeros
        ex_procread = false // should be false as we just done a write
        ex_hit = false // given diff address to write outside cache, so should be false
        ex_rdirty =
          true // although diff upper address, same cache line so will be true from previous write
        ex_valid = true //  should be true
        ex_rdata = 0x09.toInt // data in memory, cache line and word same so will be same as prev.
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(
          s"Validate 1b Write and miss (dirty bit already set) -> will output dirty bit and miss rsp....."
        )
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ac_rdirty)
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_wbackaddr == ex_wbackaddr, s"Got $ac_wbackaddr, expected $ex_wbackaddr")
        println(s"Got ac_wbackaddr:  ", ac_wbackaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        sleep(10)
        // --------------------
        // 4a.read one word from diff cache line to create a miss, but no dirty
        // 4b.followed by read one word from orig cache line to create a miss, with dirty
        // 4a.followed by read one word from diff cache line to create a miss, but no dirty
        // 4a
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0x224 // 001000|10|01|00 = 4hex|1st line | 0th word | byte 0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // 4b
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0x214 // 001000|01|01|00 = 4hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // --------------------
        // validate 4a- check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex - current tag in ram
        ex_rlineaddr = 0x220.toInt // // 001000|10|01|00 = 4hex|1st line | 1st word | byte 0
        ex_wbackaddr = 0xa20.toInt // from current tag in ram A20 hex 28hex|2nd line | zeros
        ex_procread = true // should be true as we just done a read
        ex_hit = false // given diff address to write outside cache, so should be false
        ex_rdirty = false // diff cache line so will be false from previous write
        ex_valid = true //  should be true
        // ex_rdata = 0xxx.toInt // data in cache memory, will be random rubbish so ignore
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(s"validate 4a read to create a miss, but no dirty bit.....")
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ac_rdirty)
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_wbackaddr == ex_wbackaddr, s"Got $ac_wbackaddr, expected $ex_wbackaddr")
        println(s"Got ac_wbackaddr:  ", ac_wbackaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
//        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        // --------------------
        // 4a
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0x234 // 001000|11|01|00 = 4hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // --------------------
        // validate 4b- check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex - current tag in ram
        ex_rlineaddr = 0x210.toInt // // 001000|01|01|00 = 4hex|1st line | 1st word | byte 0
        ex_wbackaddr = 0xa10.toInt // from current tag in ram A10 hex 28hex|1st line | zeros
        ex_procread = true // should be true as we just done a read
        ex_hit = false // given diff address to write outside cache, so should be false
        ex_rdirty =
          true // although diff upper address, same cache line so will be true from previous write
        ex_valid = true //  should be true
        ex_rdata = 0x09.toInt // data in memory, cache line and word same so will be same as prev.
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(s"validate 4b read to create a miss, with dirty bit....")
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ac_rdirty)
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_wbackaddr == ex_wbackaddr, s"Got $ac_wbackaddr, expected $ex_wbackaddr")
        println(s"Got ac_wbackaddr:  ", ac_wbackaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        // --------------------
        // stop
        dut.io.cmd.valid #= false
        dut.io.cmd.payload.address #= 0x0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // --------------------
        // validate 4a- check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex - current tag in ram
        ex_rlineaddr = 0x230.toInt // // 001000|10|01|00 = 4hex|1st line | 1st word | byte 0
        ex_wbackaddr = 0xa30.toInt // from current tag in ram A10 hex 28hex|1st line | zeros
        ex_procread = true // should be true as we just done a read
        ex_hit = false // given diff address to write outside cache, so should be false
        ex_rdirty = false // diff cache line so will be false from previous write
        ex_valid = true //  should be true
        // ex_rdata = 0xxx.toInt // rubbish in cache.
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(s"validate 4a read to create a miss, but no dirty bit.....")
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ac_rdirty)
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_wbackaddr == ex_wbackaddr, s"Got $ac_wbackaddr, expected $ex_wbackaddr")
        println(s"Got ac_wbackaddr:  ", ac_wbackaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
//        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        sleep(10)
        // --------------------

        // --------------------
        // 1a.write one word from diff cache line to create a miss, so should not set dirty bit
        // 1b.followed by write one word from orig cache line to create a miss, with dirty bit set already
        // 1a.followed by write one word from diff cache line to create a miss, so should not set dirty bit
        // 1a
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0x224 // 001000|10|01|00 = 4hex|1st line | 0th word | byte 0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= true
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // 1b
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0x214 // 001000|01|01|00 = 4hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= true
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // --------------------
        // validate 1a- check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex - current tag in ram
        ex_rlineaddr = 0x220.toInt // // 001000|10|01|00 = 4hex|1st line | 1st word | byte 0
        ex_wbackaddr = 0xa20.toInt // from current tag in ram A20 hex
        ex_procread = false // should be false as we just done a write
        ex_hit = false // given diff address to write outside cache, so should be false
        ex_rdirty = false // diff cache line so will be false from previous write
        ex_valid = true //  should be true
        ex_rdata = 0x0.toInt // rubbish in cache.
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(s"validate 1a write to create a miss, check not set dirty bit.....")
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ac_rdirty)
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_wbackaddr == ex_wbackaddr, s"Got $ac_wbackaddr, expected $ex_wbackaddr")
        println(s"Got ac_wbackaddr:  ", ac_wbackaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
//        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        // --------------------
        // 1a
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0x234 // 001000|11|01|00 = 4hex|1st line | 1st word | byte 0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= true
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // --------------------
        // validate 1b- check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex - current tag in ram
        ex_rlineaddr = 0x210.toInt // // 001000|10|01|00 = 4hex|1st line | 1st word | byte 0
        ex_wbackaddr = 0xa10.toInt // from current tag in ram A10 hex 28hex|1st line | zeros
        ex_procread = false // should be false as we just done a write
        ex_hit = false // given diff address to write outside cache, so should be false
        ex_rdirty = true // dirty bit set from previous write
        ex_valid = true //  should be true
        ex_rdata = 0x09.toInt //
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(s"validate 1b write to create a miss, with dirty bit set already.....")
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ac_rdirty)
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_wbackaddr == ex_wbackaddr, s"Got $ac_wbackaddr, expected $ex_wbackaddr")
        println(s"Got ac_wbackaddr:  ", ac_wbackaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        // --------------------
        // stop
        dut.io.cmd.valid #= false
        dut.io.cmd.payload.address #= 0x0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)
        // --------------------
        // validate 1a- check rsp outputs after 1 clock cycle
        // use Int or BigInt
        // output should display in run window if correct
        // expected outputs
        ex_rtag = 40 // 28 hex - current tag in ram
        ex_rlineaddr = 0x230.toInt // // 001000|10|01|00 = 4hex|1st line | 1st word | byte 0
        ex_wbackaddr = 0xa30.toInt // from current tag in ram A10 hex 28hex|1st line | zeros
        ex_procread = false // should be false as we just done a write
        ex_hit = false // given diff address to write outside cache, so should be false
        ex_rdirty = false // diff cache line so will be false from previous write
        ex_valid = true //  should be true
        ex_rdata = 0x0.toInt // rubbish in cache.
        ac_rtag = dut.io.rsp.payload.rtag.toBigInt
        ac_rlineaddr = dut.io.rsp.payload.readLineAddr.toBigInt
        ac_wbackaddr = dut.io.rsp.payload.writebackLineAddr.toBigInt
        ac_procread = dut.io.rsp.payload.procread.toBoolean
        ac_hit = dut.io.rsp.payload.hit.toBoolean
        ac_rdirty = dut.io.rsp.payload.rdirty.toBoolean
        ac_valid = dut.io.rsp.valid.toBoolean
        ac_rdata = dut.io.rsp.payload.rdata.toBigInt
        println(s"validate 1a write to create a miss, check not set dirty bit.....")
        assert(ac_hit == ex_hit, s"Got $ac_hit, expected $ex_hit")
        println(s"Got ac_hit:  ", ac_hit)
        assert(ac_rdirty == ex_rdirty, s"Got $ac_rdirty, expected $ex_rdirty")
        println(s"Got ac_rdirty:  ", ac_rdirty)
        assert(ac_rtag == ac_rtag, s"Got $ac_rtag, ex $ex_rtag")
        println(s"Got ac_rtag:  ", ac_rtag)
        assert(ac_rlineaddr == ex_rlineaddr, s"Got $ac_rlineaddr, expected $ex_rlineaddr")
        println(s"Got ac_rlineaddr:  ", ac_rlineaddr)
        assert(ac_wbackaddr == ex_wbackaddr, s"Got $ac_wbackaddr, expected $ex_wbackaddr")
        println(s"Got ac_wbackaddr:  ", ac_wbackaddr)
        assert(ac_procread == ex_procread, s"Got $ac_procread, expected $ex_procread")
        println(s"Got ac_procread:  ", ac_procread)
        assert(ac_valid == ex_valid, s"Got $ac_valid, expected $ex_valid")
        println(s"Got ac_valid:  ", ac_valid)
//        assert(ac_rdata == ex_rdata, s"Got $ac_rdata, expected $ex_rdata")
        println(s"Got ac_rdata:  ", ac_rdata)
        sleep(10)
        // --------------------
        // --------------------
        // memory write to reset the dirty bit
        dut.io.cmd.valid #= true
        dut.io.cmd.payload.address #= 0xa14
        dut.io.cmd.payload.wdata #= 0x04
        dut.io.cmd.payload.wmask #= 0xf
        dut.io.cmd.payload.memwrite #= true
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= true
        sleep(10)
        // stop
        dut.io.cmd.valid #= false
        dut.io.cmd.payload.address #= 0x0
        dut.io.cmd.payload.wdata #= 0x0
        dut.io.cmd.payload.wmask #= 0x0
        dut.io.cmd.payload.memwrite #= false
        dut.io.cmd.payload.procwrite #= false
        dut.io.cmd.payload.inputFromMem #= false
        sleep(10)

        // let sim run for no. of cycles
        sleep(100)
      }
  }
}
