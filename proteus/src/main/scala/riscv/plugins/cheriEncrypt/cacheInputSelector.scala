package riscv.plugins.cheriEncrypt
import spinal.core._
import spinal.lib._
import spinal.lib.fsm._

/** The cacheInputSelector component is used by the cacheController to select the input to the cache
  * memory
  */

/** This component does the following: */
/** 1) Selects between the Stage cmd input and the memory (via AES core) cmd input to the cache. */
/** 2) For the stage cmd input, selects between the stage cmd input and the feedback 'cache current
  * cmd input' for a repeatReadWrite` .
  */
/** 3) For the memory cmd input, selects between the readcacheline control signals or the
  * writebackcacheline control signals
  */
/** 4) Three input selectors are used: a) A single bit 'InputFromMem' is used to select the memory
  * input otherwise the stage cmd input is assumed. b) A single bit 'repeatReadWrite' is used to
  * select the 'cache current cmd input' for a repeat operation c) A single bit
  * 'inputFromReadCacheline' is used to select the input from a read cacheline operation or a
  * writeback operation
  */
/** cmdCacheSelectedInput is the selected input to the cache memory, and the output of this
  * component
  */

/** define inputs/outputs in a bundle */
//use cache cmd names
case class cacheInputSelectorIO(cacheConfig: cacheConfig) extends Bundle with IMasterSlave {

  val cmdStageInput = Flow(CacheCmd(cacheConfig)) // Stage cmd input
  val cmdCacheCurrentInput = Flow(
    CacheCmd(cacheConfig)
  ) // current cache input to be used for repeat read/write
  val cmdReadlineMemoryInput = Flow(
    CacheCmd(cacheConfig)
  ) // Memory cmd input from readCacheline block
  val cmdWritelineMemoryInput = Flow(
    CacheCmd(cacheConfig)
  ) // Memory cmd input from writebackCacheline block
  val cmdCacheSelectedInput = Flow(CacheCmd(cacheConfig)) // selected input to go to cache memory
  val inputFromMem = Bool() // select input from memory
  val inputFromReadCacheline = Bool() // select input from readcacheline
  val repeatReadWrite: Bool = Bool() // repeat Read/Write to cache needed

  /** Set the direction of each bundle/signal from a master point of view */
  override def asMaster(): Unit = {
    // declare outputs for master, so will be inputs for slave
    master(cmdStageInput)
    master(cmdCacheCurrentInput)
    master(cmdReadlineMemoryInput)
    master(cmdWritelineMemoryInput)
    out(inputFromMem)
    out(inputFromReadCacheline)
    out(repeatReadWrite)
    // declare inputs for master, so will be outputs for slave
    slave(cmdCacheSelectedInput)
  }
}

class cacheInputSelector(cacheConfig: cacheConfig) extends Component {

  /** INPUTS/OUTPUTS */
  val io = slave(cacheInputSelectorIO(cacheConfig))

  /** END INPUTS/OUTPUTS */

  /** intermediate stage cmd input */
  val cmdStageInput_int = Flow(CacheCmd(cacheConfig))

  /** intermediate memory cmd input */
  val cmdMemoryInput_int = Flow(CacheCmd(cacheConfig))

  /** 1) For the stage cmd input, selects between the stage cmd input and the feedback 'cache
    * current cmd input' for a repeatReadWrite` .
    */
  when(io.repeatReadWrite) {
    cmdStageInput_int.payload <> io.cmdCacheCurrentInput.payload
  } otherwise {
    cmdStageInput_int.payload <> io.cmdStageInput.payload
  }
  // data valid when input valid or repeat read/write
  cmdStageInput_int.valid := io.cmdStageInput.valid | io.repeatReadWrite

  /** 2) For the memory cmd input, selects between the readcacheline control signals or the
    * writebackcacheline control signals
    */
  when(io.inputFromReadCacheline) {
    cmdMemoryInput_int <> io.cmdReadlineMemoryInput
  } otherwise {
    cmdMemoryInput_int <> io.cmdWritelineMemoryInput
  }

  /** 3) Selects between the Stage cmd input and the memory (via AES core) cmd input to the cache.
    */
  when(io.inputFromMem) {
    io.cmdCacheSelectedInput <> cmdMemoryInput_int
  } otherwise {
    io.cmdCacheSelectedInput <> cmdStageInput_int
  }
}

//Generate the VHDL
object cacheInputSelectorVhdl {
  def main(args: Array[String]) {
    val cacheConfig = new cacheConfig(
      addrWidth = 32 bits, // 8
      dataWidth = 32 bits,
      sizeCacheLine = 16, // In bytes 256
      numCacheLines = 4,
      maskWidth = 4 bits
    )
    SpinalVhdl(new cacheBoundsChecker(cacheConfig))
  }
}
