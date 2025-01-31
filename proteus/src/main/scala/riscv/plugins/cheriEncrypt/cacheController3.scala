package riscv.plugins.cheriEncrypt
import riscv.plugins.cheri
import spinal.core.{Bits, _}
import spinal.lib._
import riscv._
import spinal.lib.fsm._

import AESEngine.{
  AES_Dec,
  AES_DecCmd,
  AES_DecConfig,
  AES_DecIO,
  AES_DecRsp,
  AES_Enc,
  AES_EncCmd,
  AES_EncConfig,
  AES_EncIO,
  AES_EncRsp
}

/** This is the cache controller component */
class cacheController3(
    dbusConfig: MemBusConfig,
    aes_DecConfig: AES_DecConfig,
    aes_EncConfig: AES_EncConfig,
    ibusLatency: Int = 2
)(implicit
    cacheConfig: cacheConfig,
    context: cheri.Context,
    encryptConfig: EncryptConfig,
    tableConfig: table.TableConfig
) extends Component {

  /** --- INPUTS / OUTPUTS --- */
  /** bus from stage (fetch or memory) and axi */
  val busCache = master(DCacheDbusIo(dbusConfig, idWidth = 0 bits))

  /** input triggers to enable and disable the cache from CInvokeEncrypt instruction - from memory
    * stage
    */
  val CInvokeCache = slave(ICacheCInvokeIo(aes_DecConfig))

  /** input triggers to check fetch PCC against CInvokeEncrypt bounds - from fetch stage */
  val fetchPCCCache = slave(ICacheFetchIo())

  /** IO to other cache controller */
  val otherCache = master(CacheEncryptIo())

  /** IO to AES - dec */
  val aesCache_dec = master(AES_DecIO(aes_DecConfig)) // for crypto core

  /** IO to AES - enc */
  val aesCache_enc = master(AES_EncIO(aes_EncConfig)) // for crypto core

  /** IO to keyGenWrapper for writeback saving IVCount */
  val keyGenWrapper = master(CacheUpdateIVIO(tableConfig))
  // defaults
  keyGenWrapper.cmd.valid := False
  keyGenWrapper.cmd.payload.otype := 0
  keyGenWrapper.cmd.payload.NewNextIVCount := 0x0
  keyGenWrapper.cmd.payload.storeNextIVCount := False
  keyGenWrapper.DCacheSelect := False

  /** --- END INPUTS / OUTPUTS --- */

  /** --- SET DEFAULT DRIVING (OUTPUT) SIGNALS --- */
  /** ibusCache */
  /** signals to route ibus path to cache */
  /** when false ibus routes straight through as normal, set false as default */
  /** when true routes ibus path to cache which is set in state machine */
  busCache.cmdSelect := False
  busCache.rspSelect := False

  /** --- END SET DEFAULT DRIVING (OUTPUT) SIGNALS --- */

  /** counters */
  val tempRspStartCounterReg: UInt = Reg(UInt(8 bits)) init (0)

  /** --- COMPONENTS --- */

  /** --- COMPONENT - cache memory--- */
  /** add cache memory */
  val icache = new cache(cacheConfig: cacheConfig)

  /** --- END COMPONENT - cache memory--- */

  /** --- PROC LOGIC --- */
  /** inferred control lines from cache memory for the processor side logic */

  /** processor valid output */
  val procValid: Bool = Bool()
  procValid := icache.io.rsp.valid & !icache.io.rsp.payload.outputForMem

  /** Not registered control lines */
  /** order of priority checked by state machine */
  val writebackCacheline: Bool = Bool() // 1st priority
  val readCacheline: Bool = Bool() // 2nd priority
  val continue: Bool = Bool() // 3rd priority
  // first priority writebackcacheline - procRsp valid and dirty bit and miss
  writebackCacheline := procValid & icache.io.rsp.rdirty & !icache.io.rsp.hit
  // second priority readcacheline - rsp valid and miss, we need to read if dirty bit or not
  readCacheline := procValid & !icache.io.rsp.hit
  // third priority continue if valid
  continue := procValid

  /** registered control lines */
  /** registered to hold up the fetch cmds until writebackcacheline and readcacheline done */
  /** writebackcacheline first */
  val writebackCachelineReg: Bool = Reg(Bool()) init (False)
  val writebackCachelineDone: Bool = Bool() // output from state machine
  val stopFetchForWriteback: Bool = Bool() // used to halt fetch commands while doing a writeback
  // instantiate set/reset register
  when(writebackCacheline) {
    writebackCachelineReg := True // set
  } otherwise {
    when(writebackCachelineDone) {
      writebackCachelineReg := False // reset
    }
  }
  stopFetchForWriteback := writebackCacheline | writebackCachelineReg // stop fetch straight away and hold until done
  writebackCachelineDone := False // default setting, set to true in state machine
  /** readCacheline second */
  val readCachelineReg: Bool = Reg(Bool()) init (False)
  val readCachelineDone: Bool = Bool() // output from state machine
  val stopFetchForRead: Bool = Bool() // used to halt fetch commands while doing a read
  // instantiate set/reset register
  when(readCacheline) {
    readCachelineReg := True // set
  } otherwise {
    when(readCachelineDone) {
      readCachelineReg := False // reset
    }
  }
  stopFetchForRead := readCacheline | readCachelineReg // stop fetch straight away and hold until done
  readCachelineDone := False // default setting, set to true in state machine

  /** --- END PROC LOGIC --- */

  /** --- MEM LOGIC --- */
  /** inferred control lines from cache memory */

  /** memory valid output */
  val memValid: Bool = Bool()
  memValid := icache.io.rsp.valid & icache.io.rsp.payload.outputForMem

  /** valid memory read */
  val memRspReadValid: Bool = Bool()
  memRspReadValid := memValid & icache.io.rsp.payload.memread

  /** Error if there is not a hit */
  val memRspReadError: Bool = Bool()
  // valid, memread and a miss
  memRspReadError := memValid & icache.io.rsp.payload.memread & !icache.io.rsp.payload.hit

  /** --- END MEM LOGIC --- */

  /** --- COMPONENT - cacheBoundsChecker --- */
  /** bounds checker - checks the input cmdAddress against the enclave bounds, and checks the
    * current Fetch PCC against the enclave bounds. Flags high when out of bounds
    */
  val boundsChecker = new cacheBoundsChecker(cacheConfig)
  val cmdAddrOutOfBounds: Bool = Bool()
  val PCCOutOfBounds: Bool = Bool()
  val clearBounds: Bool = Bool() // clear out the saved bounds
  /** From state machine to clear out the saved bounds */
  clearBounds := False // default value
  boundsChecker.io.clearBounds := clearBounds

  /** From CInvokeEncrypt */
  boundsChecker.io.CInvokeboundsUpdate := CInvokeCache.invokeTrigger
  boundsChecker.io.CInvokePCCboundsBase := CInvokeCache.PCCboundsBase
  boundsChecker.io.CInvokePCCboundsTop := CInvokeCache.PCCboundsTop
  boundsChecker.io.CInvokecmdAddrboundsBase := CInvokeCache.cmdAddrboundsBase
  boundsChecker.io.CInvokeCmdAddrboundsTop := CInvokeCache.cmdAddrboundsTop
  boundsChecker.io.CInvokeCmdAddrboundsLen := CInvokeCache.cmdAddrboundsLen

  /** PCC bounds input */
  boundsChecker.io.currentPCCboundsBase := fetchPCCCache.pccBase
  boundsChecker.io.currentPCCboundsTop := fetchPCCCache.pccTop

  /** cmdAddr ibus input */
  boundsChecker.io.currentCmdAddress := busCache.dbusCacheStage.cmd.payload.address
  boundsChecker.io.currentCmdAddress_vld := busCache.dbusCacheStage.cmd.valid

  /** out of bounds output flags */
  cmdAddrOutOfBounds := boundsChecker.io.addrOutOfBounds
  PCCOutOfBounds := boundsChecker.io.PCCOutOfBounds

  /** --- END COMPONENT - cacheBoundsChecker --- */
  /** register key/otype/IVCount from Cinvoke */
  // ToDo maybe move to inside boundsChecker?
  val KeyReg = Reg(Bits(aes_DecConfig.keyWidth))
  val otypeReg = Reg(UInt(tableConfig.oTypeWidth bits))
  val IVCounter64Reg: UInt = Reg(UInt(width = BitCount(tableConfig.IVWidth.value))) init 0
  when(CInvokeCache.invokeTrigger) {
    KeyReg := CInvokeCache.Key
    otypeReg := CInvokeCache.otype
    IVCounter64Reg := CInvokeCache.NextIVCount.asUInt
  } elsewhen (clearBounds) {
    KeyReg := 0x0
    otypeReg := 0
    IVCounter64Reg := 0x0
  }

  /** read cacheline component */
  /** --- COMPONENT - cacheReadWriteBatch --- */
  val readBatch = new cacheReadWriteBatch(aes_DecConfig)

  /** connect to AES */
  readBatch.aesCache_dec <> aesCache_dec

  /** connect to cacheInputSelector - connected further down code with cacheInputSelector */
  /** connect to cache controller signals - defaults driving signals here */
  readBatch.controllerio.cmd.valid := False
  readBatch.controllerio.cmd.payload.batchAddr := 0x0
  readBatch.controllerio.cmd.payload.capBaseAddr := 0x0
  readBatch.controllerio.cmd.payload.capLen := 16
  readBatch.controllerio.cmd.payload.key := 0x0
  readBatch.controllerio.cmd.payload.IV := 0x0
  keyGenWrapper.decrypt_error := readBatch.controllerio.decrypt_error // auth tag error
  /** --- END COMPONENT - cache_readwriteBatch --- */

  /** write cacheback component */
  /** --- COMPONENT - cacheWritebackLine --- */

  val writeBatch = new cacheWriteBackLine(aes_EncConfig)

  /** connect to AES enc */
  writeBatch.aesCache_enc <> aesCache_enc

  /** connect to cacheInputSelector - connected further down code with cacheInputSelector */
  /** connect to cache controller signals - defaults driving signals here */
  writeBatch.controllerio.cmd.valid := False
  writeBatch.controllerio.cmd.payload.batchAddr := 0x0
  writeBatch.controllerio.cmd.payload.capBaseAddr := 0x0
  writeBatch.controllerio.cmd.payload.capLen := 16
  writeBatch.controllerio.cmd.payload.key := 0x0
  writeBatch.controllerio.cmd.payload.IV := 0x0

  /** connect to output of cache memory */
  writeBatch.cacheio.rsp.valid := memRspReadValid
  writeBatch.cacheio.rsp.payload.memRspReadError := memRspReadError
  writeBatch.cacheio.rsp.payload.rdata := icache.io.rsp.payload.rdata

  /** --- END COMPONENT - cacheWritebackLine --- */

  /** --- LOGIC --- */

  /** data cache specific - writeBackWhenFinish */
  /** if any of the cash lines need a writeback during the enclave then we need to check and perform
    * a writeback at the end ToDo improve this method
    */
  val writeBackWhenFinishReg: Bool = Reg(Bool()) init (False)
  // when any dirty bit
  when(icache.io.rsp.valid) {
    when(icache.io.rsp.payload.rProcWriteHit) {
      // set
      writeBackWhenFinishReg := True
    }
  } elsewhen (clearBounds) {
    // reset
    writeBackWhenFinishReg := False
  }

  /** --- ibus control --- */

  /** signals to control whether more input fetch commands can be received */
  val startFetch: Bool =
    Reg(Bool()) init (False) // start fetching commands to process - from state machine
  val cmdFetchPermit: Bool =
    Bool() // over-arching control signal to cmdReady ibus to start/stop fetch commands
  // only permit if state machine says start and not stopped for a writeback or read cacheline, and cmdAddress not out of bounds
  cmdFetchPermit := startFetch & !stopFetchForWriteback & !stopFetchForRead & !cmdAddrOutOfBounds

  /** signals to control whether cache rsp is valid to go back to fetch ibus */
  val rspReadValid: Bool = Bool()
  // output of cache (memory) is valid and it is a read request and there was a valid hit
  rspReadValid := procValid && icache.io.rsp.payload.procread && icache.io.rsp.payload.hit

  /** driving signals to ibus fetch */
  busCache.dbusCacheStage.cmd.ready := cmdFetchPermit // assume ready from cache is always high
  busCache.dbusCacheStage.rsp.valid := rspReadValid // currently assume ready will be high and valid is not held
  busCache.dbusCacheStage.rsp.payload.rdata := icache.io.rsp.payload.rdata.asUInt // rspFetchData
  /** --- end ibus control --- */

  /** signals for communication between caches */
  val thisCacheNotFinishedReg: Bool = Reg(Bool()) init (False)
  val otherCacheNotFinishedReg: Bool = Reg(Bool()) init (False)
  val thisCacheErrorReg: Bool = Reg(Bool()) init (False) // init to no decrypt error
  otherCache.thisCacheNotFinished := thisCacheNotFinishedReg & !thisCacheErrorReg // finish straight away if decrypt error
  otherCacheNotFinishedReg := otherCache.otherCacheNotFinished

  /** --- end signals for communication between caches --- */

  /** --- AXI control --- */
  /** control flow of axi cmd bus */
  val cmdMemAddress: UInt = Reg(UInt(cacheConfig.addrWidth))
  val rspMemAddress: UInt = Reg(UInt(cacheConfig.addrWidth))
  val memFillCacheLine: Bool = Reg(Bool()) init (False)

  /** signal to/from Fetch FSM to AES FSM */
  val doAESWritebackSingleCacheLine: Bool = Bool()
  val doAESWritebackFinishCacheLine: Bool = Bool()
  val doAESReadSingleCacheLine: Bool = Bool()
  val doneAESWritebackSingleCacheLine: Bool = Bool()
  val doneAESWritebackFinishCacheLine: Bool = Bool()
  val doneAESReadSingleCacheLine: Bool = Bool()
  doAESWritebackSingleCacheLine := False // set default
  doAESWritebackFinishCacheLine := False // set default
  doAESReadSingleCacheLine := False // set default
  doneAESWritebackSingleCacheLine := False // set default
  doneAESWritebackFinishCacheLine := False // set default
  doneAESReadSingleCacheLine := False // set default

  /** connect to AXI */
  /** connection when do a readback cacheline */
  when(doAESReadSingleCacheLine) {
    readBatch.axiio.ibusCacheAXI <> busCache.dbusCacheAXI

    /** set driving signals */
    writeBatch.axiio.ibusCacheAXI.rsp.valid := False
    writeBatch.axiio.ibusCacheAXI.rsp.payload.assignDontCare()
    writeBatch.axiio.ibusCacheAXI.cmd.ready := False
  } otherwise {

    /** connection when do a writeback cacheline */
    writeBatch.axiio.ibusCacheAXI <> busCache.dbusCacheAXI

    /** set driving signals */
    readBatch.axiio.ibusCacheAXI.rsp.valid := False
    readBatch.axiio.ibusCacheAXI.rsp.payload.assignDontCare()
    readBatch.axiio.ibusCacheAXI.cmd.ready := False
  }

  /** --- end AXI control --- */

  /** --- driving signals to cache --- */

  /** repeat read/write to cache */
  /** repeatReadWrite signal to indicate we need to repeat read/write to cache following a miss and
    * after writeback / read before permitting more fetch cmds
    */
  val repeatReadWrite: Bool = Bool()
  repeatReadWrite := False // set default to false, set to true by state machine

  /** --- COMPONENT - cacheInputSelector --- */
  /** select cmd input to cache */
  val cacheCmdInput = new cacheInputSelector(cacheConfig)

  /** selector inputs */
  cacheCmdInput.io.repeatReadWrite := repeatReadWrite
  cacheCmdInput.io.inputFromReadCacheline := doAESReadSingleCacheLine

  /** set to mem input when interacting with AES side */
  cacheCmdInput.io.inputFromMem := doAESWritebackSingleCacheLine | doAESWritebackFinishCacheLine | doAESReadSingleCacheLine

  /** stage input */
  cacheCmdInput.io.cmdStageInput.payload.address := busCache.dbusCacheStage.cmd.payload.address.asBits
  cacheCmdInput.io.cmdStageInput.payload.wdata := busCache.dbusCacheStage.cmd.payload.wdata.asBits
  cacheCmdInput.io.cmdStageInput.payload.wmask := busCache.dbusCacheStage.cmd.payload.wmask.asBits
  cacheCmdInput.io.cmdStageInput.payload.procwrite := busCache.dbusCacheStage.cmd.payload.write
  cacheCmdInput.io.cmdStageInput.payload.memwrite := False // default to read
  cacheCmdInput.io.cmdStageInput.payload.inputFromMem := False // this is proc read/write
  cacheCmdInput.io.cmdStageInput.valid := (busCache.dbusCacheStage.cmd.valid & cmdFetchPermit) | repeatReadWrite

  /** current input */
  /** feed back held registers to the cache (memory) to repeat read/write since we already accepted
    * the input address
    */
  cacheCmdInput.io.cmdCacheCurrentInput.payload.address := icache.io.rsp.payload.currentAddr
  cacheCmdInput.io.cmdCacheCurrentInput.payload.wdata := icache.io.rsp.payload.curentWdata
  cacheCmdInput.io.cmdCacheCurrentInput.payload.wmask := icache.io.rsp.payload.currentWmask
  cacheCmdInput.io.cmdCacheCurrentInput.payload.procwrite := icache.io.rsp.payload.currentProcwrite
  cacheCmdInput.io.cmdCacheCurrentInput.payload.memwrite := icache.io.rsp.payload.currentMemwrite
  cacheCmdInput.io.cmdCacheCurrentInput.payload.inputFromMem := icache.io.rsp.payload.currentInputFromMem
  cacheCmdInput.io.cmdCacheCurrentInput.valid := False // unused, generated by repeatReadWrite
  /** readcacheline - memory (via AES core) input */
  cacheCmdInput.io.cmdReadlineMemoryInput.payload.address := readBatch.cacheio.cmd.payload.address
  cacheCmdInput.io.cmdReadlineMemoryInput.payload.wdata := readBatch.cacheio.cmd.payload.wdata
  cacheCmdInput.io.cmdReadlineMemoryInput.payload.wmask := readBatch.cacheio.cmd.payload.wmask
  cacheCmdInput.io.cmdReadlineMemoryInput.payload.procwrite := readBatch.cacheio.cmd.payload.procwrite
  cacheCmdInput.io.cmdReadlineMemoryInput.payload.memwrite := readBatch.cacheio.cmd.payload.memwrite
  cacheCmdInput.io.cmdReadlineMemoryInput.payload.inputFromMem := readBatch.cacheio.cmd.payload.inputFromMem
  cacheCmdInput.io.cmdReadlineMemoryInput.valid := readBatch.cacheio.cmd.valid

  /** writecacheline memory reads */
  cacheCmdInput.io.cmdWritelineMemoryInput.payload.address := writeBatch.cacheio.cmd.payload.address
  cacheCmdInput.io.cmdWritelineMemoryInput.payload.wdata := writeBatch.cacheio.cmd.payload.wdata
  cacheCmdInput.io.cmdWritelineMemoryInput.payload.wmask := writeBatch.cacheio.cmd.payload.wmask
  cacheCmdInput.io.cmdWritelineMemoryInput.payload.procwrite := writeBatch.cacheio.cmd.payload.procwrite
  cacheCmdInput.io.cmdWritelineMemoryInput.payload.memwrite := writeBatch.cacheio.cmd.payload.memwrite
  cacheCmdInput.io.cmdWritelineMemoryInput.payload.inputFromMem := writeBatch.cacheio.cmd.payload.inputFromMem
  cacheCmdInput.io.cmdWritelineMemoryInput.valid := writeBatch.cacheio.cmd.valid

  /** output - Actual input to cache */
  icache.io.cmd <> cacheCmdInput.io.cmdCacheSelectedInput

  /** --- END COMPONENT - cacheInputSelector --- */

  /** --- end driving signals to cache --- */

  /** indicates when cache has been flushed at end of enclave - initially set to true */
  val cacheFlushedReg: Bool = Reg(Bool()) init (True)

  /** flush counter - set to highest value and count down */
  val flushCounterReg: UInt = Reg(UInt((cacheConfig.wordBits + cacheConfig.lineBits) bits)).setAll()

  /** STATE MACHINE */
  /** ------------ */
  val cacheEnclaveFsm = new StateMachine {

    /** state machine states */
    val resetState =
      StateEntryPoint()
    val waitInvokeState =
      State() // wait for invoke start trigger
    val waitRspStartState = State() // wait for rsp already in progress to finish
    val startInvokeState = State() // start read/write to cache
    val writebackCachelineState = State() // do a writeback cacheline
    val readCachelineState = State() // do a read cacheline
    val repeatReadWriteState =
      State() // repeat read/write to cache before get any new cmds following a miss with writeback/read cacheline
    val waitRspFinishState = State() // wait for rsp already in progress at end before free bus
    val storeNextIVCountState = State() // store next IV count after finish all writebacks
    val waitstoreIVDoneState = State() // wait for store to finish
    val flushCacheState = State() // flush out the cache on enclave return

    resetState.whenIsActive {
      startFetch := False // halt all processor cmds to cache, and rsp to processor
      // let ibus data pass straight through IbusCntrlSelector
      busCache.cmdSelect := False
      busCache.rspSelect := False
      readCachelineDone := True // needed to reset registers at reset
      writebackCachelineDone := True // needed to reset registers at reset

      icache.io.cmd.valid := False
      icache.io.cmd.payload.address(30 downto 0) := 0x0
      icache.io.cmd.payload.address(31 downto 31) := 0x1 // set top bit to 1
      icache.io.cmd.payload.memwrite := True
      icache.io.cmd.payload.inputFromMem := True // input is from memory side
      icache.io.cmd.payload.procwrite := False
      icache.io.cmd.payload.wmask := 0xf

      clearBounds := True
      thisCacheErrorReg := False

      goto(waitInvokeState)
    }

    /** wait for invoke start trigger */
    waitInvokeState.whenIsActive {
      startFetch := False // halt all processor cmds to cache, and rsp to processor
      /** let ibus data pass straight through IbusCntrlSelector */
      busCache.cmdSelect := False
      busCache.rspSelect := False

      /** start on input trigger */
      when(CInvokeCache.invokeTrigger) {
        thisCacheNotFinishedReg := True
        cacheFlushedReg := False
        goto(waitRspStartState)

        /** check for decrypt error */
      } elsewhen (thisCacheErrorReg) {
        goto(resetState)

        /** when finished check again if still within enclave because may have done a jump */
        /** after the prefetch goes outside the enclave */
      } elsewhen (!PCCOutOfBounds) {
        thisCacheNotFinishedReg := True
        goto(waitRspStartState)

        /** need to flush cache before finishing */
      } elsewhen (!cacheFlushedReg) {
        goto(storeNextIVCountState)

        /** waiting to finish and clear bounds */
      } otherwise {
        thisCacheNotFinishedReg := False // this cache now finished

        /** wait for the other cache to finish */
        when(otherCacheNotFinishedReg) {
          busCache.cmdSelect := True
          busCache.rspSelect := True
        } otherwise {
          clearBounds := True // clear out the saved enclave bounds when out of PCC bounds
        }
        goto(waitInvokeState)
      }
    }

    /** finish sending back rsp already in progress */
    waitRspStartState.whenIsActive {
      busCache.cmdSelect := True // direct cmd ibus through to cache controller
      busCache.rspSelect := False // finish rsp back to processor
      startFetch := False // but stall, dont yet permit cmd to cache controller
      tempRspStartCounterReg := tempRspStartCounterReg + 1 // temp
      /** wait for rsp in progress to finish (we really wait for valid to go low) */
      // ToDo 1) need to do something different here as valid may go low without finishing
      // fetchRspReady will always be true - this is currently how proteus is designed.
      // See MemBus.scala line 322,We always accept responses.
      when(busCache.axiRspValid & busCache.stageRspReady) {
        goto(waitRspStartState)
      } elsewhen (tempRspStartCounterReg < 2) { // extra temp delay to make sure not stalled //ToDo fix this
        goto(waitRspStartState)
      } otherwise {
        tempRspStartCounterReg := 0 // reset counter
        goto(startInvokeState)
      }
    }

    /** start processing invoke commands */
    startInvokeState.whenIsActive {
      busCache.cmdSelect := True // direct cmd ibus through to cache controller
      busCache.rspSelect := True // direct rsp ibus through to cache controller
      startFetch := True // permit cmds to cache

      /** 1st priority writeback */
      when(writebackCacheline) {
        goto(writebackCachelineState)

        /** 2nd priority read cacheline */
      } elsewhen (readCacheline) {
        goto(readCachelineState)

        /** check if commands go out of bounds, maybe prefetch, or data outside enclave */
      } elsewhen (cmdAddrOutOfBounds) {
        startFetch := False
        goto(waitRspFinishState)

        /** Also need to check when PCC goes out of bounds here because for the data */
        /** cache the PCC goes out of bounds before the cmdAddress. For the instruction */
        /** cache it is the other way around and will not normally get to do this check */
      } elsewhen (PCCOutOfBounds) {
        startFetch := False

        /** check for final writeback needed on the data cache */
        when(writeBackWhenFinishReg) {
          goto(writebackCachelineState)
        } otherwise {

          /** store NextIVCount and then flush the cache before finish */
          goto(storeNextIVCountState)
        }

        /** 3rd priority read/write hit and continue */
        // ToDo don't need check here as goes back to state by default anyway
      } elsewhen (continue) {
        goto(startInvokeState)
      } otherwise {
        goto(startInvokeState)
      }
    }

    /** do a writeback cacheline */
    writebackCachelineState.whenIsActive {
      busCache.cmdSelect := True // direct cmd ibus through to cache controller
      busCache.rspSelect := True // direct rsp ibus through to cache controller
      startFetch := False // permit cmds to cache
      /** when done final writeback for data cache, finish */
      when(writeBackWhenFinishReg & PCCOutOfBounds) {
        doAESWritebackFinishCacheLine := True // set default
        when(doneAESWritebackFinishCacheLine) {
          goto(waitRspFinishState)
        } otherwise {
          goto(writebackCachelineState)
        }

        /** otherwise do a normal writeback of a single cacheline */
      } otherwise {
        doAESWritebackSingleCacheLine := True // set default
        when(doneAESWritebackSingleCacheLine) {

          /** when done continue to read a new cacheline following a writeback */
          writebackCachelineDone := True // reset register
          goto(readCachelineState)
        } otherwise {
          goto(writebackCachelineState)
        }
      }
    }

    /** do a read cacheline */
    readCachelineState.whenIsActive {
      busCache.cmdSelect := True // direct cmd ibus through to cache controller
      busCache.rspSelect := True // direct rsp ibus through to cache controller
      startFetch := False // permit cmds to cache
      doAESReadSingleCacheLine := True // start reading cacheline
      /** stay in this state until reading of cacheline is complete */
      /** or there is a decrypt tag error */
      when(aesCache_dec.tag_error) {
        thisCacheErrorReg := True // use this to tell other cache to finish early and flag need to go to error state after flush cache
        /** flush the cache and finish then sit in the error state */
        goto(flushCacheState)
      }
      when(doneAESReadSingleCacheLine) {
        goto(repeatReadWriteState)
      }
    }

    /** repeat read/write to cache following a miss and after writeback / read before permitting
      * more fetch cmds
      */
    repeatReadWriteState.whenIsActive {
      busCache.cmdSelect := True // direct cmd ibus through to cache controller
      busCache.rspSelect := True // direct rsp ibus through to cache controller
      startFetch := True // permit cmds to cache
      repeatReadWrite := True // repeat cmd to cache
      readCachelineDone := True
      goto(startInvokeState)
    }

    /** wait response to finish */
    waitRspFinishState.whenIsActive {
      busCache.cmdSelect := True // direct cmd ibus through to cache controller
      busCache.rspSelect := True // direct rsp ibus through to cache controller
      startFetch := False // dont permit anymore cmds to cache
      /** wait for rsp in progress to finish (this really means just wait for valid to go low) */
      // ToDo fetchRspReady will always be true - this is currently how proteus is designed.
      //  ToDo See MemBus.scala line 322, We always accept responses.
      when(procValid & busCache.dbusCacheStage.rsp.ready) {
        goto(waitRspFinishState)
      } otherwise {
        goto(waitInvokeState)
      }
    }

    /** update IVCount before flush and finish */
    /** If not done any writebacks at end, but did a single writeback only earlier - still need to
      * update IVCount
      */
    /** so have to do this at end anyway before cash flush */
    storeNextIVCountState.whenIsActive {

      /** keep control of the bus */
      busCache.cmdSelect := True // direct cmd ibus through to cache controller
      // If PCC out of bounds before Addr, we need to keep hold of rsp side for 1 more clk to allow
      // last cache rsp to go back to processor
      // ToDo we could add an extra state for this but will cost us an extra clk cycle
      busCache.rspSelect := True // allow response in flight from waitInvokeState from cache
      startFetch := False // dont permit anymore cmds to cache

      /** store NextIVcount in table */
      keyGenWrapper.cmd.payload.storeNextIVCount := True
      keyGenWrapper.cmd.payload.NewNextIVCount := IVCounter64Reg.asBits
      keyGenWrapper.cmd.payload.otype := otypeReg
      keyGenWrapper.cmd.valid := True
      keyGenWrapper.DCacheSelect := True
      goto(waitstoreIVDoneState)
    }

    /** wait for IVCount to be stored */
    /** we need to wait otherwise next commands might go to the table before this one is finished */
    waitstoreIVDoneState.whenIsActive {

      /** keep control of the bus */
      busCache.cmdSelect := True // direct cmd ibus through to cache controller
      /** If Adr out of bounds before PCC, we need to release rsp side now to allow AXI rsp to go
        * back to processor. This solution relies on AXI rsp taking more than 1 clk cycle(longer
        * than cache rsp when PCC goes out of bounds first)
        */
      // ToDo we should add extra state and hold the AXI rsp until we are ready to check it
      busCache.rspSelect := False // allow response in flight from waitInvokeState from AXI memory
      startFetch := False // dont permit anymore cmds to cache

      /** check for table error condition */
      when(keyGenWrapper.table_error) {

        /** immediately flush cache and finish */
        goto(flushCacheState)
      }

      /** wait for IV to be stored then go to flush cache */
      /** if there are only a few enclaves we don't need to wait because it will be quicker than the
        * flush and before another command is sent. But it is best to wait because it may take
        * longer if lots of enclaves to look up in table. Waiting will work in any scenario
        */
      keyGenWrapper.DCacheSelect := True // keep selected until done
      when(keyGenWrapper.IVcountsavedDone) {
        goto(flushCacheState)
      }
    }

    /** flush out the cache before finish */
    flushCacheState.whenIsActive {

      /** keep control of the bus */
      busCache.cmdSelect := True // direct cmd ibus through to cache controller
      busCache.rspSelect := False // allow response in flight from waitInvokeState ToDo modify for external memory, maybe add another wait state?
      startFetch := False // dont permit anymore cmds to cache

      /** set up cache inputs */
      icache.io.cmd.valid := True

      /** set tag bits to zero */
      icache.io.cmd.payload.address(
        cacheConfig.addrWidth.value - 1 downto (cacheConfig.wordBits + cacheConfig.lineBits + cacheConfig.byteBits)
      ) := 0x0

      /** set byte bits to zero */
      icache.io.cmd.payload.address(cacheConfig.byteBits - 1 downto 0) := 0x0

      /** set word and line bits to flush counter, remember take into account byteBits! */
      icache.io.cmd.payload.address(
        (cacheConfig.wordBits + cacheConfig.lineBits + cacheConfig.byteBits - 1) downto cacheConfig.byteBits
      ) := flushCounterReg.asBits

      /** set data to zero */
      icache.io.cmd.payload.wdata := 0x0

      /** write from memory to reset dirty bits */
      icache.io.cmd.payload.memwrite := True

      /** input is from memory side */
      icache.io.cmd.payload.inputFromMem := True
      icache.io.cmd.payload.procwrite := False
      icache.io.cmd.payload.wmask := 0xf

      /** always subtract counter. */
      /** when reached zero will roll back round to */
      /** all bits set ready for next time flush */
      flushCounterReg := flushCounterReg - 1

      /** when flushed all memory say done and exit */
      when(flushCounterReg === 0) {
        cacheFlushedReg := True // flushed cache done
        goto(waitRspFinishState)
      }
    }

  }

  /** END STATE MACHINE ------------ */

  /** STATE MACHINE FOR AES control */
  // ToDo separate state machine, but could combine in statemachine above and make more efficient.
  val cachelineCounter: UInt = Reg(UInt(cacheConfig.lineBits + 1 bits)) init (0)

  /** ------------ */
  val AESFsm = new StateMachine {

    /** state machine states */
    val AESidleState = StateEntryPoint() // wait
    val AESwritebackFinishState = State() // write to memory via AES, check all
    val AESwritebackSingleState = State() // write to memory via AES single cacheline
    val AESreadSingleState = State() // read single cacheline from memory via AES

    AESidleState.whenIsActive {
      when(doAESWritebackFinishCacheLine) {
        goto(AESwritebackFinishState)
      } elsewhen (doAESWritebackSingleCacheLine) {
        goto(AESwritebackSingleState)
      } elsewhen (doAESReadSingleCacheLine) {
        goto(AESreadSingleState)
      } otherwise {
        goto(AESidleState)
      }
    }

    // ToDo move this state into write cacheline block / sort out dirty cache registers
    AESwritebackFinishState.whenIsActive {
      // ToDo currently assumes cache line is 4 cache lines
      /** 1. check the rdirty for each of the 4 cache lines */
      cacheCmdInput.io.cmdWritelineMemoryInput.payload.address := 0x0
      cacheCmdInput.io.cmdWritelineMemoryInput.payload.address(
        (cacheConfig.byteBits + cacheConfig.wordBits + cacheConfig.lineBits - 1) downto (cacheConfig.byteBits + cacheConfig.wordBits)
      ) := cachelineCounter.asBits((cacheConfig.lineBits - 1) downto 0)
      cacheCmdInput.io.cmdWritelineMemoryInput.valid := True
      cacheCmdInput.io.cmdWritelineMemoryInput.payload.memwrite := False // read
      /** 2. When dirty do a writeback for a single cacheline */
      when(memValid & icache.io.rsp.payload.rdirty) {
        // do single writeback
        cacheCmdInput.io.cmdWritelineMemoryInput.valid := False
        goto(AESwritebackSingleState)

        /** 3. when done all 4 cachelines, stop (counter will progress one further) */
      } elsewhen (cachelineCounter === 4) {
        cacheCmdInput.io.cmdWritelineMemoryInput.valid := False
        cachelineCounter := 0
        doneAESWritebackFinishCacheLine := True // finished
        goto(AESidleState)
      } otherwise {
        cachelineCounter := cachelineCounter + 1
        goto(AESwritebackFinishState)
      }
    }

    AESwritebackSingleState.whenIsActive {

      /** send info to read a single batch component */
      writeBatch.controllerio.cmd.valid := True
      writeBatch.controllerio.cmd.payload.key := KeyReg
      writeBatch.controllerio.cmd.payload
        .IV(127 downto 96) := encryptConfig.fixedIVvalue.asBits // fixed part
      writeBatch.controllerio.cmd.payload
        .IV(95 downto 32) := IVCounter64Reg.asBits // counter part
      writeBatch.controllerio.cmd.payload.IV(31 downto 0) := 0x0 // padding part
      writeBatch.controllerio.cmd.payload.capBaseAddr := boundsChecker.io.capBase.asBits
      writeBatch.controllerio.cmd.payload.capLen := boundsChecker.io.capLen
      writeBatch.controllerio.cmd.payload.batchAddr := icache.io.rsp.payload.writebackLineAddr

      /** do write back */
      when(!(writeBatch.controllerio.rsp.valid & writeBatch.controllerio.rsp.payload.done)) {
        goto(AESwritebackSingleState)
      } otherwise {
        when(doAESWritebackFinishCacheLine) {

          /** update IVCounterReg for next time */
          IVCounter64Reg := IVCounter64Reg + 1
          goto(AESwritebackFinishState)
        } otherwise {

          /** only doing a single so finish */
          doneAESWritebackSingleCacheLine := True // finished
          /** update IVCounterReg for next time */
          IVCounter64Reg := IVCounter64Reg + 1
          goto(AESidleState)
        }
      }
    }

    AESreadSingleState.whenIsActive {

      /** send info to read a single batch component */
      readBatch.controllerio.cmd.valid := True
      readBatch.controllerio.cmd.payload.IV := 0x0 // don't need this for read, this is read from memory
      readBatch.controllerio.cmd.payload.key := KeyReg
      readBatch.controllerio.cmd.payload.capBaseAddr := boundsChecker.io.capBase.asBits
      readBatch.controllerio.cmd.payload.capLen := boundsChecker.io.capLen
      readBatch.controllerio.cmd.payload.batchAddr := icache.io.rsp.payload.readLineAddr
      // readBatch.controllerio.cmd.payload.write:= False //read
      when(!(readBatch.controllerio.rsp.valid & readBatch.controllerio.rsp.payload.done)) {
        goto(AESreadSingleState)
      } otherwise {
        doneAESReadSingleCacheLine := True // finished
        goto(AESidleState)
      }
    }

  }

}
