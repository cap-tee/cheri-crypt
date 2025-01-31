package riscv.plugins.cheriEncrypt

import spinal.core.{Bits, _}
import spinal.lib._
import riscv._
import riscv.plugins.cheri
import AESEngine._
import table._

/** This is the Instruction Cache encryption component that goes in the pipeline area and connects
  * to the Fetch stage ibus control selector.
  */

/** define input / output signals */
case class ICacheIbusIo(ibusConfig: MemBusConfig, idWidth: BitCount)
    extends Bundle
    with IMasterSlave {
  val ibusCacheFetch = MemBus(ibusConfig, idWidth).setName("ibusCacheFetch")
  val ibusCacheAXI = MemBus(ibusConfig, idWidth).setName("ibusCacheAXI")
  val cmdSelect = Bool() // select cmd and rsp separately as we need to wait for responses to finish
  val rspSelect = Bool()
  val fetchRspReady = Bool() // from ibus fetch side to know when rsp finished
  val axiRspValid = Bool() // from ibus AXI side to know when rsp finished

  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    out(cmdSelect)
    out(rspSelect)
    in(fetchRspReady)
    in(axiRspValid)
    master(ibusCacheAXI)
    slave(ibusCacheFetch)
  }
}

/** Input from CInvokeEncrypt to enable and disable the cache */
case class ICacheCInvokeIo(aes_DecConfig: AES_DecConfig)(implicit
    cacheConfig: cacheConfig,
    tableConfig: table.TableConfig
) extends Bundle
    with IMasterSlave {
  val invokeTrigger = Bool() // enable cache into ibus
  val PCCboundsBase = UInt(cacheConfig.addrWidth) // lower enclave bounds
  val PCCboundsTop = UInt(cacheConfig.addrWidth) // upper enclave bounds
  val cmdAddrboundsBase = UInt(cacheConfig.addrWidth)
  val cmdAddrboundsTop = UInt(cacheConfig.addrWidth)
  val cmdAddrboundsLen = UInt(cacheConfig.addrWidth)
  val Key = Bits(aes_DecConfig.keyWidth)
  val otype = UInt(tableConfig.oTypeWidth bits)
  val NextIVCount = Bits(tableConfig.IVWidth)

  /** feedback decrypt error to a stage to trigger a hardware exception */
  val decrypt_error = Bool()
  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    out(invokeTrigger)
    out(PCCboundsBase)
    out(PCCboundsTop)
    out(cmdAddrboundsBase)
    out(cmdAddrboundsTop)
    out(cmdAddrboundsLen)
    out(Key)
    out(otype)
    out(NextIVCount)

    /** feedback decrypt error to a stage to trigger a hardware exception */
    in(decrypt_error)
  }
}

/** Input from Fetch stage to check the current PCC against the CInvoke bounds and enable/disable
  * the cache
  */
case class ICacheFetchIo(implicit cacheConfig: cacheConfig) extends Bundle with IMasterSlave {
  val pccBase = UInt(cacheConfig.addrWidth) // lower pcc bounds
  val pccTop = UInt(cacheConfig.addrWidth) // upper pcc bounds
  val pccLength = UInt(cacheConfig.addrWidth) // length bounds
  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    out(pccBase)
    out(pccTop)
    out(pccLength)
  }
}

/** Communication IO between caches
  */
case class CacheEncryptIo(implicit cacheConfig: cacheConfig) extends Bundle with IMasterSlave {
  val thisCacheNotFinished = Bool() // output saying whether this cache has finished processing
  val otherCacheNotFinished = Bool() // input saying whether other cache has finished processing
  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    out(thisCacheNotFinished)
    in(otherCacheNotFinished)
  }
}

/** Definition of a service to add/connect Io within a stage */
/** This is used by FetcherEncrypt.scala to connect the ibus control selector to the instruction
  * cache.
  */
trait ICacheIbusIoService {
  def getICacheIbusIo(stage: Stage, ibusConfig: MemBusConfig, idWidth: BitCount): ICacheIbusIo
}

/** Definition of a service to add/connect Io within a stage */
/** This is used by Encrypt.scala to connect the trigger signals to the cache
  */
trait ICacheCInvokeIoService {
  def getICacheCInvokeIo(stage: Stage)(implicit cacheConfig: cacheConfig): ICacheCInvokeIo
}

/** Definition of a service to add/connect Io within a stage */
/** This is used by FetcherEncrypt.scala to connect the pcc to the cache
  */
trait ICacheFetchIoService {
  def getICacheFetchIo(stage: Stage)(implicit cacheConfig: cacheConfig): ICacheFetchIo
}

/** Definition of a service to add/connect Io to another pipeline component */
/** This is used by AESCntrlSelector.scala to connect the instruction cache to the AES. Uses the AES
  * IO definition
  */
trait ICacheAESIoService {
  def getICacheAESIo(component: Component): AES_DecIO // for crypto core
}

/** Definition of a service to add/connect Io to another pipeline component */
/** This is used by both caches to connect to each other.
  */
trait CacheEncryptIoService {
  def getCacheEncryptIo(component: Component)(implicit cacheConfig: cacheConfig): CacheEncryptIo
}

/** component placed inside the pipeline area */
/** pass through generics as implicit */
/** getIo body of KeyGenWrapperService is fully defined */
class InstructionCacheEncrypt(aes_DecConfig: AES_DecConfig, aes_EncConfig: AES_EncConfig)(implicit
    context: cheri.Context,
    cacheConfig: cacheConfig,
    encryptConfig: EncryptConfig,
    tableConfig: table.TableConfig
) extends Plugin[Pipeline]
    with ICacheIbusIoService
    with ICacheAESIoService
    with ICacheCInvokeIoService
    with ICacheFetchIoService
    with CacheEncryptIoService {

  /** CacheIbus IO */
  private var CacheIbusComponentIo: ICacheIbusIo = _
  private var CacheIbusStageIo: Option[ICacheIbusIo] = None

  /** CacheAESbus IO */
  private var CacheAESComponentIo: AES_DecIO = _ // for crypto core
  private var CacheAESSlaveIo: Option[AES_DecIO] = None // for crypto core

  /** CacheCInvokebus IO */
  private var CacheCInvokeComponentIo: ICacheCInvokeIo = _
  private var CacheCInvokeStageIo: Option[ICacheCInvokeIo] = None

  /** CacheFetchbus IO */
  private var CacheFetchComponentIo: ICacheFetchIo = _
  private var CacheFetchStageIo: Option[ICacheFetchIo] = None

  /** CacheEncrypt IO */
  private var CacheEncryptComponentIo: CacheEncryptIo = _
  private var CacheEncryptMasterIo: Option[CacheEncryptIo] = None
  override def build(): Unit = {

    /** Add a new component to the pipeline area */
    val component = pipeline plug new Component {
      setDefinitionName("InstructionCacheEncrypt")

      /** INPUTS/OUTPUTS */
      /** IO to Ibus component in pipeline area io (master). can't pass ibus as config as don't know
        * what that is here
        */
      val ibusCache = master(ICacheIbusIo(context.config.ibusConfig, idWidth = 0 bits))

      /** trigger inputs - slave for inputs */
      val CInvokeCache = slave(ICacheCInvokeIo(aes_DecConfig))

      /** Fetch inputs - slave for inputs */
      val fetchPCCCache = slave(ICacheFetchIo())

      /** IO to AES - dec only */
      val aesCache_dec = master(AES_DecIO(aes_DecConfig)) // for crypto core

      /** IO to other cache */
      val encryptCache = slave(CacheEncryptIo())

      /** END INPUTS/OUTPUTS */

      /** route through cache control */
      val cacheControl =
        new cacheController3(context.config.dbusConfig, aes_DecConfig, aes_EncConfig)

      /** IO to keyGenWrapper2 for saving IVcount during writeback */
      /** We don't need to do this on the instruction side so we set fixed driving signals to always
        * done because the cache controller still enters the store state at the end
        */
      // ToDo might be able to change controller so it doesn't enter this state for the instruction side
      cacheControl.keyGenWrapper.IVcountsavedDone := True
      cacheControl.keyGenWrapper.table_error := False

      /** raise exception if decrypt error */
      /** this needs to feed into a stage - memory stage in order to be able to run the exception
        * code
        */
      CInvokeCache.decrypt_error := aesCache_dec.tag_error // | cacheControl.keyGenWrapper.decrypt_error

      /** we need to pass in full dbus to allow cacheController block to be compatible with
        * instruction cache and data cache. But we can set those unused for the instruction cache to
        * fixed default values to/from fetch stage
        */
      cacheControl.busCache.dbusCacheStage.cmd.valid := ibusCache.ibusCacheFetch.cmd.valid
      cacheControl.busCache.dbusCacheStage.cmd.ready <> ibusCache.ibusCacheFetch.cmd.ready
      cacheControl.busCache.dbusCacheStage.cmd.payload.address := ibusCache.ibusCacheFetch.cmd.payload.address
      cacheControl.busCache.dbusCacheStage.cmd.payload.id := ibusCache.ibusCacheFetch.cmd.payload.id

      /** fixed default values */
      cacheControl.busCache.dbusCacheStage.cmd.payload.write := False // default to read
      cacheControl.busCache.dbusCacheStage.cmd.payload.wmask := 0xf
      cacheControl.busCache.dbusCacheStage.cmd.payload.wdata := 0x0
      cacheControl.busCache.dbusCacheStage.rsp <> ibusCache.ibusCacheFetch.rsp

      /** to/from AXI */
      cacheControl.busCache.dbusCacheAXI.cmd.valid <> ibusCache.ibusCacheAXI.cmd.valid
      cacheControl.busCache.dbusCacheAXI.cmd.ready <> ibusCache.ibusCacheAXI.cmd.ready
      cacheControl.busCache.dbusCacheAXI.cmd.payload.address <> ibusCache.ibusCacheAXI.cmd.payload.address
      cacheControl.busCache.dbusCacheAXI.cmd.payload.id <> ibusCache.ibusCacheAXI.cmd.payload.id
      cacheControl.busCache.dbusCacheAXI.rsp <> ibusCache.ibusCacheAXI.rsp

      /** control signals */
      cacheControl.busCache.cmdSelect <> ibusCache.cmdSelect
      cacheControl.busCache.rspSelect <> ibusCache.rspSelect
      cacheControl.busCache.stageRspReady <> ibusCache.fetchRspReady
      cacheControl.busCache.axiRspValid <> ibusCache.axiRspValid

      /** IO to cache control CInvoke */
      cacheControl.CInvokeCache.invokeTrigger := CInvokeCache.invokeTrigger

      /** PCC bounds to check PCC against in Fetch stage */
      cacheControl.CInvokeCache.PCCboundsBase := CInvokeCache.PCCboundsBase
      cacheControl.CInvokeCache.PCCboundsTop := CInvokeCache.PCCboundsTop

      /** PCC bounds to check cmdAddress */
      cacheControl.CInvokeCache.cmdAddrboundsBase := CInvokeCache.cmdAddrboundsBase
      cacheControl.CInvokeCache.cmdAddrboundsTop := CInvokeCache.cmdAddrboundsTop

      /** needed for readcacheline / writebackcacheline - gives cap length */
      cacheControl.CInvokeCache.cmdAddrboundsLen := CInvokeCache.cmdAddrboundsLen

      /** key */
      cacheControl.CInvokeCache.Key := CInvokeCache.Key

      /** otype - needed for writeback, not used instruction side */
      cacheControl.CInvokeCache.otype := CInvokeCache.otype

      /** nextIVCount - needed for writeback, not used instruction side */
      cacheControl.CInvokeCache.NextIVCount := CInvokeCache.NextIVCount

      /** IO to cache from Fetch stage PCC */
      cacheControl.fetchPCCCache.pccBase := fetchPCCCache.pccBase
      cacheControl.fetchPCCCache.pccTop := fetchPCCCache.pccTop
      cacheControl.fetchPCCCache.pccLength := fetchPCCCache.pccLength // ToDo don't need this now, need to use length above

      /** IO to AESCntrlSelector to AES_DEC */
      cacheControl.aesCache_dec <> aesCache_dec

      /** IO to AESCntrlSelector to AES_ENC */
      /** Not used on the instruction side so we set default driving signals here */
      cacheControl.aesCache_enc.cmd.ready := False
      cacheControl.aesCache_enc.busy := True
      cacheControl.aesCache_enc.aes_done := False
      cacheControl.aesCache_enc.rsp.valid := False
      cacheControl.aesCache_enc.rsp.payload.assignDontCare()

      /** IO to data cache - slave side */
      /** We need to swap signals: thisCache input from data cache becomes otherCache because this
        * is the slave side. Also thisCache output from instruction cache becomes otherCache output
        * to the data cache input.
        */
      /** signals to IO */
      /** output to data cache (data cache doesn't need to wait for instruction cache) */
      encryptCache.otherCacheNotFinished := False // fix to say instruction cache always finished so don't need to wait */

      /** signals to cache controller */
      /** input from data cache (instruction cache does need to wait for data cache) */
      /** cacheControl.otherCache.otherCacheNotFinished := False // fix to say data cache always
        * finished
        */
      cacheControl.otherCache.otherCacheNotFinished := encryptCache.thisCacheNotFinished // from data cache output
    }

    /** connect component IO to area */
    CacheIbusComponentIo = component.ibusCache
    CacheAESComponentIo = component.aesCache_dec
    CacheCInvokeComponentIo = component.CInvokeCache
    CacheFetchComponentIo = component.fetchPCCCache
    CacheEncryptComponentIo = component.encryptCache
  }

  /** In the pipeline area connect to stage /another component */
  override def finish(): Unit = {
    pipeline plug new Area {
      CacheIbusStageIo.foreach(io => CacheIbusComponentIo <> io)
      CacheAESSlaveIo.foreach(io => CacheAESComponentIo <> io)
      CacheCInvokeStageIo.foreach(io => CacheCInvokeComponentIo <> io)
      CacheFetchStageIo.foreach(io => CacheFetchComponentIo <> io)
      CacheEncryptMasterIo.foreach(io => CacheEncryptComponentIo <> io)
    }
  }

  /** Definition of a service to add/connect Io within a stage */
  /** This is used by FetcherEncrypt.scala to connect the ibus control selector to the instruction
    * cache.
    */
  override def getICacheIbusIo(
      stage: Stage,
      ibusConfig: MemBusConfig,
      idWidth: BitCount
  ): ICacheIbusIo = {

    assert(CacheIbusStageIo.isEmpty)

    /** add Io to stage area */
    val stageArea = stage plug new Area {
      val io = slave(ICacheIbusIo(ibusConfig, idWidth))
    }
    CacheIbusStageIo = Some(stageArea.io)
    stageArea.io
  }

  /** Definition of a service to add/connect Io within a pipeline component */
  /** This is used by AESCntrlSelector.scala to connect the instruction cache to the AES control
    * selector.
    */
  override def getICacheAESIo(component: Component): AES_DecIO = {
    assert(CacheAESSlaveIo.isEmpty)

    /** add Io to component area */
    val area = component plug new Area {
      val io = slave(AES_DecIO(aes_DecConfig)) // for crypto core
    }
    CacheAESSlaveIo = Some(area.io)
    area.io
  }

  /** Definition of a service to add/connect Io within a stage */

  /** This is used by Encrypt.scala to connect the trigger signals to the cache
    */
  override def getICacheCInvokeIo(
      stage: Stage
  )(implicit cacheConfig: cacheConfig): ICacheCInvokeIo = {

    assert(CacheCInvokeStageIo.isEmpty)

    /** add Io to stage area */
    val stageArea = stage plug new Area {
      val io = master(ICacheCInvokeIo(aes_DecConfig))
    }
    CacheCInvokeStageIo = Some(stageArea.io)
    stageArea.io
  }

  /** This is used by FetcherEncrypt.scala to connect the pcc to the cache
    */
  override def getICacheFetchIo(stage: Stage)(implicit
      cacheConfig: cacheConfig
  ): ICacheFetchIo = {

    assert(CacheFetchStageIo.isEmpty)

    /** add Io to stage area */
    val stageArea = stage plug new Area {
      val io = master(ICacheFetchIo())
    }
    CacheFetchStageIo = Some(stageArea.io)
    stageArea.io
  }

  /** Definition of a service to add/connect Io within a pipeline component */

  /** This is used by both caches to connect the instruction cache controller to the data cache
    * controller.
    */
  override def getCacheEncryptIo(
      component: Component
  )(implicit cacheConfig: cacheConfig): CacheEncryptIo = {
    assert(CacheEncryptMasterIo.isEmpty)

    /** add Io to component area */
    val area = component plug new Area {
      val io = master(CacheEncryptIo())
    }
    CacheEncryptMasterIo = Some(area.io)
    area.io
  }

}
