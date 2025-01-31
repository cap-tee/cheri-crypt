package riscv.plugins.cheriEncrypt

import AESEngine._
import spinal.core._
import spinal.lib._
import riscv._
import riscv.plugins.cheri

/** This is the Data Cache encryption component that goes in the pipeline area and connects to the
  * AES control selector and the Dbus control selector.
  */

/** define input / output signals */
case class DCacheDbusIo(dbusConfig: MemBusConfig, idWidth: BitCount)
    extends Bundle
    with IMasterSlave {
  val dbusCacheStage = MemBus(dbusConfig, idWidth).setName("dbusCacheStage")
  val dbusCacheAXI = MemBus(dbusConfig, idWidth).setName("dbusCacheAXI")
  val cmdSelect = Bool() // select cmd and rsp separately as we need to wait for responses to finish
  val rspSelect = Bool()
  val stageRspReady = Bool() // from dbus memory stage side to know when rsp finished
  val axiRspValid = Bool() // from dbus AXI side to know when rsp finished

  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    out(cmdSelect)
    out(rspSelect)
    in(stageRspReady)
    in(axiRspValid)
    master(dbusCacheAXI)
    slave(dbusCacheStage)
  }
}

/** This is used by AESCntrlSelector.scala to connect the data cache to the AES. Uses the AES IO
  * definition
  */
case class DCacheAESIo(aes_DecConfig: AES_DecConfig, aes_EncConfig: AES_EncConfig)
    extends Bundle
    with IMasterSlave {
  val DCacheAES_DEC = AES_DecIO(aes_DecConfig) // for crypto core
  val DCacheAES_ENC = AES_EncIO(aes_EncConfig) // for crypto core

  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    master(DCacheAES_DEC, DCacheAES_ENC)
  }
}

/** Input from CInvokeEncrypt to enable and disable the cache */
case class DCacheCInvokeIo(aes_DecConfig: AES_DecConfig)(implicit
    cacheConfig: cacheConfig,
    tableConfig: table.TableConfig
) extends Bundle
    with IMasterSlave {
  val invokeTrigger = Bool() // enable cache into dbus
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
    // ToDo change format so invoke trigger is a valid signal as part of a flow
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

/** Input from Fetch stage to check the current DC against the CInvoke bounds and enable/disable the
  * cache
  */
case class DCacheFetchIo(implicit cacheConfig: cacheConfig) extends Bundle with IMasterSlave {
  val pccBase = UInt(cacheConfig.addrWidth) // lower dc bounds
  val pccTop = UInt(cacheConfig.addrWidth) // upper dc bounds
  val pccLength = UInt(cacheConfig.addrWidth) // length bounds
  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    out(pccBase)
    out(pccTop)
    out(pccLength)
  }
}

/** Definition of a service to add/connect Io within a stage */
/** This is used by memoryEncrypt2.scala to connect the dbus control selector to the data cache.
  */
trait DCacheDbusIoService {
  def getDCacheDbusIo(
      component: Component,
      dbusConfig: MemBusConfig,
      idWidth: BitCount
  ): DCacheDbusIo
}

/** Definition of a service to add/connect Io within a stage */
/** This is used by CInvokeEncrypt.scala to connect the trigger signals to the cache
  */
trait DCacheCInvokeIoService {
  def getDCacheCInvokeIo(stage: Stage)(implicit cacheConfig: cacheConfig): DCacheCInvokeIo
}

/** Definition of a service to add/connect Io within a stage */
/** Input from Fetch stage to check the current DC against the CInvoke bounds and enable/disable the
  * cache
  */
trait DCacheFetchIoService {
  def getDCacheFetchIo(stage: Stage)(implicit cacheConfig: cacheConfig): DCacheFetchIo
}

/** Definition of a service to add/connect Io to another pipeline component */
/** This is used by AESCntrlSelector.scala to connect the data cache to the AES. Uses the AES IO
  * definition
  */
trait DCacheAESIoService {
  def getDCacheAESIo(component: Component): DCacheAESIo
}

/** component placed inside the pipeline area */
/** pass through generics as implicit */
class DataCacheEncrypt(aes_DecConfig: AES_DecConfig, aes_EncConfig: AES_EncConfig)(implicit
    context: cheri.Context,
    cacheConfig: cacheConfig,
    encryptConfig: EncryptConfig,
    tableConfig: table.TableConfig
) extends Plugin[Pipeline]
    with DCacheDbusIoService
    with DCacheAESIoService
    with DCacheCInvokeIoService
    with DCacheFetchIoService {

  /** CacheIbus IO */
  private var CacheDbusComponentIo: DCacheDbusIo = _
  private var CacheDbusSlaveIo: Option[DCacheDbusIo] = None

  /** CacheAESbus IO */
  private var CacheAESComponentIo: DCacheAESIo = _
  private var CacheAESSlaveIo: Option[DCacheAESIo] = None

  /** CacheCInvokebus IO */
  private var CacheCInvokeComponentIo: DCacheCInvokeIo = _
  private var CacheCInvokeStageIo: Option[DCacheCInvokeIo] = None

  /** CacheFetchbus IO */
  private var CacheFetchComponentIo: DCacheFetchIo = _
  private var CacheFetchStageIo: Option[DCacheFetchIo] = None

  override def build(): Unit = {

    /** Add a new component to the pipeline area */
    val component = pipeline plug new Component {
      setDefinitionName("DataCacheEncrypt")

      /** INPUTS/OUTPUTS */
      /** IO to Dbus component in pipeline area io (master). can't pass dbus as config as don't know
        * what that is here
        */
      val dbusCache = master(DCacheDbusIo(context.config.dbusConfig, idWidth = 0 bits))

      /** trigger inputs - slave for inputs */
      val CInvokeCache = slave(DCacheCInvokeIo(aes_DecConfig))

      /** Fetch inputs - slave for inputs */
      val fetchDCCache = slave(DCacheFetchIo())

      /** IO to AES - enc and dec */
      val aesCache = master(DCacheAESIo(aes_DecConfig, aes_EncConfig))

      /** IO to KeyGenWrapper2 to save out IVCount after final writeback before exit enclave */
      val keyGenWrapper = pipeline.service[CacheUpdateIVIOService].getCacheUpdateIVIo(this)

      /** IO to Instruction cache encrypt */
      /** defined in instructionCacheEncrypt so import as a service */
      val encryptCache = pipeline.service[CacheEncryptIoService].getCacheEncryptIo(this)

      /** END INPUTS/OUTPUTS */

      /** route through cache control */
      val cacheControl =
        new cacheController3(context.config.dbusConfig, aes_DecConfig, aes_EncConfig)

      /** raise exception if decrypt error */
      /** this needs to feed into a stage - memory stage in order to be able to run the exception
        * code
        */
      CInvokeCache.decrypt_error := aesCache.DCacheAES_DEC.tag_error // | cacheControl.keyGenWrapper.decrypt_error

      /** IO to keyGenWrapper2 for saving IVcount during writeback */
      cacheControl.keyGenWrapper <> keyGenWrapper

      // ToDo better signal naming re-use cache controller for data bus as well as instruction bus
      /** bus to memory stage and axi bus */

      cacheControl.busCache <> dbusCache

      /** IO to AESCntrlSelector to AES_DEC */
      cacheControl.aesCache_dec <> aesCache.DCacheAES_DEC

      /** IO to AESCntrlSelector to AES_ENC */
      cacheControl.aesCache_enc <> aesCache.DCacheAES_ENC

      /** IO to cache control CInvoke */
      cacheControl.CInvokeCache.invokeTrigger := CInvokeCache.invokeTrigger

      /** PCC bounds to check PCC against in Fetch stage */
      cacheControl.CInvokeCache.PCCboundsBase := CInvokeCache.PCCboundsBase
      cacheControl.CInvokeCache.PCCboundsTop := CInvokeCache.PCCboundsTop

      /** DC bounds to check cmdAddress */
      cacheControl.CInvokeCache.cmdAddrboundsBase := CInvokeCache.cmdAddrboundsBase
      cacheControl.CInvokeCache.cmdAddrboundsTop := CInvokeCache.cmdAddrboundsTop

      /** needed for readcacheline / writebackcacheline - gives cap length */
      cacheControl.CInvokeCache.cmdAddrboundsLen := CInvokeCache.cmdAddrboundsLen

      /** key */
      cacheControl.CInvokeCache.Key := CInvokeCache.Key

      /** otype */
      cacheControl.CInvokeCache.otype := CInvokeCache.otype

      /** nextIVCount */
      cacheControl.CInvokeCache.NextIVCount := CInvokeCache.NextIVCount

      /** IO to cache from Fetch stage PCC */
      /** We still need to check PCC from fetch stage. We don't need to check DC from the fetch
        * stage, we just need to check the dbus cmdAddress above because there are no pre-fetches
        * here so the cmdAddress will be the exact address that is being processed.
        */
      cacheControl.fetchPCCCache.pccBase <> fetchDCCache.pccBase
      cacheControl.fetchPCCCache.pccTop <> fetchDCCache.pccTop
      cacheControl.fetchPCCCache.pccLength <> fetchDCCache.pccLength

      /** IO to Instruction cache - master side */
      /** signals to IO */
      /** output to instruction cache (instruction cache does need to wait for data cache) */
      /** encryptCache.thisCacheNotFinished := False // fix to say data cache always finished so
        * don't need to wait
        */
      encryptCache.thisCacheNotFinished := cacheControl.otherCache.thisCacheNotFinished // wait for data cache to finish

      /** signals to cache controller */
      /** input from instruction cache (data cache doesn't need to wait for instruction cache) */
      cacheControl.otherCache.otherCacheNotFinished := False // fix to say instruction cache always finished
    }

    /** connect component IO to area */
    CacheDbusComponentIo = component.dbusCache
    CacheAESComponentIo = component.aesCache
    CacheCInvokeComponentIo = component.CInvokeCache
    CacheFetchComponentIo = component.fetchDCCache

  }

  /** In the pipeline area connect to stage /another component */
  override def finish(): Unit = {
    pipeline plug new Area {
      CacheDbusSlaveIo.foreach(io => CacheDbusComponentIo <> io)
      CacheAESSlaveIo.foreach(io => CacheAESComponentIo <> io)
      CacheCInvokeStageIo.foreach(io => CacheCInvokeComponentIo <> io)
      CacheFetchStageIo.foreach(io => CacheFetchComponentIo <> io)
    }
  }

  /** Definition of a service to add/connect Io within a stage */
  /** This is used by FetcherEncrypt.scala to connect the ibus control selector to the instruction
    * cache.
    */
  override def getDCacheDbusIo(
      component: Component,
      dbusConfig: MemBusConfig,
      idWidth: BitCount
  ): DCacheDbusIo = {

    assert(CacheDbusSlaveIo.isEmpty)

    /** add Io to stage area */
    val area = component plug new Area {
      val io = slave(DCacheDbusIo(dbusConfig, idWidth))
    }
    CacheDbusSlaveIo = Some(area.io)
    area.io
  }

  /** Definition of a service to add/connect Io within a pipeline component */
  /** This is used by AESCntrlSelector.scala to connect the instruction cache to the AES control
    * selector.
    */
  override def getDCacheAESIo(component: Component): DCacheAESIo = {
    assert(CacheAESSlaveIo.isEmpty)

    /** add Io to component area */
    val area = component plug new Area {
      val io = slave(DCacheAESIo(aes_DecConfig, aes_EncConfig))
    }
    CacheAESSlaveIo = Some(area.io)
    area.io
  }

  /** Definition of a service to add/connect Io within a stage */

  /** This is used by CInvokeEncrypt.scala to connect the trigger signals to the cache
    */
  override def getDCacheCInvokeIo(
      stage: Stage
  )(implicit cacheConfig: cacheConfig): DCacheCInvokeIo = {

    assert(CacheCInvokeStageIo.isEmpty)

    /** add Io to stage area */
    val stageArea = stage plug new Area {
      val io = master(DCacheCInvokeIo(aes_DecConfig))
    }
    CacheCInvokeStageIo = Some(stageArea.io)
    stageArea.io
  }

  /** This is used by FetcherEncrypt.scala to connect the pcc to the cache
    */
  override def getDCacheFetchIo(
      stage: Stage
  )(implicit cacheConfig: cacheConfig): DCacheFetchIo = {

    assert(CacheFetchStageIo.isEmpty)

    /** add Io to stage area */
    val stageArea = stage plug new Area {
      val io = master(DCacheFetchIo())
    }
    CacheFetchStageIo = Some(stageArea.io)
    stageArea.io
  }

}
