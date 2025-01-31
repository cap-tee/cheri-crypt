package riscv.plugins.cheriEncrypt

import spinal.core._
import spinal.lib._
import riscv._
import riscv.plugins.cheri

/** This is the KeyGenWrapper component that goes in the pipeline area and connects the key
  * generation/management block to the CSealEncrypt and CInvokeEncrypt instruction code, and the
  * dataCacheEncrypt. This is the top level component responsible for key generation and management.
  */

/** define input / output signals for Wrapper component */

/** cseal IO */
/** inputs */
case class KeyCSealCmd(tableConfig: table.TableConfig) extends Bundle {

  /** otype is defined as a UInt in CHERI-proteus */
  val otype = UInt(tableConfig.oTypeWidth bits)
  val NewNextIVCount = Bits(tableConfig.IVWidth)
  val genKey, storeNextIVCount = Bool()
}

/** outputs */
case class KeyCSealRsp(tableConfig: table.TableConfig) extends Bundle {
  val key = Bits(tableConfig.keyWidth)
  val NextIVCount = Bits(tableConfig.IVWidth)
}

/** then use master/slave handshake so can include both in/out signals in one bundle */
case class KeyCSealIO(tableConfig: table.TableConfig) extends Bundle with IMasterSlave {
  val cmd = Flow(KeyCSealCmd(tableConfig))
  val rsp = Flow(KeyCSealRsp(tableConfig))
  val table_error, CSealSelect, IVcountsavedDone = Bool()
  val encrypt_error = Bool()

  /** Set the direction of each bundle from a master point of view */
  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    master(cmd)
    out(CSealSelect)
    out(encrypt_error)

    /** declare inputs for master, so will be outputs for slave */
    slave(rsp)
    in(table_error)
    in(IVcountsavedDone)
  }
}

/** Definition of a service to add/connect KeyGenWrapper2 within a stage */
/** This is used by CSealEncrypt.scala to connect the instruction logic (in memory stage) to the key
  * generator.
  */
trait KeyCSealIOService {
  def getKeyCSealIo(stage: Stage): KeyCSealIO
}

/** cInvoke IO */
/** inputs */
case class KeyCInvokeCmd(tableConfig: table.TableConfig) extends Bundle {

  /** otype is defined as a UInt in CHERI-proteus */
  val otype = UInt(tableConfig.oTypeWidth bits)
  val getKey = Bool()
}

/** outputs */
case class KeyCInvokeRsp(tableConfig: table.TableConfig) extends Bundle {
  val key = Bits(tableConfig.keyWidth)
  val NextIVCount = Bits(tableConfig.IVWidth)
}

/** then use master/slave handshake so can include both in/out signals in one bundle */
case class KeyCInvokeIO(tableConfig: table.TableConfig) extends Bundle with IMasterSlave {
  val cmd = Flow(KeyCInvokeCmd(tableConfig))
  val rsp = Flow(KeyCInvokeRsp(tableConfig))
  val table_error, decrypt_error, CInvokeSelect = Bool()

  /** Set the direction of each bundle from a master point of view */
  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    master(cmd)
    out(decrypt_error, CInvokeSelect)

    /** declare inputs for master, so will be outputs for slave */
    slave(rsp)
    in(table_error)
  }
}

/** Definition of a service to add/connect KeyGenWrapper2 within a stage */
/** This is used by CInvokeEncrypt.scala to connect the instruction logic (in memory stage) to the
  * key generator.
  */
trait KeyCInvokeIOService {
  def getKeyCInvokeIo(stage: Stage): KeyCInvokeIO
}

/** dataCacheEncrypt IO for updating IV after writeback operation */
/** inputs */
case class cacheUpdateIVCmd(tableConfig: table.TableConfig) extends Bundle {

  /** otype is defined as a UInt in CHERI-proteus */
  val otype = UInt(tableConfig.oTypeWidth bits)
  val NewNextIVCount = Bits(tableConfig.IVWidth)
  val storeNextIVCount = Bool()
}

/** outputs */

/** then use master/slave handshake so can include both in/out signals in one bundle */
case class CacheUpdateIVIO(tableConfig: table.TableConfig) extends Bundle with IMasterSlave {
  val cmd = Flow(cacheUpdateIVCmd(tableConfig))
  val IVcountsavedDone = Bool()
  val table_error, decrypt_error, DCacheSelect = Bool()

  /** Set the direction of each bundle from a master point of view */
  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    master(cmd)
    out(DCacheSelect)
    out(decrypt_error)

    /** declare inputs for master, so will be outputs for slave */
    in(table_error)
    in(IVcountsavedDone)
  }
}

/** Definition of a service to add/connect KeyGenWrapper2 within a component */
/** This is used by DataCacheEncrypt.scala to connect to the key generator.
  */
trait CacheUpdateIVIOService {
  def getCacheUpdateIVIo(component: Component): CacheUpdateIVIO
}

/** KeyGenWrapper component placed inside the pipeline area */
/** pass through generics as implicit */
/** getIo body of KeyGenWrapperService is fully defined */
class KeyGenWrapper2(implicit
    keyGenConfig: table.KeyGenConfig,
    tableConfig: table.TableConfig,
    context: cheri.Context
) extends Plugin[Pipeline]
    with KeyCSealIOService
    with KeyCInvokeIOService
    with CacheUpdateIVIOService {

  private var componentIo_KeyCSeal: KeyCSealIO = _
  private var stageIo_KeyCSeal: Option[KeyCSealIO] = None

  private var componentIo_KeyCInvoke: KeyCInvokeIO = _
  private var stageIo_KeyCInvoke: Option[KeyCInvokeIO] = None

  private var componentIo_CacheUpdateIV: CacheUpdateIVIO = _
  private var stageIo_CacheUpdateIV: Option[CacheUpdateIVIO] = None

  override def build(): Unit = {

    /** Add a new component to the pipeline area */
    val component = pipeline plug new Component {
      setDefinitionName("KeyGenWrapper2")

      /** component in pipeline area io (slave) */
      val io_KeyCSeal = slave(KeyCSealIO(tableConfig))
      val io_KeyCInvoke = slave(KeyCInvokeIO(tableConfig))
      val io_CacheUpdateIV = slave(CacheUpdateIVIO(tableConfig)) // from data cache

      /** component BODY HERE */
      /** Since this is just a Wrapper for inserting logic in the pipeline area, insert the actual
        * components here and connect.
        */
      /** use new table from library */
      val tableKeyGenTop = new table.TableKeyGenTop(tableConfig, keyGenConfig)

      /** cseal only inputs */
      tableKeyGenTop.io.cmd.payload.genKey := io_KeyCSeal.cmd.payload.genKey

      /** cseal/cinvoke/dcache inputs */
      when(io_KeyCSeal.CSealSelect) {

        /** cseal */
        tableKeyGenTop.io.cmd.payload.otype := io_KeyCSeal.cmd.payload.otype
        tableKeyGenTop.io.cmd.payload.storeNextIVCount := io_KeyCSeal.cmd.payload.storeNextIVCount
        tableKeyGenTop.io.cmd.payload.NewNextIVCount := io_KeyCSeal.cmd.payload.NewNextIVCount
      } elsewhen (io_KeyCInvoke.CInvokeSelect) {

        /** cinvoke */
        tableKeyGenTop.io.cmd.payload.otype := io_KeyCInvoke.cmd.payload.otype
        tableKeyGenTop.io.cmd.payload.storeNextIVCount := False // not used
        tableKeyGenTop.io.cmd.payload.NewNextIVCount := 0x0 // not used
      } otherwise {

        /** dcache */
        tableKeyGenTop.io.cmd.payload.otype := io_CacheUpdateIV.cmd.payload.otype
        tableKeyGenTop.io.cmd.payload.storeNextIVCount := io_CacheUpdateIV.cmd.payload.storeNextIVCount
        tableKeyGenTop.io.cmd.payload.NewNextIVCount := io_CacheUpdateIV.cmd.payload.NewNextIVCount
      }
      tableKeyGenTop.io.cmd.valid := io_KeyCSeal.cmd.valid | io_KeyCInvoke.cmd.valid | io_CacheUpdateIV.cmd.valid
      // ToDo feedback decrypt error signal from icache
      /** encryption errors from (1)cSealEncrypt due to length errors, (2) decryption tag errors */
      tableKeyGenTop.io.decrypt_error := io_CacheUpdateIV.decrypt_error | io_KeyCSeal.encrypt_error | io_KeyCInvoke.decrypt_error // | io_iCache.decrypt_error

      /** cinvoke only inputs */
      tableKeyGenTop.io.cmd.payload.getKey := io_KeyCInvoke.cmd.payload.getKey

      /** cseal outputs */
      io_KeyCSeal.rsp.payload.NextIVCount := tableKeyGenTop.io.rsp.payload.NextIVCount
      io_KeyCSeal.rsp.payload.key := tableKeyGenTop.io.rsp.payload.key
      io_KeyCSeal.rsp.valid := io_KeyCSeal.CSealSelect & tableKeyGenTop.io.rsp.valid
      io_KeyCSeal.table_error := tableKeyGenTop.io.error
      io_KeyCSeal.IVcountsavedDone := io_KeyCSeal.CSealSelect & tableKeyGenTop.io.IVcountsavedDone

      /** cinvoke outputs */
      io_KeyCInvoke.rsp.valid := io_KeyCInvoke.CInvokeSelect & tableKeyGenTop.io.rsp.valid
      io_KeyCInvoke.rsp.payload.key := tableKeyGenTop.io.rsp.payload.key
      io_KeyCInvoke.rsp.payload.NextIVCount := tableKeyGenTop.io.rsp.payload.NextIVCount
      io_KeyCInvoke.table_error := tableKeyGenTop.io.error

      /** dcache outputs */
      io_CacheUpdateIV.IVcountsavedDone := io_CacheUpdateIV.DCacheSelect & tableKeyGenTop.io.IVcountsavedDone
      io_CacheUpdateIV.table_error := tableKeyGenTop.io.error
    }

    /** connect component IO to area */
    componentIo_KeyCSeal = component.io_KeyCSeal
    componentIo_KeyCInvoke = component.io_KeyCInvoke
    componentIo_CacheUpdateIV = component.io_CacheUpdateIV
  }

  override def finish(): Unit = {
    pipeline plug new Area {
      stageIo_KeyCSeal.foreach(io => componentIo_KeyCSeal <> io)
      stageIo_KeyCInvoke.foreach(io => componentIo_KeyCInvoke <> io)
      stageIo_CacheUpdateIV.foreach(io => componentIo_CacheUpdateIV <> io)
    }
  }

  /** Definition of a service to add/connect KeyGenWrapperIo within a stage */
  /** This is used by CSealEncrypt.scala to connect the instruction logic (in memory stage) to the
    * key generator.
    */

  override def getKeyCSealIo(stage: Stage): KeyCSealIO = {
    assert(stageIo_KeyCSeal.isEmpty)

    /** add KeyGenWrapperIo to stage area */
    val stageArea = stage plug new Area {

      val io_KeyCSeal = master(KeyCSealIO(tableConfig))

    }

    stageIo_KeyCSeal = Some(stageArea.io_KeyCSeal)
    stageArea.io_KeyCSeal
  }

  /** Definition of a service to add/connect KeyGenWrapper2 within a stage */
  /** This is used by CInvokeEncrypt.scala to connect the instruction logic (in memory stage) to the
    * key generator.
    */
  override def getKeyCInvokeIo(stage: Stage): KeyCInvokeIO = {
    assert(stageIo_KeyCInvoke.isEmpty)

    /** add KeyGenWrapperIo to stage area */
    val stageArea = stage plug new Area {

      val io_KeyCInvoke = master(KeyCInvokeIO(tableConfig))

    }

    stageIo_KeyCInvoke = Some(stageArea.io_KeyCInvoke)
    stageArea.io_KeyCInvoke
  }

  /** Definition of a service to add/connect KeyGenWrapper2 within a component */
  /** This is used by DataCacheEncrypt.scala to connect to the key generator.
    */
  override def getCacheUpdateIVIo(component: Component): CacheUpdateIVIO = {
    assert(stageIo_CacheUpdateIV.isEmpty)

    /** add KeyGenWrapperIo to component area */
    val area = component plug new Area {
      val io_CacheUpdateIV = master(CacheUpdateIVIO(tableConfig))

    }

    stageIo_CacheUpdateIV = Some(area.io_CacheUpdateIV)
    area.io_CacheUpdateIV
  }

}
