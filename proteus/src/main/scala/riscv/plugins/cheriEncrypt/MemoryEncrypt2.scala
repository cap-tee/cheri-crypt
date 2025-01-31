package riscv.plugins.cheriEncrypt

/** This is the memory encryption block that goes between the dbus pipeline interface and the memory
  * stage
  *
  * It uses pipeline.service[MemoryService].filterDBus to cut the dbus and insert the encryption
  * block. Since this process can only be done once the block also includes the cheri Memory Tagger
  * which previously formed the block between the dbus pipeline interface and the memory stage
  *
  * The Memory Tagger itself has been made into a component which is inserted into the wrapper
  * encryption block. The Memory Tagger connects to the DbusCntrlSelector component via an
  * intermediate dBus.
  */

import riscv._
import riscv.plugins.cheri
import riscv.plugins.cheri.{CapBus, TaggedMemoryService}
import spinal.core._
import spinal.lib._

class MemoryEncrypt2(memoryStart: BigInt, memorySize: BigInt)(implicit context: cheri.Context)
    extends Plugin[Pipeline]
    with TaggedMemoryService {
  assert(memorySize % (context.clen / 8) == 0)

  /** connection of master and slave capability bus defined in 'def finish' below */
  private var masterCapBus: CapBus = _
  private var slaveCapBus: CapBus = _

  /** Databus between components */
  /** out Tagger, in DbusCntrlSelector */
  private var DbusIntermediate: MemBus = _

  /** connection of master and slave defined in 'def finish' below */
  private var masterDCacheDbusIo: DCacheDbusIo = _
  private var slaveDCacheDbusIo: DCacheDbusIo = _
  private var masterCSealEDbusIo: CSealEDbusIo = _
  private var slaveCSealEDbusIo: CSealEDbusIo = _

  override def build(): Unit = {

    /** uses pipeline.service[MemoryService].filterDBus to cut the dbus */
    /** can only perform this cut once! */
    /** so we need to build all the components here that use the databus in `pipeline` outside the
      * memory stage
      */
    pipeline.service[MemoryService].filterDBus { (stage, dbusIn, dbusOut) =>
      /** set the name of the buses */
      slaveCapBus = CapBus().setName("cbus")
      DbusIntermediate = MemBus(dbusIn.config, dbusIn.idWidth).setName("intermediate_dbus")
      slaveDCacheDbusIo = DCacheDbusIo(dbusIn.config, dbusIn.idWidth).setName("DCacheDbusIo")
      slaveCSealEDbusIo = CSealEDbusIo(dbusIn.config, dbusIn.idWidth).setName("CSealEDbusIo")

      /** connect Tagger and DbusCntrlSelector via Dbus (DbusIntermediate) */
      buildTagger(stage, dbusIn, slaveCapBus, DbusIntermediate)
      buildDbusCntrlSelector(stage, DbusIntermediate, dbusOut, slaveDCacheDbusIo, slaveCSealEDbusIo)
    }
  }

  /** create pipeline area for DbusCntrlSelector component */
  /** This component is closest to pipeline interface */
  def buildDbusCntrlSelector(
      stage: Stage,
      dbusIn: MemBus,
      dbusOut: MemBus,
      dbusCache: DCacheDbusIo,
      dbusCSealE: CSealEDbusIo
  ): Unit = {

    /** Create a new component in the pipeline */
    val component = pipeline plug new Component {
      setDefinitionName("DbusCntrlSelectorTop")

      /** IO to encryption cache - slave */
      val dbusCache =
        pipeline.service[DCacheDbusIoService].getDCacheDbusIo(this, dbusIn.config, dbusIn.idWidth)

      /** IO to CSealEReadWrite - slave */
      val dbusCSealE =
        pipeline.service[CSealEDbusIoService].getCSealEDbusIo(this, dbusIn.config, dbusIn.idWidth)

      val dBusMem = slave(MemBus(dbusIn.config, dbusIn.idWidth))

      val dBusAXI = master(MemBus(dbusIn.config, dbusIn.idWidth))

      /** add dbusSelector component */
      val dbusSelector = new dbusCntrlSelector(dbusOut)

      dbusCSealE <> dbusSelector.dbusCSealE
      dbusCache <> dbusSelector.dbusCache
      dBusMem <> dbusSelector.dbusMem
      dBusAXI <> dbusSelector.dbusAXI

    }

    /** route straight through - this needs to go outside of component */
    component.dBusMem <> dbusIn
    dbusOut <> component.dBusAXI

  }

  /** create pipeline area for Tagger component */
  /** This component is furthest from pipeline interface in terms of the databus */
  def buildTagger(stage: Stage, dbusIn: MemBus, cbusIn: CapBus, dbusOut: MemBus): Unit = {

    /** Create a new area in the pipeline */
    pipeline plug new Area {

      /** instantiate Tagger component */
      /** dbusOut passed to get generics */
      val tagger = new Tagger(memoryStart, memorySize, dbusOut)

      /** assign def buildTagger IO to component IO */
      tagger.dbusIn <> dbusIn
      tagger.dbusOut <> dbusOut
      tagger.cbusIn <> cbusIn

    }
  }

  /** plugin class def */
  /** autoconnect the master side to the slave side of the CapBus */
  override def finish(): Unit = {
    pipeline plug {
      masterCapBus <> slaveCapBus
    }
  }

  /** TaggedMemoryService trait def */
  /** The capBus is created in Lsu.scala */
  /** val cbus = pipeline.service[TaggedMemoryService].createCapBus(stage) */
  /** The master side of the bus is created here (in Lsu.scala) */
  override def createCapBus(stage: Stage): CapBus = {
    assert(masterCapBus == null)

    stage plug {
      masterCapBus = master(CapBus()).setName("cbus")
    }

    masterCapBus
  }

}
