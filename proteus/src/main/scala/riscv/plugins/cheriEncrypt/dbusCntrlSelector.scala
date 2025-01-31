package riscv.plugins.cheriEncrypt

import riscv._
import riscv.plugins.cheri
import spinal.core._
import spinal.lib._

/** dbus control selector to select between normal operation and encryption controlled (for an data
  * encryption cache)
  */
/** dbusCntrlSelector component. */
/** (dbus used for config info) */
class dbusCntrlSelector(dbus: MemBus)(implicit context: cheri.Context) extends Component {
  setDefinitionName("dbusCntrlSelector")

  /** ---------------------------------------------------------------------- */
  /** INPUTS AND OUTPUTS */

  /** IO databus from memory stage, out to AXI */
  /** don't need bundle here as MemBus extends Bundle with IMaster Slave so just need to say if
    * master or slave
    */
  val dbusMem = slave(MemBus(dbus.config, dbus.idWidth)) // dbus from Memory stage via Tagger
  val dbusAXI = master(MemBus(dbus.config, dbus.idWidth)) // dbus out to axi

  /** IO to encryption data cache */
  val dbusCache = slave(DCacheDbusIo(dbus.config, dbus.idWidth))

  /** IO to CSealEReadWrite */
  val dbusCSealE = slave(CSealEDbusIo(dbus.config, dbus.idWidth))

  /** ---------------------------------------------------------------------- */

  /** Intermediate Databus between AXI MUX */
  private var DbusIntAXI: MemBus = _
  DbusIntAXI = MemBus(dbus.config, dbus.idWidth).setName("DbusIntAXI")

  /** Intermediate Databus between MEM MUX */
  private var DbusIntMem: MemBus = _
  DbusIntMem = MemBus(dbus.config, dbus.idWidth).setName("DbusIntMem")

  /** signals to check when response in progress finished */
  dbusCache.stageRspReady := dbusMem.rsp.ready
  dbusCache.axiRspValid := dbusAXI.rsp.valid

  /** InvokeSelect data cache MUX selector */
  /** cmd */
  when(dbusCache.cmdSelect) {

    /** when encryption (after a CInvokeEncrypt) route via data Cache */
    dbusAXI.cmd <> dbusCache.dbusCacheAXI.cmd
    dbusMem.cmd <> dbusCache.dbusCacheStage.cmd

    /** invalidate intermediate driving signals to memory */
    DbusIntMem.cmd.payload.assignDontCare()
    DbusIntMem.cmd.valid := False

    /** invalidate driving signals to AXI */
    DbusIntAXI.cmd.ready := False

  } otherwise {

    /** gets confused over direction for intermediate so write out in full */
    dbusAXI.cmd.payload := DbusIntAXI.cmd.payload
    dbusAXI.cmd.valid := DbusIntAXI.cmd.valid
    DbusIntAXI.cmd.ready := dbusAXI.cmd.ready

    DbusIntMem.cmd.payload := dbusMem.cmd.payload
    DbusIntMem.cmd.valid := dbusMem.cmd.valid
    dbusMem.cmd.ready := DbusIntMem.cmd.ready

    /** invalidate driving signals to cache */
    dbusCache.dbusCacheAXI.cmd.ready := False

    /** invalidate driving signals to memory */
    dbusCache.dbusCacheStage.cmd.valid := False
    dbusCache.dbusCacheStage.cmd.payload.assignDontCare()
  }

  /** InvokeSelect data cache MUX selector */
  /** rsp */
  when(dbusCache.rspSelect) {

    /** when encryption (after a CInvokeEncrypt) route via data Cache */
    dbusAXI.rsp <> dbusCache.dbusCacheAXI.rsp
    dbusMem.rsp <> dbusCache.dbusCacheStage.rsp

    /** invalidate intermediate driving signals to memory */
    DbusIntMem.rsp.ready := False

    /** invalidate driving signals to AXI */
    DbusIntAXI.rsp.payload.assignDontCare()
    DbusIntAXI.rsp.valid := False

  } otherwise {

    /** gets confused over direction for intermediate so write out in full */
    dbusAXI.rsp.ready := DbusIntAXI.rsp.ready
    DbusIntAXI.rsp.payload := dbusAXI.rsp.payload
    DbusIntAXI.rsp.valid := dbusAXI.rsp.valid

    DbusIntMem.rsp.ready := dbusMem.rsp.ready
    dbusMem.rsp.payload := DbusIntMem.rsp.payload
    dbusMem.rsp.valid := DbusIntMem.rsp.valid

    /** invalidate driving signals to cache */
    dbusCache.dbusCacheAXI.rsp.valid := False
    dbusCache.dbusCacheAXI.rsp.payload.assignDontCare()

    /** invalidate driving signals to memory */
    dbusCache.dbusCacheStage.rsp.ready := False
  }

  /** CSealESelect MUX selector */
  when(dbusCSealE.CSealSelect) {

    /** when encryption (during CSealEncrypt) route via CSealEReadWrite */
    // DbusIntAXI <> dbusCSealE.dbusCSealAXI

    /** gets confused over direction for intermediate so write out in full */
    DbusIntAXI.cmd.payload := dbusCSealE.dbusCSealAXI.cmd.payload
    DbusIntAXI.cmd.valid := dbusCSealE.dbusCSealAXI.cmd.valid
    DbusIntAXI.rsp.ready := dbusCSealE.dbusCSealAXI.rsp.ready
    dbusCSealE.dbusCSealAXI.rsp.payload := DbusIntAXI.rsp.payload
    dbusCSealE.dbusCSealAXI.rsp.valid := DbusIntAXI.rsp.valid
    dbusCSealE.dbusCSealAXI.cmd.ready := DbusIntAXI.cmd.ready

    /** invalidate driving signals to memory */
    DbusIntMem.rsp.payload.assignDontCare()
    DbusIntMem.rsp.valid := False
    DbusIntMem.cmd.ready := False

  } otherwise {

    /** when no encryption route straight through */
    // DbusIntAXI <> DbusIntMem

    /** gets confused over direction for intermediate so write out in full */
    DbusIntAXI.cmd.payload := DbusIntMem.cmd.payload
    DbusIntAXI.cmd.valid := DbusIntMem.cmd.valid
    DbusIntAXI.rsp.ready := DbusIntMem.rsp.ready
    DbusIntMem.rsp.payload := DbusIntAXI.rsp.payload
    DbusIntMem.rsp.valid := DbusIntAXI.rsp.valid
    DbusIntMem.cmd.ready := DbusIntAXI.cmd.ready

    /** invalidate driving signals to CSealEReadWrite */
    dbusCSealE.dbusCSealAXI.cmd.ready := False
    dbusCSealE.dbusCSealAXI.rsp.valid := False
    dbusCSealE.dbusCSealAXI.rsp.payload.assignDontCare()

  }

}
