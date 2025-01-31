package riscv.plugins.cheriEncrypt

import riscv._
import riscv.plugins.cheri
import spinal.core._
import spinal.lib._

/** ibus control selector to select between normal operation and encryption controlled (for an
  * instruction encryption cache)
  */
/** ibusCntrlSelector component. */
/** (ibus used for config info) */
class ibusCntrlSelector(ibus: MemBus) extends Component {
  setDefinitionName("ibusCntrlSelector")

  /** ---------------------------------------------------------------------- */
  /** INPUTS/OUTPUTS */
  /** declare inputs and outputs to Fetcher and ibus */
  /** don't need bundle here as MemBus extends Bundle with IMaster Slave so just need to say if
    * master or slave
    */
  val ibusFetch = slave(MemBus(ibus.config, ibus.idWidth)) // ibus input from Fetch stage
  val ibusAXI = master(MemBus(ibus.config, ibus.idWidth)) // output to ibus for axi

  /** declare inputs and outputs to encryption cache */
  val ibusCache = slave(ICacheIbusIo(ibus.config, ibus.idWidth))

  /** ---------------------------------------------------------------------- */

  /** signals to check when response in progress finished */
  ibusCache.fetchRspReady := ibusFetch.rsp.ready
  ibusCache.axiRspValid := ibusAXI.rsp.valid

  /** route to cache */
  when(ibusCache.cmdSelect) {
    ibusAXI.cmd <> ibusCache.ibusCacheAXI.cmd
    ibusFetch.cmd <> ibusCache.ibusCacheFetch.cmd
  } otherwise {

    /** route straight through */
    ibusAXI.cmd <> ibusFetch.cmd

    /** invalidate driving signals to cache */
    ibusCache.ibusCacheAXI.cmd.ready := False
    ibusCache.ibusCacheFetch.cmd.valid := False
    ibusCache.ibusCacheFetch.cmd.payload.assignDontCare()
  }

  /** route to cache */
  when(ibusCache.rspSelect) {
    ibusAXI.rsp <> ibusCache.ibusCacheAXI.rsp
    ibusFetch.rsp <> ibusCache.ibusCacheFetch.rsp
  } otherwise {

    /** route straight through */
    ibusAXI.rsp <> ibusFetch.rsp

    /** invalidate driving signals to cache */
    ibusCache.ibusCacheAXI.rsp.valid := False
    ibusCache.ibusCacheAXI.rsp.payload.assignDontCare()
    ibusCache.ibusCacheFetch.rsp.ready := False
  }

}
