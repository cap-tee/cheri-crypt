package riscv.plugins.cheriEncrypt

/** This is the Fetch stage that has been modified to add an ibus control selector to select between
  * normal operation and encryption controlled (for an instruction encryption cache)
  */

import riscv._
import riscv.Stage
import riscv.plugins.cheri.PccService
import riscv.plugins.{Fetcher, cheri}
import spinal.core._
import spinal.lib._

/** Need to pass the fetchStage and ibusLatency through to Fetch Stage */
class FetcherEncrypt(fetchStage: Stage, ibusLatency: Int = 2)(implicit
    context: cheri.Context,
    cacheConfig: cacheConfig
) extends Fetcher(fetchStage, ibusLatency) {

  private var addressTranslator = new FetchAddressTranslator {
    override def translate(stage: Stage, address: UInt): UInt = {
      address
    }
  }

  private var addressTranslatorChanged = false

  override def build(): Unit = {

    /** create an area in the fetch stage for the fetch logic/components */
    fetchStage plug new Area {
      import fetchStage._

      /** Get the PCC of the Fetch stage, this needs routing out to the cache to check the current
        * PCC against the CInvokeEncrypt set bounds. See services.scala and PCCManager.Scala for the
        * service definition and implementation.
        */

      val fetchPCC = pipeline.service[PccService].getPcc(fetchStage)

      /** this is the bus used to connect the fetch pcc to the cache. See instructionCacheEncrypt
        * for service definition and implementation.
        */
      val fetchICache =
        pipeline.service[ICacheFetchIoService].getICacheFetchIo(fetchStage)

      fetchICache.pccBase := fetchPCC.base
      fetchICache.pccTop := fetchPCC.top
      fetchICache.pccLength := fetchPCC.length

      val fetchDCache =
        pipeline.service[DCacheFetchIoService].getDCacheFetchIo(fetchStage)

      fetchDCache.pccBase := fetchPCC.base
      fetchDCache.pccTop := fetchPCC.top
      fetchDCache.pccLength := fetchPCC.length

      /** Insert a component between IBusControl and ibus going to outside of pipeline */
      // Note IBusControl is the driving force,
      // so IbusIntermediate is the master, IbusCntrlSelector input is slave
      // IbusCntrlSelector output is Master for the ibus (ibus created as master)
      // ibusCache is the control and buses IO to encryption logic / cache
      // -----------------------                     --------------------------------------
      // | IBusControl (master) | -ibusIntermediate->| (slave) IbusCntrlSelector (master) | --> ibus (master)
      // |                      |                    |            (master)
      // -----------------------                     --------------------------------------
      //                                                             ^
      //                                                             |
      //                                                         ibusCache

      /** create standard ibus (this is master) */
      val ibus = pipeline.service[MemoryService].createInternalIBus(fetchStage)

      /** First add an intermediate ibus to connect the two internal components */
      val ibusIntermediate = MemBus(ibus.config, ibus.idWidth) // (master connection)

      /** Then add IO that will connect new component - ibusCntrlSelector to external pipeline for
        * encryption instruction cache (InstructionCacheEncrypt) and AES core The service is defined
        * in the InstructionCacheEncrypt component.
        */
      /** this is slave */
      val ibusCache =
        pipeline.service[ICacheIbusIoService].getICacheIbusIo(fetchStage, ibus.config, ibus.idWidth)

      /** Then add the new component */
      val ibusCSelect = new ibusCntrlSelector(ibus)

      /** Then add IBusControl */
      val ibusCtrl = new IBusControl(ibusIntermediate, ibusLatency)

      /** Connect the two internal components together and to the ibus */
      /** Input to ibusCntrlSelector from IBusControl */
      ibusCSelect.ibusFetch <> ibusIntermediate

      /** output from ibusCntrlSelector to ibus */
      ibus <> ibusCSelect.ibusAXI

      /** connect new I/O bus (ibusCache) to ibusCntrlSelector (ibusCSelect). */
      ibusCSelect.ibusCache <> ibusCache

      /** ----------------------------------- */
      /** Keep the rest of Fetcher the same */

      arbitration.isReady := False

      val pc = input(pipeline.data.PC)
      val nextPc = pc + 4

      when(arbitration.isRunning) {
        val fetchAddress = addressTranslator.translate(fetchStage, pc)
        val (valid, rdata) = ibusCtrl.read(fetchAddress)

        when(valid) {
          arbitration.isReady := True

          output(pipeline.data.NEXT_PC) := nextPc
          output(pipeline.data.IR) := rdata
        }
      }

    }
  }

  override def setAddressTranslator(translator: FetchAddressTranslator): Unit = {
    assert(!addressTranslatorChanged, "FetchAddressTranslator can only be set once")

    addressTranslator = translator
    addressTranslatorChanged = true
  }

}
