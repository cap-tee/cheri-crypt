package riscv.plugins.cheriEncrypt
import riscv._
import spinal.core._
import AESEngine._

/** This control selector component controls inputs and outputs to the AES Core */

class AESCntrlSelector(implicit
    aes_DecConfig: AES_DecConfig,
    aes_EncConfig: AES_EncConfig
) extends Plugin[Pipeline] {

  override def build(): Unit = {
    val component = pipeline plug new Component {
      setDefinitionName("AESCntrlSelector")

      /** ---------------------------------------------------------------------- */
      /** INPUTS/OUTPUTS */
      /** IO to AES - this is master */
      val aesIo = pipeline.service[AESTopWrapperService].getAESTopWrapperIO(this)

      /** IO to Instruction cache - this is slave */
      val ICacheaesIo = pipeline.service[ICacheAESIoService].getICacheAESIo((this))

      /** IO to data cache - this is slave */
      val DCacheaesIo = pipeline.service[DCacheAESIoService].getDCacheAESIo((this))

      /** IO to CSealEncrypt control read/write - this is slave */
      val CSealEaesIo = pipeline.service[CSealEAESIoService].getCSealEAESIo((this))

      /** ---------------------------------------------------------------------- */

      /** Route signals */
      /** Instruction cache directly to AES_DEC * */
      aesIo.instr_AES_DEC <> ICacheaesIo

      /** Data cache directly to AES_DEC * */
      aesIo.data_AES_DEC <> DCacheaesIo.DCacheAES_DEC

      /** MUX selector to AES_ENC */
      when(CSealEaesIo.CSealSelect) {

        /** when CSealEncrypt route via CSealEReadWrite */
        aesIo.data_AES_ENC <> CSealEaesIo.CSealAES

        /** Invalidate driving signals back to data cache */
        DCacheaesIo.DCacheAES_ENC.cmd.ready := False
        DCacheaesIo.DCacheAES_ENC.rsp.valid := False
        DCacheaesIo.DCacheAES_ENC.rsp.payload.assignDontCare()
        DCacheaesIo.DCacheAES_ENC.busy := False
        DCacheaesIo.DCacheAES_ENC.aes_done := False

      } otherwise {

        /** otherwise route via data cache */
        aesIo.data_AES_ENC <> DCacheaesIo.DCacheAES_ENC

        /** Invalidate driving signals */
        CSealEaesIo.CSealAES.cmd.ready := False
        CSealEaesIo.CSealAES.rsp.valid := False
        CSealEaesIo.CSealAES.rsp.payload.assignDontCare()
        CSealEaesIo.CSealAES.busy := False
        CSealEaesIo.CSealAES.aes_done := False

      }

    }
  }
}
