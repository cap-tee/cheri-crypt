package riscv.plugins.cheriEncrypt

import riscv._
import riscv.plugins.cheri
import spinal.core.{out, _}
import spinal.lib._
import AESEngine.{AES_Dec, AES_DecConfig, AES_DecIO, AES_Enc, AES_EncConfig, AES_EncIO}

/** This is the AES Core component */

/** AESTopWrapper IO */

/** master/slave handshake so can include both in/out signals in one bundle */
case class AESgcmIo(implicit aes_DecConfig: AES_DecConfig, aes_EncConfig: AES_EncConfig)
    extends Bundle
    with IMasterSlave {

  /** use Three encryption cores so need three lots of IO */
  /** decryption for instruction part */
  val instr_AES_DEC = AES_DecIO(aes_DecConfig) // include crypto core

  /** decryption for data part */
  val data_AES_DEC = AES_DecIO(aes_DecConfig) // includ crypto core

  /** encryption for data part  and cSealEncrypt */
  val data_AES_ENC = AES_EncIO(aes_EncConfig) // include crypto core

  override def asMaster() = {
    master(instr_AES_DEC, data_AES_DEC, data_AES_ENC)

  }
}

/** Create service to allow IO to be created in another pipeline component */
trait AESTopWrapperService {

  /** need to pass component it is being created in */
  def getAESTopWrapperIO(component: Component): AESgcmIo
}

/** create AESTopWrapper component */

class AESTopWrapper(implicit aes_DecConfig: AES_DecConfig, aes_EncConfig: AES_EncConfig)
    extends Plugin[Pipeline]
    with AESTopWrapperService {

  private var componentIo: AESgcmIo = _
  private var masterIo: Option[AESgcmIo] = None

  override def build(): Unit = {
    val component = pipeline plug new Component {
      setDefinitionName("AESTopWrapper")
      val io = slave(AESgcmIo())
      // area body
      /** use Three encryption cores */
      /** decryption core for instruction part */
      val AES_DEC_i = new AES_Dec(dataWidth = 128 bits) // use crypto core

      /** decryption core for data part */
      val AES_DEC_d = new AES_Dec(dataWidth = 128 bits) // use crypto core

      /** encryption core for data part */
      val AES_ENC_d = new AES_Enc(dataWidth = 128 bits) // use crypto core

      /** connect io to components */
      AES_DEC_i.io <> io.instr_AES_DEC
      AES_DEC_d.io <> io.data_AES_DEC
      AES_ENC_d.io <> io.data_AES_ENC

    }
    componentIo = component.io
  }

  /** In the pipeline area connect to masterIO */
  override def finish(): Unit = {
    pipeline plug new Area {
      masterIo.foreach { io => componentIo <> io }
    }
  }

  /** definition of a service to add/connect "master" IO within a component */
  override def getAESTopWrapperIO(component: Component): AESgcmIo = {
    assert(masterIo.isEmpty)

    val area = component plug new Area {
      val io = master(AESgcmIo())
    }
    masterIo = Some(area.io)
    area.io
  }

}
