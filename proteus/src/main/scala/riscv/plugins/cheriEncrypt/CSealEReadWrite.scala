package riscv.plugins.cheriEncrypt

import AESEngine.{AES_EncRsp, AES_EncCmd, AES_EncConfig, AES_EncIO}
import spinal.core._
import spinal.lib._
import spinal.lib.fsm._
import riscv._
import riscv.plugins.cheri
import spinal.lib.fsm.StateMachine

/** This is the CSealEncrypt readWrite component used for the control of reading and writing data
  * from memory during encryption
  */
case class CSealReadWriteConfig(
    aesInputFifoDepth: Int,
    aesOutputFifoDepth: Int
)

/** define input / output signals */
case class CSealInstrCmd(aes_EncConfig: AES_EncConfig)(implicit context: cheri.Context)
    extends Bundle {
  val key = Bits(aes_EncConfig.keyWidth)
  val dataAddress = UInt(context.config.xlen bits)
  val authTagAddress = UInt(context.config.xlen bits)
  val length = UInt(context.config.xlen bits)
  val IV = Bits(aes_EncConfig.dataWidth)
  val start = Bool()
}
case class CSealInstrRsp() extends Bundle {
  val done = Bool()
}

/** then use master/slave handshake so can include both in/out signals in one bundle */
case class CSealInstrIo(aes_EncConfig: AES_EncConfig)(implicit context: cheri.Context)
    extends Bundle
    with IMasterSlave {

  val cmd = Flow(CSealInstrCmd(aes_EncConfig)) // stream not req. cache mem always ready to accept
  val rsp = Flow(CSealInstrRsp())
  val encrypt_error = Bool()

  /** Set the direction of each bundle/signal from a master point of view */
  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    master(cmd)

    /** declare inputs for master, so will be outputs for slave */
    slave(rsp)
    in(encrypt_error)
  }
}

/** Definition of a service to add/connect Io within a stage */
/** This is used by CSealEncrypt.scala to connect the CSealEncrypt instruction to the
  * CSealEReadWrite component cache.
  */
trait CSealInstrIoService {
  def getCSealInstrIo(stage: Stage)(implicit
      context: cheri.Context,
      aes_EncConfig: AES_EncConfig
  ): CSealInstrIo
}

/** define input / output signals */
case class CSealEDbusIo(dbusConfig: MemBusConfig, idWidth: BitCount)
    extends Bundle
    with IMasterSlave {
  val dbusCSealAXI = MemBus(dbusConfig, idWidth).setName("dbusCSealAXI")
  val CSealSelect = Bool()

  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    out(CSealSelect)
    master(dbusCSealAXI)
  }
}

/** Definition of a service to add/connect Io within a stage */
/** This is used by FetcherEncrypt.scala to connect the ibus control selector to the instruction
  * cache.
  */
trait CSealEDbusIoService {
  def getCSealEDbusIo(
      component: Component,
      ibusConfig: MemBusConfig,
      idWidth: BitCount
  ): CSealEDbusIo
}

/** define input / output signals */
case class CSealEAESIo(aes_EncConfig: AES_EncConfig) extends Bundle with IMasterSlave {
  val CSealAES = AES_EncIO(aes_EncConfig) // crypto core
  val CSealSelect = Bool()

  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    out(CSealSelect)
    master(CSealAES)
  }
}

/** Definition of a service to add/connect Io to another pipeline component */
/** This is used by AESCntrlSelector.scala to connect the instruction cache to the AES. Uses the AES
  * IO definition
  */
trait CSealEAESIoService {
  def getCSealEAESIo(component: Component): CSealEAESIo
}

/** used to define input fifo to AES core without putting aad_vld, tag_gold and key through fifo as
  * they will be stored in held registers, to make design more efficient
  */
case class AES_EncCmdFIFO(config: AES_EncConfig) extends Bundle {
  val vector_vld = Bool() // valid signal for IV
  val pt_vld = Bool() // valid signal for plaintext (encryption)
  // val aad_vld = Bool() //valid signal for AAD
  val block = Bits(config.dataWidth) // the first clk is the initial vector, then are the plaintexts
  val last_word = Bool() // signal to indicate the last word of the data patch
  val key_vld = Bool() // valid signal for key
  // val key = Bits(config.keyWidth) //encryption key
}

/** component placed inside the pipeline area */
/** pass through generics as implicit */
class CSealEReadWrite(implicit
    context: cheri.Context,
    aes_EncConfig: AES_EncConfig,
    csealConfig: CSealReadWriteConfig
) extends Plugin[Pipeline]
    with CSealEDbusIoService
    with CSealEAESIoService
    with CSealInstrIoService {

  /** CacheDbus IO */
  private var CSealDbusComponentIo: CSealEDbusIo = _
  private var CSealDbusSlaveIo: Option[CSealEDbusIo] = None

  /** CacheAESbus IO */
  private var CSealAESComponentIo: CSealEAESIo = _
  private var CSealAESSlaveIo: Option[CSealEAESIo] = None

  /** CacheControlbus IO - from CSealEncrypt instruction */
  private var CSealInstrComponentIo: CSealInstrIo = _
  private var CSealInstrMasterIo: Option[CSealInstrIo] = None

  override def build(): Unit = {

    /** Add a new component to the pipeline area */
    /** ----------------------------------------------------- */
    val component = pipeline plug new Component {
      setDefinitionName("CSealEReadWrite")

      /** compile check block width in multiples of 128bits */
      assert(aes_EncConfig.dataWidth.value % 128 == 0)

      /** currently only supports 128 bit block size */
      assert(aes_EncConfig.dataWidth.value < 129)

      /** ---------------------------------------------------------------------- */

      /** COMPONENT IO */

      /** IO to Dbus AXI
        */
      val dbusAXI = master(CSealEDbusIo(context.config.dbusConfig, idWidth = 0 bits))

      /** set default outputs */
      dbusAXI.dbusCSealAXI.cmd.valid := False
      dbusAXI.dbusCSealAXI.cmd.payload.address := 0x0
      dbusAXI.dbusCSealAXI.cmd.payload.write := False
      dbusAXI.dbusCSealAXI.cmd.payload.wdata := 0x0
      dbusAXI.dbusCSealAXI.cmd.payload.id := 0x0
      dbusAXI.dbusCSealAXI.cmd.payload.wmask := 0xf

      dbusAXI.dbusCSealAXI.rsp.ready := False // say always false unless set in state machine
      /** --------- */

      /** IO to AES */
      val aesCSeal = master(CSealEAESIo(aes_EncConfig))

      /** fix AES ENC to full data size */
      aesCSeal.CSealAES.data_size := B("1111").asUInt

      /** fix aad_vld to false as not used */
      aesCSeal.CSealAES.cmd.payload.aad_vld := False

      /** IO to CSealEncrypt instruction */
      val CSealInstr = slave(CSealInstrIo(aes_EncConfig))
      // assign defaults
      CSealInstr.rsp.valid := False
      CSealInstr.rsp.payload.done := False
      // ToDo currently not used
      CSealInstr.encrypt_error := False

      /** ---------------------------------------------------------------------- */

      /** register for controlling the databus / AES driving signals for pass through or encryption
        */
      val cSealSelectReg: Bool = Reg(Bool) init (False)
      aesCSeal.CSealSelect := cSealSelectReg // aes crypto control
      dbusAXI.CSealSelect := cSealSelectReg // databus control

      /** INPUT READ MUX - SIGNALS */
      /** Input read data mux signals to get read data from memory into 128-bit blocks */
      // address as if going out to memory
      val currentReadAddress: UInt = Reg(UInt(context.config.xlen bits)) init (0)
      // ToDo this should be a fixed batch length
      val endReadLength: UInt = Reg(UInt(context.config.xlen bits)) init (0)
      val endReadLength2: UInt = Reg(UInt(context.config.xlen bits)) init (0)

      /** reads in 4 words at a time - counter wraps round after 3 */
      val currentReadBlock: UInt =
        Reg(UInt((aes_EncConfig.dataWidth.value / 128 + 1) bits)) init (0)
      val muxReadReg: UInt = Reg(UInt(aes_EncConfig.dataWidth)) init (0) // 128 bit block size
      val muxReadRegValid: Bool = Reg(Bool) init (False) // valid every 4th read
      val lastRegValid: Bool = Reg(Bool) init (False) // valid when last block in batch

      /** --- */
      /** OUTPUT READ MUX - SIGNALS */
      /** Output write data mux to get 128-bit data into 32-bit blocks */
      /** 128bit data comes from output of output fifo */
      // data address as if going out to memory
      val currentWriteAddress: UInt = Reg(UInt(context.config.xlen bits)) init (0)
      // decrement until get to zero
      val currentWriteLength: UInt = Reg(UInt(context.config.xlen bits)) init (0xff)
      // fixed at 4
      val currentWriteBlock: UInt = Reg(
        UInt((aes_EncConfig.dataWidth.value / 128 + 1) bits)
      ) init (0) // counter wraps round after 3
      val wdataValid: Bool = Reg(Bool) init (False) // datavalid reg
      val tdataValid: Bool = Reg(Bool) init (False) // tag datavalid reg
      /** --- */

      /** when input buffer nearly full we need to stop reading */
      val stopReading: Bool = Reg(Bool) init (False)

      /** read stopped only after data accepted on axi bus */
      val readStopped: Bool = Reg(Bool) init (False)

      /** when output buffer empty we need to stop writing */
      val stopWriting: Bool = Reg(Bool) init (False)

      /** flag to indicate when done all the memory reads */
      val readDone: Bool = Reg(Bool) init (False)

      /** flag to indicate when done all the memory writes */
      val writeDone: Bool = Reg(Bool) init (False)

      /** finished encrypting memory */
      val encryptDone: Bool = readDone && writeDone

      /** ---------------------------------------------------------------------- */

      /** INPUT DATA FIFO TO CRYPTO CORE */
      /** 128bit key not in fifo input because it is set in register which is more efficient,
        * aad_vld not in fifo because not used
        */
      val inputFifo = StreamFifo(
        // dataType = AES_EncCmd(aes_EncConfig),
        dataType = AES_EncCmdFIFO(aes_EncConfig),
        depth = csealConfig.aesInputFifoDepth
      )
      // val streamReadInput, streamReadOutput = Stream(AES_EncCmd(aes_EncConfig))
      val streamReadInput, streamReadOutput = Stream(AES_EncCmdFIFO(aes_EncConfig))
      inputFifo.io.push << streamReadInput
      inputFifo.io.pop >> streamReadOutput

      /** ---------------------------------------------------------------------- */

      /** OUTPUT DATA FIFO FROM CRYPTO CORE */
      /** Fill outputFifo with encrypted data */
      val outputFifo = StreamFifo(
        dataType = AES_EncRsp(aes_EncConfig),
        depth = csealConfig.aesOutputFifoDepth
      )
      val streamWriteInput, streamWriteOutput = Stream(AES_EncRsp(aes_EncConfig))
      outputFifo.io.push << streamWriteInput
      outputFifo.io.pop >> streamWriteOutput

      /** hold output data until all row of data multiplexed onto 32bit bus by state machine mux */
      streamWriteOutput.ready := False //

      /** CONTROL STATE MACHINE */
      val readWritefsm: StateMachine = new StateMachine {

        val idle = new State with EntryPoint
        val readData = new State
        val writeData = new State
        val writeTag = new State
        val writeIV = new State
        val finished = new State

        /** push rsp set up for AESWrapperIO back to CSealEncrypt */

        /** Default set to false, can push response when finished */
        def cSealInstrRsp: CSealInstrRsp = new CSealInstrRsp // return done to CSealEncrypt

        val aesRsp: CSealInstrRsp = Reg(cSealInstrRsp)
        // default reg outputs
        aesRsp.done := False

        idle.onEntry {

          /** reset here */
          cSealSelectReg := False
          readDone := False
          writeDone := False
        }
        idle.whenIsActive {
          when(CSealInstr.cmd.valid && CSealInstr.cmd.payload.start) {

            /** switch databus output / aes to be controlled by encryption logic */
            cSealSelectReg := True

            /** set up read parameters */
            currentReadAddress := CSealInstr.cmd.payload.dataAddress
            endReadLength := CSealInstr.cmd.payload.length // ToDo fixed batch length
            readStopped := False

            /** set up write parameters */
            currentWriteAddress := CSealInstr.cmd.payload.dataAddress
            currentWriteLength := CSealInstr.cmd.payload.length // ToDo fixed batch length
            currentWriteBlock := 0
            wdataValid := False
            tdataValid := False

            goto(readData)
          }
        }

        /** When the input read buffer is nearly full, the state machine will go to the write state
          * to see if there are any values to write and then come back here to do more reads. Since
          * there is only 1 address bus we can not read and write at the same time, we have to do
          * one or the other, so we have to wait.
          */
        // ToDo make more efficient for large memory - need something more intelligent here?
        readData.whenIsActive {

          dbusAXI.dbusCSealAXI.rsp.ready := True
          dbusAXI.dbusCSealAXI.cmd.valid := False

          /** read until end of length required */
          when(!(endReadLength === 0)) {

            /** when the input buffer is nearly full we can stop sending read commands and check the
              * output buffer to see if it has encrypted data ready to write back out to memory. But
              * note that we do not know the delay between sending the read commands and getting
              * data back from memory. For external off chip memory this could be a long delay.
              */
            /** read until input buffer nearly full and accepted previous data. If we don't wait for
              * current data to be accepted before driving valid low it messes up the axi arbiter
              * and everything grinds to a halt (ready stays low)
              */
            when(!readStopped) {
              dbusAXI.dbusCSealAXI.cmd.valid := True
              dbusAXI.dbusCSealAXI.cmd.payload.address := currentReadAddress
              when(dbusAXI.dbusCSealAXI.cmd.ready) {
                currentReadAddress := currentReadAddress + 4 // address out to memory (goes up in 4)
                endReadLength := endReadLength - 4 // reduce in 4's too
                when(stopReading) {

                  /** When input buffer nearly full (stopReading) stop here only after ready gone
                    * high. Flip to write data and see if there is encrypted data available to write
                    * to memory. We set a flag to say we have stopped for the next time it comes
                    * into this state, Otherwise carry on reading as normal
                    */
                  readStopped := True
                  goto(writeData)
                }
              }

              /** when we have already stopped reading from a previous condition we need to check to
                * see if we can carry on reading now, If we can carry on reading we need to reset
                * the stop flag (readStopped) and wait for the next clock cycle, otherwise flip back
                * to write data and see if there is encrypted data available to write
                */
            } otherwise {
              when(!stopReading) {
                readStopped := False
              } otherwise { goto(writeData) }
            }
          } otherwise {

            /** we have now finished all the reads */
            readDone := True
            when(encryptDone) {
              goto(finished)
            } otherwise {
              goto(writeData)
            }
          }

        }

        /** When the output write buffer is empty, the state machine will go to the read state to
          * read more values from memory and then come back here to do more writes. Since there is
          * only 1 address bus we can not read and write at the same time, we have to do one or the
          * other, so we have to wait. When all reads and writes are complete, encryption will
          * finish
          */
        writeData.whenIsActive {
          dbusAXI.dbusCSealAXI.rsp.ready := True
          dbusAXI.dbusCSealAXI.cmd.valid := False

          /** write until end of length required */
          when(!(currentWriteLength === 0)) {

            /** write until output buffer empty */
            when(!stopWriting) {

              /** only extract data out the buffer when it is valid */
              when(streamWriteOutput.valid) {
                when(streamWriteOutput.payload.data_vld) {
                  dbusAXI.dbusCSealAXI.cmd.valid := True
                  dbusAXI.dbusCSealAXI.cmd.payload.address := currentWriteAddress
                  dbusAXI.dbusCSealAXI.cmd.payload.write := True

                  /** write mux, convert to 32bit data out of fifo buffer */
                  /** fixed at 128bits */
                  when(currentWriteBlock === 0) {
                    dbusAXI.dbusCSealAXI.cmd.payload.wdata := streamWriteOutput.payload
                      .Out_data(31 downto 0)
                      .asUInt
                  }
                  when(currentWriteBlock === 1) {
                    dbusAXI.dbusCSealAXI.cmd.payload.wdata := streamWriteOutput.payload
                      .Out_data(63 downto 32)
                      .asUInt
                  }
                  when(currentWriteBlock === 2) {
                    dbusAXI.dbusCSealAXI.cmd.payload.wdata := streamWriteOutput.payload
                      .Out_data(95 downto 64)
                      .asUInt
                  }
                  when(currentWriteBlock === 3) {
                    dbusAXI.dbusCSealAXI.cmd.payload.wdata := streamWriteOutput.payload
                      .Out_data(127 downto 96)
                      .asUInt
                  }
                }
              }
              when(streamWriteOutput.valid & dbusAXI.dbusCSealAXI.cmd.ready) {
                currentWriteBlock := currentWriteBlock + 1 // wraps round after 3 for 128 bit block
                currentWriteAddress := currentWriteAddress + 4 // address out to memory (goes up in 4)
                currentWriteLength := currentWriteLength - 4 // reduce in 4's too
                when(currentWriteBlock === 3) {
                  streamWriteOutput.ready := True // pulse high for 1 clock cycle until get next valid data
                }
              }
            } otherwise {

              /** Flip to read data and see if there is more to read out of memory
                */
              goto(readData)
            }
          } otherwise {
            writeDone := False // not yet finished
            currentWriteAddress := tagAddrReg // load new address with tag address
            goto(writeTag)
          }
        }

        writeTag.whenIsActive {

          /** write tag */
          when(streamWriteOutput.valid) {
            when(streamWriteOutput.payload.tag_vld) {
              dbusAXI.dbusCSealAXI.cmd.valid := True
              dbusAXI.dbusCSealAXI.cmd.payload.address := currentWriteAddress
              dbusAXI.dbusCSealAXI.cmd.payload.write := True

              /** fixed at 128bits */
              when(currentWriteBlock === 0) {
                dbusAXI.dbusCSealAXI.cmd.payload.wdata := streamWriteOutput.payload
                  .Out_data(31 downto 0)
                  .asUInt
              }
              when(currentWriteBlock === 1) {
                dbusAXI.dbusCSealAXI.cmd.payload.wdata := streamWriteOutput.payload
                  .Out_data(63 downto 32)
                  .asUInt
              }
              when(currentWriteBlock === 2) {
                dbusAXI.dbusCSealAXI.cmd.payload.wdata := streamWriteOutput.payload
                  .Out_data(95 downto 64)
                  .asUInt
              }
              when(currentWriteBlock === 3) {
                dbusAXI.dbusCSealAXI.cmd.payload.wdata := streamWriteOutput.payload
                  .Out_data(127 downto 96)
                  .asUInt
              }
            }
          }
          when(streamWriteOutput.valid & dbusAXI.dbusCSealAXI.cmd.ready) {
            currentWriteBlock := currentWriteBlock + 1 // wraps round after 3 for 128 bit block
            currentWriteAddress := currentWriteAddress + 4 // address out to memory (goes up in 4)
            when(currentWriteBlock === 3) {
              streamWriteOutput.ready := True // pulse high for 1 clock cycle until get next valid data
              /** when done tag go to write IV */
              goto(writeIV)
            }
          }
        }

        writeIV.whenIsActive {
          dbusAXI.dbusCSealAXI.cmd.valid := True
          dbusAXI.dbusCSealAXI.cmd.payload.address := currentWriteAddress
          dbusAXI.dbusCSealAXI.cmd.payload.write := True

          /** fixed at 128bits */
          when(currentWriteBlock === 0) {
            dbusAXI.dbusCSealAXI.cmd.payload.wdata := IVReg(31 downto 0).asUInt
          }
          when(currentWriteBlock === 1) {
            dbusAXI.dbusCSealAXI.cmd.payload.wdata := IVReg(63 downto 32).asUInt
          }
          when(currentWriteBlock === 2) {
            dbusAXI.dbusCSealAXI.cmd.payload.wdata := IVReg(95 downto 64).asUInt
          }
          when(currentWriteBlock === 3) {
            dbusAXI.dbusCSealAXI.cmd.payload.wdata := IVReg(127 downto 96).asUInt
          }
          when(dbusAXI.dbusCSealAXI.cmd.ready) {
            currentWriteBlock := currentWriteBlock + 1 // wraps round after 3 for 128 bit block
            currentWriteAddress := currentWriteAddress + 4 // address out to memory (goes up in 4)

            when(currentWriteBlock === 3) {

              /** when done writing IV go to finish */
              writeDone := True // finished all the writes
              /** we can finish straight away */
              aesRsp.done := True // registered
              goto(finished)
            }
          }
        }

        finished.whenIsActive {
          // reset the write length to something greater than zero
          currentWriteLength := 0xff
          // push done to output to complete encryption
          // push sets valid to true as well as pushing done
          CSealInstr.rsp.push(aesRsp)
          goto(idle)
        }

      } // end state machine

      /** ---------------------------------------------------------------------- */
      /** read data mux - put outside control state machine because delay between read commands and
        * rsp and we need the control read state to stop straight away when buffer nearly full
        */
      /** ******************************
        */
      val readMuxfsm: StateMachine = new StateMachine {

        val idle = new State with EntryPoint
        val readMux = new State

        idle.whenIsActive {
          muxReadRegValid := False
          lastRegValid := False
          currentReadBlock := 0
          when(CSealInstr.cmd.valid && CSealInstr.cmd.payload.start) {
            endReadLength2 := CSealInstr.cmd.payload.length // ToDo fixed batch length
            goto(readMux)
          }
        }

        readMux.whenIsActive {

          /** put data into registered mux */
          /** fixed at 128 bit block */
          muxReadRegValid := False // default
          lastRegValid := False // default
          when(dbusAXI.dbusCSealAXI.rsp.valid) {
            when(currentReadBlock === 0) {
              muxReadReg(31 downto 0) := dbusAXI.dbusCSealAXI.rsp.payload.rdata
            }
            when(currentReadBlock === 1) {
              muxReadReg(63 downto 32) := dbusAXI.dbusCSealAXI.rsp.payload.rdata
            }
            when(currentReadBlock === 2) {
              muxReadReg(95 downto 64) := dbusAXI.dbusCSealAXI.rsp.payload.rdata
            }
            when(currentReadBlock === 3) {
              muxReadReg(127 downto 96) := dbusAXI.dbusCSealAXI.rsp.payload.rdata
              muxReadRegValid := True

              /** check if will be last */
              when((endReadLength2 - 4) === 0) {
                lastRegValid := True
                goto(idle)
              }
            }
            currentReadBlock := currentReadBlock + 1 // wraps round after 3 for 128 bit block
            endReadLength2 := endReadLength2 - 4 // reduce in 4's too
          }

          /** ******************************
            */
        }
      }

      /** ---------------------------------------------------------------------- */

      /** CRYPTO CORE */

      /** Need to input IVVector first to fifo */
      when(CSealInstr.cmd.valid) {
        streamReadInput.payload.vector_vld := True
        streamReadInput.payload.key_vld := True
        streamReadInput.payload.block := CSealInstr.cmd.payload.IV
        streamReadInput.payload.pt_vld := False
        streamReadInput.payload.last_word := lastRegValid
      } otherwise {

        /** connect read data mux to fifo input to the core */
        streamReadInput.payload.vector_vld := False
        streamReadInput.payload.key_vld := True
        streamReadInput.payload.block := muxReadReg.asBits
        streamReadInput.payload.pt_vld := muxReadRegValid
        streamReadInput.payload.last_word := lastRegValid
      }

      /** valid fifo input */
      streamReadInput.valid := CSealInstr.cmd.valid | muxReadRegValid
      // streamReadInput.payload.key := 0x0 // not put in fifo, key in reg
      // streamReadInput.payload.aad_vld := False // not put in fifo because not used

      /** to stall reading data from memory */
      /** Here we stop sending read commands when the read fifo gets nearly full */
      /** availability will depend on block size, need to be at least 4 for 128 */
      // when(inputFifo.io.availability < 7) {
      when(inputFifo.io.availability < ((csealConfig.aesInputFifoDepth / 2) + 1)) {
        stopReading := True
      } otherwise {
        stopReading := False
      }

      /** key set up to crypto core, save IV */
      // ToDo this assumes key is available before data, but may need to change this setup
      // if  aes core is going to be clocked at a faster rate
      // consider having key sent in fifo as first data with key tag bit
      // then key reg on output of fifo
      // do this for now - hold value of key in register until done
      val keyReg: Bits = Reg(Bits(aes_EncConfig.keyWidth)) init 0x0
      val IVReg: Bits = Reg(Bits(aes_EncConfig.keyWidth)) init 0x0
      val tagAddrReg: UInt = Reg(UInt(width = BitCount(context.config.xlen))) init 0
      when(CSealInstr.cmd.valid) {
        keyReg := CSealInstr.cmd.payload.key
        IVReg := CSealInstr.cmd.payload.IV
        tagAddrReg := CSealInstr.cmd.payload.authTagAddress
      }
      when(encryptDone) {
        keyReg := 0x0
        IVReg := 0x0
      }

      /** connect key to crypto core - stored in reg, not fifo */
      aesCSeal.CSealAES.cmd.payload.key := keyReg

      /** connect inputFifo to crypto core */
      streamReadOutput.ready := aesCSeal.CSealAES.cmd.ready
      aesCSeal.CSealAES.cmd.valid := streamReadOutput.valid
      aesCSeal.CSealAES.cmd.payload.block := streamReadOutput.payload.block.asBits
      aesCSeal.CSealAES.cmd.payload.last_word := streamReadOutput.payload.last_word
      aesCSeal.CSealAES.cmd.payload.vector_vld := streamReadOutput.payload.vector_vld
      aesCSeal.CSealAES.cmd.payload.key_vld := streamReadOutput.payload.key_vld
      aesCSeal.CSealAES.cmd.payload.pt_vld := streamReadOutput.payload.pt_vld

      /** connect crypto core to output fifo */
      streamWriteInput.valid := aesCSeal.CSealAES.rsp.valid
      streamWriteInput.payload := aesCSeal.CSealAES.rsp.payload

      /** to stall writing data to memory */
      /** Here we stop sending write commands when the output fifo is empty */
      when(outputFifo.io.occupancy < 1) {
        stopWriting := True
      } otherwise {
        stopWriting := False
      }

      /** connect outputFifo to mux is done in state machine */

      /** END COMPONENT BODY */

      /** --------------------------------------------------------------- */
    }

    /** --------------------------------------------------------------- */
    /** connect component IO to area */
    CSealDbusComponentIo = component.dbusAXI
    CSealAESComponentIo = component.aesCSeal
    CSealInstrComponentIo = component.CSealInstr
  }

  /** In the pipeline area connect to stage /another component */
  override def finish(): Unit = {
    pipeline plug new Area {
      CSealDbusSlaveIo.foreach(io => CSealDbusComponentIo <> io)
      CSealAESSlaveIo.foreach(io => CSealAESComponentIo <> io)
      CSealInstrMasterIo.foreach(io => CSealInstrComponentIo <> io)
    }
  }

  /** Definition of a service to add/connect Io within a stage */
  /** This is used by FetcherEncrypt.scala to connect the ibus control selector to the instruction
    * cache.
    */
  override def getCSealEDbusIo(
      component: Component,
      ibusConfig: MemBusConfig,
      idWidth: BitCount
  ): CSealEDbusIo = {

    assert(CSealDbusSlaveIo.isEmpty)

    /** add Io to component area */
    val area = component plug new Area {
      val io = slave(CSealEDbusIo(ibusConfig, idWidth))
    }
    CSealDbusSlaveIo = Some(area.io)
    area.io
  }

  /** Definition of a service to add/connect Io within a pipeline component */
  /** This is used by AESCntrlSelector.scala to connect the instruction cache to the AES control
    * selector.
    */
  override def getCSealEAESIo(component: Component): CSealEAESIo = {
    assert(CSealAESSlaveIo.isEmpty)

    /** add Io to component area */
    val area = component plug new Area {
      val io = slave(CSealEAESIo(aes_EncConfig))
    }
    CSealAESSlaveIo = Some(area.io)
    area.io
  }

  /** Definition of a service to add/connect Io within a stage area */

  /** This is used by cSealEncrypt instruction.
    */
  override def getCSealInstrIo(stage: Stage)(implicit
      context: cheri.Context,
      aes_EncConfig: AES_EncConfig
  ): CSealInstrIo = {
    assert(CSealInstrMasterIo.isEmpty)

    /** add Io to stage area */
    val stageArea = stage plug new Area {
      val io = master(CSealInstrIo(aes_EncConfig))
    }
    CSealInstrMasterIo = Some(stageArea.io)
    stageArea.io
  }

}
