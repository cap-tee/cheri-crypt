package riscv.plugins.cheriEncrypt

import spinal.core._
import spinal.lib._
import spinal.core.{UInt, _}
import spinal.core.{BitCount, Component}
import spinal.lib.fsm.{EntryPoint, State, StateMachine, StateParallelFsm}
import AESEngine.{
  AES_Dec,
  AES_DecCmd,
  AES_DecConfig,
  AES_DecIO,
  AES_DecRsp,
  AES_Enc,
  AES_EncCmd,
  AES_EncConfig,
  AES_EncIO,
  AES_EncRsp
}
import riscv.plugins.cheri
import riscv.{Config, MemBus, MemBusConfig, MemBusControl, Pipeline}
import riscv.plugins.cheri.Context
import spinal.core.Component.push

/** component to do a read cacheline - used by the cache controller component */
/** 1) read data from memory 2) decrypt 3) write to cache memory. Note that we can read and write at
  * the same time. If there is a decryption error we need to feed this back to raise an exception
  */

/** controllerIO - IO to the cache controller */
case class controllerIOCmd(cacheConfig: cacheConfig, aes_DecConfig: AES_DecConfig) extends Bundle {
  val batchAddr = Bits(cacheConfig.addrWidth)
  val capBaseAddr = Bits(cacheConfig.addrWidth)
  val capLen = UInt(cacheConfig.addrWidth)
  val key = Bits(aes_DecConfig.keyWidth)
  val IV = Bits(aes_DecConfig.dataWidth)
}
case class controllerIORsp(cacheConfig: cacheConfig) extends Bundle {
  val done = Bool() // done operation
}
case class controllerIO(cacheConfig: cacheConfig, aes_DecConfig: AES_DecConfig)
    extends Bundle
    with IMasterSlave {
  val cmd = Flow(controllerIOCmd(cacheConfig, aes_DecConfig))
  val rsp = Flow(controllerIORsp(cacheConfig))
  val decrypt_error = Bool()
  override def asMaster() = {

    /** declare outputs for master, so will be inputs for slave */
    master(cmd)
    in(decrypt_error)

    /** declare inputs for master, so will be outputs for slave */
    slave(rsp)

  }
}

/** cacheIO - IO to the cache memory */
case class cacheIO(cacheConfig: cacheConfig) extends Bundle with IMasterSlave {
  val cmd = Flow(CacheCmd(cacheConfig))

  override def asMaster() = {

    /** declare outputs for master, so will be inputs for slave */
    master(cmd)

    /** Set the direction of each bundle/signal from a master point of view */
  }
}

/** AXIIO - IO to the AXI bus */
case class AXIIO(ibusConfig: MemBusConfig, idWidth: BitCount) extends Bundle with IMasterSlave {
  val ibusCacheAXI = MemBus(ibusConfig, idWidth).setName("ibusCacheAXI")

  override def asMaster() = {

    /** declare outputs for master, so will be inputs for slave */
    master(ibusCacheAXI)

    /** declare inputs for master, so will be outputs for slave */
  }
}

/** used to define input fifo to AES core without putting aad_vld, tag_gold and key through fifo as
  * they will be stored in held registers, make design more efficient
  */
case class AES_DecCmdFIFO(config: AES_DecConfig) extends Bundle {
  val vector_vld = Bool() // ready signal for IV
  val ct_vld = Bool() // ready signal for ciphertext (decryption)
  // val aad_vld = Bool() // ready signal for AAD
  // val tag_gold = Bits(config.dataWidth) // golden tag value read from the memory
  val block = Bits(config.dataWidth) // can be the initial vector, ciphertext, and AAD
  val last_word = Bool() // last word of the input data
  val key_vld = Bool() // ready signal for key
  // val key = Bits(config.keyWidth) // decryption key
}

/** read cacheline component */
class cacheReadWriteBatch(aes_DecConfig: AES_DecConfig)(implicit
    context: cheri.Context,
    cacheConfig: cacheConfig,
    encryptConfig: EncryptConfig
) extends Component {

  /** INPUTS/OUTPUTS */
  /** controller IO --------- */
  val controllerio = slave(controllerIO(cacheConfig, aes_DecConfig))

  /** define inputs/outputs registers */
  val in_keyReg = Reg(Bits(aes_DecConfig.keyWidth)) init (0)
  val decrypt_errorReg = Reg(Bool()) init (False)

  val out_doneReg: Bool = Reg(Bool()) init (False)

  /** set default outputs */
  out_doneReg := False // unless set by state machine
  controllerio.rsp.valid := out_doneReg
  controllerio.rsp.payload.done := out_doneReg
  controllerio.decrypt_error := decrypt_errorReg

  /** End controller IO --------- */

  /** cache memory IO --------- */
  val cacheio = master(cacheIO((cacheConfig)))

  /** set default outputs */
  cacheio.cmd.payload.wmask := 0xf
  cacheio.cmd.payload.memwrite := True // writing to cache with data from the memory side
  cacheio.cmd.payload.procwrite := False
  cacheio.cmd.payload.inputFromMem := True // this is mem read/write

  /** end cache memory IO --------- */

  /** AES IO --------- */
  val aesCache_dec = master(AES_DecIO(aes_DecConfig)) // crypto core

  /** fix AES DEC to full data size */
  aesCache_dec.data_size := B("1111").asUInt

  /** fix aad_vld to false as not used */
  aesCache_dec.cmd.payload.aad_vld := False

  /** end AES IO --------- */

  /** AXI IO --------- */
  val axiio = master(AXIIO(context.config.dbusConfig, idWidth = 0 bits))

  /** set default outputs */
  axiio.ibusCacheAXI.cmd.valid := False
  axiio.ibusCacheAXI.cmd.payload.address := 0x0
  axiio.ibusCacheAXI.cmd.payload.write := False
  axiio.ibusCacheAXI.cmd.payload.wdata := 0x0
  axiio.ibusCacheAXI.cmd.payload.id := 0x0
  axiio.ibusCacheAXI.cmd.payload.wmask := 0xf

  /** ToDo - see FIXMe note below. - we say rsp.ready is always true. we wait on the cmd side
    * instead when the buffer is getting nearly full because setting rsp.ready to low crashes the
    * simulation. This is a work-around until the problem is resolved
    */
  axiio.ibusCacheAXI.rsp.ready := True // default unless set in state machine

  /** end AXI IO --------- */
  /** END INPUTS/OUTPUTS */

  /** INPUT READ MUX from memory - SIGNALS */
  /** Input read data mux signals to get read data from memory into 128-bit blocks */
  // address as if going out to memory
  val currentReadAddress: UInt = Reg(UInt(context.config.xlen bits)) init (0)
  // decrement until get to zero
  // size needs to be generic based on batch size, doesn't always need to be this big
  // val endReadLength: UInt = Reg(UInt(context.config.xlen bits)) init (0)
  // val endReadLength2: UInt = Reg(UInt(context.config.xlen bits)) init (0)
  val endReadLength: UInt = Reg(UInt(encryptConfig.batchShiftBits + 1 bits)) init (0)
  val endReadLength2: UInt = Reg(UInt(encryptConfig.batchShiftBits + 1 bits)) init (0)

  /** reads in 4 words at a time - counter wraps round after 3 */
  val currentReadBlock: UInt =
    Reg(UInt((aes_DecConfig.dataWidth.value / 128 + 1) bits)) init (0)
  val muxReadReg: UInt = Reg(UInt(aes_DecConfig.dataWidth)) init (0) // 128 bit block size
  val muxReadRegValid: Bool = Reg(Bool) init (False) // valid every 4th read
  val lastRegValid: Bool = Reg(Bool) init (False) // valid when last block in batch

  val TagReg: UInt = Reg(UInt(aes_DecConfig.dataWidth)) init (0) // 128 bit block size
  val IVReg: UInt = Reg(UInt(aes_DecConfig.dataWidth)) init (0) // 128 bit block size
  val IVRegValid: Bool = Reg(Bool) init (False) // valid after 4th read

  /** ---------------------------------------------------------------------- */
  /** OUTPUT WRITE MUX to cache - SIGNALS */
  /** reads in 4 words at a time - counter wraps round after 3 */
  val currentWriteBlock: UInt =
    Reg(UInt((aes_DecConfig.dataWidth.value / 128 + 1) bits)) init (0)
  val wdata: UInt = Reg(UInt(context.config.xlen bits)) init (0) // data to be written to cache
  val wdataValid: Bool = Reg(Bool) init (False) // valid every 4th read
  // size needs to be generic based on batch size, doesn't always need to be this big
  // val currentWriteLength: UInt = Reg(UInt(context.config.xlen bits)) init (0)
  val currentWriteLength: UInt = Reg(UInt(encryptConfig.batchShiftBits + 1 bits)) init (0)
  val currentWriteAddress: UInt = Reg(UInt(context.config.xlen bits)) init (0)
  // address as if going out to CACHE
  val writeAddress: UInt = Reg(UInt(context.config.xlen bits)) init (0)

  /** ---------------------------------------------------------------------- */

  /** INPUT DATA FIFO TO CRYPTO CORE */
  /** removed 128bit key, & gold tag from fifo input because it is set in register which is more
    * efficient
    */
  val inputFifo = StreamFifo(
    // dataType = AES_DecCmd(aes_DecConfig),
    dataType = AES_DecCmdFIFO(aes_DecConfig),
    depth = encryptConfig.aesInputFifoDepth
  )
  // val streamReadInput, streamReadOutput = Stream(AES_DecCmd(aes_DecConfig))
  val streamReadInput, streamReadOutput = Stream(AES_DecCmdFIFO(aes_DecConfig))
  inputFifo.io.push << streamReadInput
  inputFifo.io.pop >> streamReadOutput

  /** to restart reading data from memory after a burst */
  val readFifoNearlyEmpty: Bool = Bool()
  when(inputFifo.io.occupancy < ((encryptConfig.aesInputFifoDepth / 2) + 1)) {
    readFifoNearlyEmpty := True
  } otherwise {
    readFifoNearlyEmpty := False
  }

  /** ---------------------------------------------------------------------- */

  /** ---------------------------------------------------------------------- */

  /** OUTPUT DATA FIFO FROM CRYPTO CORE */
  /** Fill outputFifo with encrypt data */
  /** output data FIFO */
  val outputFifo = StreamFifo(
    dataType = AES_DecRsp(aes_DecConfig),
    depth = encryptConfig.aesOutputFifoDepth
  )
  val streamWriteInput, streamWriteOutput = Stream(AES_DecRsp(aes_DecConfig))
  outputFifo.io.push << streamWriteInput
  outputFifo.io.pop >> streamWriteOutput

  /** hold output data until all row of data multiplexed onto 32bit bus by state machine mux */
  streamWriteOutput.ready := False

  /** ---------------------------------------------------------------------- */

  /** tag address calculations */
  // Todo may need to register some of these if timing issues
  // Todo more efficient to put this calc outside this block, so can use same logic for readline and writeback
  val capLenShift: UInt = UInt(cacheConfig.addrWidth)
  val intAddr = Bits(cacheConfig.addrWidth)
  val intAddrShift = Bits(cacheConfig.addrWidth)
  val intAddrShiftTag = Bits(cacheConfig.addrWidth)
  val tagL = UInt(cacheConfig.addrWidth)
  val tagAddr = Bits(cacheConfig.addrWidth)
  val tagAddrReg = Reg(Bits(cacheConfig.addrWidth))
  // Ld ->Sb-St
  capLenShift := controllerio.cmd.payload.capLen |>> encryptConfig.tagCalcShiftBits
  // batchAddr-baseAddr
  intAddr := (controllerio.cmd.payload.batchAddr.asUInt - controllerio.cmd.payload.capBaseAddr.asUInt).asBits
  // (batchAddr-baseAddr)->Sb-St
  intAddrShift := intAddr |>> encryptConfig.tagCalcShiftBits
  // (batchAddr-baseAddr)->Sb-St + LtIV
  intAddrShiftTag := (intAddrShift.asUInt + encryptConfig.lengthTagIV).asBits
  // Ld + (capLenShift - intAddrShiftTag)
  tagL := controllerio.cmd.payload.capLen + capLenShift - intAddrShiftTag.asUInt
  // tagAddr
  tagAddr := (controllerio.cmd.payload.capBaseAddr.asUInt + tagL).asBits

  /** END tag address calculations */

  /** *************************
    */
  /** state machine to send cmds for read data from memory over axi bus */
  val readCmdsMemFsm = new StateMachine {
    val idle = new State with EntryPoint
    val cmdTagState = new State
    val cmdIVState = new State
    val cmdDataState = new State
    val cmdWaitFIFO = new State

    val endReadTagLength: UInt =
      Reg(
        UInt(encryptConfig.tagShiftBits bits)
      ) init (encryptConfig.lengthTagIVinWords)

    val burstLength: UInt =
      Reg(
        UInt(encryptConfig.burstLengthBits bits)
      ) init (0)
    idle.whenIsActive {
      burstLength := (encryptConfig.aesInputFifoDepth / 2) * 4 // 4 lots of data in one fifo space
      when(controllerio.cmd.valid) {

        /** from tag address calculations */
        tagAddrReg := tagAddr
        in_keyReg := controllerio.cmd.payload.key
        goto(cmdTagState)
      }
    }

    cmdTagState.whenIsActive {
      axiio.ibusCacheAXI.cmd.valid := False

      /** read until end of tag length required 8/2 = 4  (encryptConfig.lengthTagIVinWords / 2) */
      /** valid first then wait for ready */
      when(!(endReadTagLength === encryptConfig.lengthTagIVinWords / 2)) {
        axiio.ibusCacheAXI.cmd.valid := True
        axiio.ibusCacheAXI.cmd.payload.address := tagAddrReg.asUInt
        when(axiio.ibusCacheAXI.cmd.ready) {
          tagAddrReg := (tagAddrReg.asUInt + 4).asBits // address out to memory (goes up in 4)
          endReadTagLength := endReadTagLength - 1
        }
      } otherwise { goto(cmdIVState) }
    }

    cmdIVState.whenIsActive {
      IVRegValid := False // default unless set below to go into FIFO
      axiio.ibusCacheAXI.cmd.valid := False

      /** read until end (0) */
      /** valid first then wait for ready */
      when(!(endReadTagLength === 0)) {
        axiio.ibusCacheAXI.cmd.valid := True
        axiio.ibusCacheAXI.cmd.payload.address := tagAddrReg.asUInt
        when(axiio.ibusCacheAXI.cmd.ready) {
          tagAddrReg := (tagAddrReg.asUInt + 4).asBits // address out to memory (goes up in 4)
          endReadTagLength := endReadTagLength - 1
        }
      } otherwise {
        goto(cmdDataState)
      }
    }

    cmdDataState.whenIsActive {

      /** reset endReadTagLength ready for next time */
      endReadTagLength := encryptConfig.lengthTagIVinWords // should equal 8 in our case
      IVRegValid := False
      axiio.ibusCacheAXI.cmd.valid := False

      /** we send data in bursts so we don't over-fill the rsp FIFO */
      /** bursts should be a multiple of 16 bytes */
      /** FIXMe - we wait on the cmd side because setting rsp.ready to low crashes the simulation */
      when(!(burstLength === 0)) {
        when(!(endReadLength === 0)) {
          axiio.ibusCacheAXI.cmd.valid := True
          axiio.ibusCacheAXI.cmd.payload.address := currentReadAddress
          when(axiio.ibusCacheAXI.cmd.ready) {
            currentReadAddress := currentReadAddress + 4 // address out to memory (goes up in 4)
            endReadLength := endReadLength - 4 // reduce in 4's too
            burstLength := burstLength - 1
          }
        } otherwise {

          /** wait for data to be written to cache */
          when(out_doneReg) {
            goto(idle)
          }
        }

        /** wait for fifo to empty a bit */
      } otherwise {
        goto(cmdWaitFIFO)
      }
    }

    /** wait for fifo to empty a bit before sending another burst of commands */
    /** FIXMe - we wait on the cmd side because setting rsp.ready to low crashes the simulation
      * responses are therefore always accepted
      */
    cmdWaitFIFO.whenIsActive {
      IVRegValid := False
      axiio.ibusCacheAXI.cmd.valid := False
      when(readFifoNearlyEmpty) {
        burstLength := (encryptConfig.aesInputFifoDepth / 2) * 4
        goto(cmdDataState)
      }
    }

  }

  /** *************************
    */
  /** state machine to get rsp for read data from memory over axi bus */
  val readRspMemFsm = new StateMachine {
    val idle = new State with EntryPoint
    val readTagState = new State
    val readIVState = new State
    val readDataState = new State

    idle.whenIsActive {
      when(controllerio.cmd.valid) {

        /** set up read parameters */
        currentReadAddress := controllerio.cmd.payload.batchAddr.asUInt
        endReadLength := encryptConfig.batchLength
        endReadLength2 := encryptConfig.batchLength // ToDo rename/make more efficient
        currentReadBlock := 0
        muxReadRegValid := False
        lastRegValid := False

        IVRegValid := False
        goto(readTagState)
      }
    }

    readTagState.whenIsActive {

      /** write to tag register */
      when(axiio.ibusCacheAXI.rsp.valid) {
        // axiio.ibusCacheAXI.rsp.ready := True // accept data straight away

        /** fixed at 128 bit block */
        when(currentReadBlock === 0) {
          TagReg(31 downto 0) := axiio.ibusCacheAXI.rsp.payload.rdata
        }
        when(currentReadBlock === 1) {
          TagReg(63 downto 32) := axiio.ibusCacheAXI.rsp.payload.rdata
        }
        when(currentReadBlock === 2) {
          TagReg(95 downto 64) := axiio.ibusCacheAXI.rsp.payload.rdata
        }
        when(currentReadBlock === 3) {
          TagReg(127 downto 96) := axiio.ibusCacheAXI.rsp.payload.rdata
          goto(readIVState)
        }
        currentReadBlock := currentReadBlock + 1 // wraps round after 3 for 128 bit block
      }
    }

    readIVState.whenIsActive {
      IVRegValid := False // default unless set below to go into FIFO
      muxReadRegValid := False
      lastRegValid := False

      /** put IV into data registered mux going to AES_DEC input fifo */
      /** fixed at 128 bit block */
      when(axiio.ibusCacheAXI.rsp.valid) {
        // axiio.ibusCacheAXI.rsp.ready := True // accept data straight away
        when(currentReadBlock === 0) {
          muxReadReg(31 downto 0) := axiio.ibusCacheAXI.rsp.payload.rdata
        }
        when(currentReadBlock === 1) {
          muxReadReg(63 downto 32) := axiio.ibusCacheAXI.rsp.payload.rdata
        }
        when(currentReadBlock === 2) {
          muxReadReg(95 downto 64) := axiio.ibusCacheAXI.rsp.payload.rdata
        }
        when(currentReadBlock === 3) {
          muxReadReg(127 downto 96) := axiio.ibusCacheAXI.rsp.payload.rdata
          IVRegValid := True // this is IV to make this valid , not muxReadRegValid
          goto(readDataState)
        }
        currentReadBlock := currentReadBlock + 1 // wraps round after 3 for 128 bit block
      }
    }

    readDataState.whenIsActive {
      muxReadRegValid := False
      lastRegValid := False

      /** put data into registered mux */
      /** fixed at 128 bit block */
      when(axiio.ibusCacheAXI.rsp.valid) {
        // FIXMe simulation seems to break if we wait for the input fifo to be ready as well before accepting responses
        // work around is to stop read cmds and always accept responses
        // axiio.ibusCacheAXI.rsp.ready := True // accept data
        when(currentReadBlock === 0) {
          muxReadReg(31 downto 0) := axiio.ibusCacheAXI.rsp.payload.rdata
        }
        when(currentReadBlock === 1) {
          muxReadReg(63 downto 32) := axiio.ibusCacheAXI.rsp.payload.rdata
        }
        when(currentReadBlock === 2) {
          muxReadReg(95 downto 64) := axiio.ibusCacheAXI.rsp.payload.rdata
        }
        when(currentReadBlock === 3) {
          muxReadReg(127 downto 96) := axiio.ibusCacheAXI.rsp.payload.rdata
          muxReadRegValid := True

          /** check if will be last */
          when((endReadLength2 - 4) === 0) {
            lastRegValid := True
          }
        }
        currentReadBlock := currentReadBlock + 1 // wraps round after 3 for 128 bit block
        endReadLength2 := endReadLength2 - 4 // reduce in 4's too
      }

      /** wait for data to be written to cache */
      when(out_doneReg) {
        goto(idle)
      }

    }

  }

  /** *************************
    */

  /** ---------------------------------------------------------------------- */

  /** CRYPTO CORE */
  /** connect read data mux to fifo input to the core */
  streamReadInput.payload.vector_vld := IVRegValid
  streamReadInput.payload.key_vld := True // will be true when valid is true
  streamReadInput.payload.block := muxReadReg.asBits
  streamReadInput.payload.ct_vld := muxReadRegValid
  streamReadInput.payload.last_word := lastRegValid

  /** valid fifo input */
  streamReadInput.valid := muxReadRegValid || IVRegValid
  // streamReadInput.payload.tag_gold := 0x0 // removed from fifo, tag in reg
  // streamReadInput.payload.key := 0x0 // removed from fifo, key in reg
  // streamReadInput.payload.aad_vld := False // removed from fifo, not used

  /** connect key to crypto core */
  aesCache_dec.cmd.payload.key := in_keyReg
  aesCache_dec.cmd.payload.tag_gold := TagReg.asBits

  /** connect inputFifo to crypto core */
  streamReadOutput.ready := aesCache_dec.cmd.ready
  aesCache_dec.cmd.valid := streamReadOutput.valid
  aesCache_dec.cmd.payload.block := streamReadOutput.payload.block.asBits
  aesCache_dec.cmd.payload.last_word := streamReadOutput.payload.last_word
  aesCache_dec.cmd.payload.vector_vld := streamReadOutput.payload.vector_vld
  aesCache_dec.cmd.payload.key_vld := streamReadOutput.payload.key_vld
  aesCache_dec.cmd.payload.ct_vld := streamReadOutput.payload.ct_vld

  /** connect crypto core to output fifo */
  // ToDo improve error check
  streamWriteInput.valid := aesCache_dec.rsp.valid | aesCache_dec.tag_error
  streamWriteInput.payload.tag_vld := aesCache_dec.rsp.payload.tag_vld | aesCache_dec.tag_error
  streamWriteInput.payload.data_vld := aesCache_dec.rsp.payload.data_vld
  streamWriteInput.payload.Out_data := aesCache_dec.rsp.payload.Out_data

  /** ---------------------------------------------------------------------- */

  /** since we are writing to cache, we can read from memory and write to cache at the same time we
    * don't need to wait for each other. we can write to cache as soon as the data is ready
    */
  val writeCacheFsm = new StateMachine {

    val idle = new State with EntryPoint
    val writeCacheState = new State
    val checkTagErrorState = new State
    val doneState = new State

    idle.whenIsActive {
      out_doneReg := False
      currentWriteBlock := 0
      wdataValid := False
      currentWriteLength := encryptConfig.batchLength
      when(controllerio.cmd.valid) {

        /** set up write parameters */
        currentWriteAddress := controllerio.cmd.payload.batchAddr.asUInt
        goto(writeCacheState)
      }
    }

    writeCacheState.whenIsActive {
      wdataValid := False
      out_doneReg := False

      /** write until end of length required */
      when(!(currentWriteLength === 0)) {
        when(streamWriteOutput.valid & streamWriteOutput.payload.data_vld) {
          writeAddress := currentWriteAddress // register it so aligned to cache
          currentWriteAddress := currentWriteAddress + 4 // address to cache (goes up in 4)
          currentWriteLength := currentWriteLength - 4 // reduce in 4's too
          /** write mux, convert to 32bit data out of fifo buffer */
          /** fixed at 128 bit block */
          when(currentWriteBlock === 0) {
            wdata := streamWriteOutput.payload.Out_data(31 downto 0).asUInt
            wdataValid := True
          }
          when(currentWriteBlock === 1) {
            wdata := streamWriteOutput.payload.Out_data(63 downto 32).asUInt
            wdataValid := True
          }
          when(currentWriteBlock === 2) {
            wdata := streamWriteOutput.payload.Out_data(95 downto 64).asUInt
            wdataValid := True
          }
          when(currentWriteBlock === 3) {
            wdata := streamWriteOutput.payload.Out_data(127 downto 96).asUInt
            wdataValid := True
            streamWriteOutput.ready := True
          }
          currentWriteBlock := currentWriteBlock + 1 // wraps round after 3 for 128 bit block

        }

        /** wait for tag to see if there was an error */
      } elsewhen (streamWriteOutput.valid & streamWriteOutput.payload.tag_vld) {

        /** clear tag out */
        streamWriteOutput.ready := True
        goto(checkTagErrorState)
      }
    }

    /** a tag error happens after tag output so check then */
    checkTagErrorState.whenIsActive {
      // ToDo improve error check
      when(streamWriteOutput.valid & streamWriteOutput.payload.tag_vld) {
        decrypt_errorReg := True // stay high once triggered
        /** clear error out */
        streamWriteOutput.ready := True
      } otherwise {
        out_doneReg := True
        goto(doneState)
      }
    }

    /** need this because need a delay after done */
    doneState.whenIsActive {
      goto(idle)
    }
  }

  /** set outputs to cache */
  cacheio.cmd.valid := wdataValid
  cacheio.cmd.payload.address := writeAddress.asBits
  cacheio.cmd.payload.wdata := wdata.asBits

}
