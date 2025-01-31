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
import riscv.{Config, MemBus, MemBusConfig, Pipeline}
import riscv.plugins.cheri.Context

/** component to do a write back cacheline */
/** 1) read data from cache 2) encrypt 3) write to main memory. Note that we can read and write at
  * the same time.
  */
/** define generics */

/** controllerIO */
case class writeBackControllerIOCmd(cacheConfig: cacheConfig, aes_EncConfig: AES_EncConfig)
    extends Bundle {
  val batchAddr = Bits(cacheConfig.addrWidth)
  val capBaseAddr = Bits(cacheConfig.addrWidth)
  val capLen = UInt(cacheConfig.addrWidth)
  val key = Bits(aes_EncConfig.keyWidth)
  val IV = Bits(aes_EncConfig.dataWidth)
}
case class writeBackControllerIORsp(cacheConfig: cacheConfig) extends Bundle {
  val done = Bool() // done operation
}
case class writeBackControllerIO(cacheConfig: cacheConfig, aes_EncConfig: AES_EncConfig)
    extends Bundle
    with IMasterSlave {
  val cmd = Flow(writeBackControllerIOCmd(cacheConfig, aes_EncConfig))
  val rsp = Flow(writeBackControllerIORsp(cacheConfig))

  override def asMaster() = {

    /** set the direction of each component, from the prospective of Master */
    /** declare outputs for master, so will be inputs for slave */
    master(cmd)

    /** declare inputs for master, so will be outputs for slave */
    slave(rsp)
  }
}

/** cache memory IO */
case class writebackCacheRsp(cacheConfig: cacheConfig) extends Bundle {
  val memRspReadError = Bool()
  val rdata = Bits(cacheConfig.dataWidth) // data read value
}
case class writeBackCacheIO(cacheConfig: cacheConfig) extends Bundle with IMasterSlave {
  val cmd = Flow(CacheCmd(cacheConfig))
  val rsp = Flow(writebackCacheRsp(cacheConfig))

  override def asMaster() = {

    /** set the direction of each component, from the prospective of Master */
    /** declare outputs for master, so will be inputs for slave */
    master(cmd)

    /** declare inputs for master, so will be outputs for slave */
    slave(rsp)
  }
}

/** AXI IO */
case class writeBackAXIIO(ibusConfig: MemBusConfig, idWidth: BitCount)
    extends Bundle
    with IMasterSlave {
  val ibusCacheAXI = MemBus(ibusConfig, idWidth).setName("ibusCacheAXI")

  override def asMaster() = {

    /** set the direction of each component, from the prospective of Master */
    /** declare outputs for master, so will be inputs for slave */
    master(ibusCacheAXI)

    /** declare inputs for master, so will be outputs for slave */
  }
}

/** WriteBack Line component */
class cacheWriteBackLine(aes_EncConfig: AES_EncConfig)(implicit
    context: cheri.Context,
    cacheConfig: cacheConfig,
    encryptConfig: EncryptConfig
) extends Component {

  /** INPUTS/OUTPUTS */
  /** controller IO --------- */
  val controllerio = slave(writeBackControllerIO(cacheConfig, aes_EncConfig))

  /** define inputs/outputs registers */
  val in_batchAddrReg = Reg(Bits(cacheConfig.addrWidth)) init (0) // writeback address line
  val in_capBaseAddrReg = Reg(Bits(cacheConfig.addrWidth)) init (0)
  val in_capLenReg = Reg(UInt(cacheConfig.addrWidth)) init (0)
  val in_keyReg = Reg(Bits(aes_EncConfig.keyWidth)) init (0)
  val in_IVReg = Reg(Bits(aes_EncConfig.dataWidth)) init (0)

  val out_doneReg: Bool = Reg(Bool()) init (False)

  /** set default outputs */
  out_doneReg := False // unless set by state machine
  controllerio.rsp.valid := out_doneReg
  controllerio.rsp.payload.done := out_doneReg

  /** End controller IO --------- */

  /** cache memory IO --------- */
  val cacheio = master(writeBackCacheIO((cacheConfig)))

  /** set default outputs */
  cacheio.cmd.valid := False
  cacheio.cmd.payload.address := 0x0
  cacheio.cmd.payload.wdata := 0x0 // not writing
  cacheio.cmd.payload.wmask := 0xf
  cacheio.cmd.payload.memwrite := False // read
  cacheio.cmd.payload.procwrite := False
  cacheio.cmd.payload.inputFromMem := True // this is mem read/write

  /** --------- */

  /** AES IO --------- */
  val aesCache_enc = master(AES_EncIO(aes_EncConfig)) // crypto core

  /** fix AES ENC to full data size */
  aesCache_enc.data_size := B("1111").asUInt

  /** fix aad_vld to false as not used */
  aesCache_enc.cmd.payload.aad_vld := False

  /** --------- */
  /** AXI IO --------- */
  val axiio = master(writeBackAXIIO(context.config.dbusConfig, idWidth = 0 bits))

  /** set default outputs */
  axiio.ibusCacheAXI.cmd.valid := False
  axiio.ibusCacheAXI.cmd.payload.address := 0x0
  axiio.ibusCacheAXI.cmd.payload.write := False
  axiio.ibusCacheAXI.cmd.payload.wdata := 0x0
  axiio.ibusCacheAXI.cmd.payload.id := 0x0
  axiio.ibusCacheAXI.cmd.payload.wmask := 0xf

  /** ToDo we say rsp.ready is always true here even though it is not used for a cmd write. We do
    * this because it is used as the default condition by the controller and setting rsp.ready to
    * low can crash the simulation. This is a work-around until the problem is resolved
    */
  axiio.ibusCacheAXI.rsp.ready := True // default unless set in state machine

  /** --------- */
  /** END INPUTS/OUTPUTS */

  /** INPUT READ MUX - SIGNALS */
  /** Input read data mux signals to get read data from memory into 128-bit blocks */
  // address as if going out to memory
  val currentReadAddress: UInt = Reg(UInt(context.config.xlen bits)) init (0)
  // decrement until get to zero
  // ToDo size needs to be generic based on batch size, doesn't always need to be this big
  val endCacheCmdReadLength: UInt = Reg(UInt(context.config.xlen bits)) init (0)
  val endCacheRspReadLength: UInt = Reg(UInt(context.config.xlen bits)) init (0)

  /** reads in 4 words at a time - counter wraps round after 3 */
  val currentReadBlock: UInt =
    Reg(UInt((aes_EncConfig.dataWidth.value / 128 + 1) bits)) init (0)
  val muxReadReg: UInt = Reg(UInt(aes_EncConfig.dataWidth)) init (0) // 128 bit block size
  val muxReadRegValid: Bool = Reg(Bool) init (False) // valid every 4th read
  val lastRegValid: Bool = Reg(Bool) init (False) // valid when last block in batch

  /** ---------------------------------------------------------------------- */
  /** OUTPUT WRITE MUX - SIGNALS */
  /** reads in 4 words at a time - counter wraps round after 3 */
  val currentWriteBlock: UInt =
    Reg(UInt((aes_EncConfig.dataWidth.value / 128 + 1) bits)) init (0)
  val wdata: UInt = Reg(UInt(context.config.xlen bits)) init (0) // data to be written to cache
  val wdataValid: Bool = Reg(Bool) init (False) // valid every 4th read
  val writeReady: Bool = Reg(Bool) init (False) // READY every 4th read
  // start address that gets incremented
  val startWriteAddress: UInt = Reg(UInt(context.config.xlen bits)) init (0)
  // ToDo size needs to be generic based on batch size, doesn't always need to be this big
  val currentWriteLength: UInt = Reg(UInt(context.config.xlen bits)) init (0)
  val currentWriteAddress: UInt = Reg(UInt(context.config.xlen bits)) init (0)
  // address as if going out to CACHE
  val writeAddress: UInt = Reg(UInt(context.config.xlen bits)) init (0)
  val counterBlock: UInt = Reg(UInt((aes_EncConfig.dataWidth.value / 128 + 1) bits)) init (0)
  // decrement until get to zero
  val endWriteLength: UInt = Reg(UInt(context.config.xlen bits)) init (0)

  val TagReg: UInt = Reg(UInt(aes_EncConfig.dataWidth)) init (0) // 128 bit block size
  val IVReg: UInt = Reg(UInt(aes_EncConfig.dataWidth)) init (0) // 128 bit block size
  val IVRegValid: Bool = Reg(Bool) init (False) // valid after 4th read

  /** ---------------------------------------------------------------------- */

  /** INPUT DATA FIFO TO CRYPTO CORE */
  /** ToDo - remove 128bit key, & gold tag from fifo input because it is set in register which is
    * more efficient
    */
  val inputFifo = StreamFifo(
    // dataType = AES_EncCmd(aes_EncConfig),
    dataType = AES_EncCmdFIFO(aes_EncConfig),
    depth = encryptConfig.aesInputFifoDepth
  )
  // val streamReadInput, streamReadOutput = Stream(AES_EncCmd(aes_EncConfig))
  val streamReadInput, streamReadOutput = Stream(AES_EncCmdFIFO(aes_EncConfig))
  inputFifo.io.push << streamReadInput
  inputFifo.io.pop >> streamReadOutput

  /** stop reading data from cache if buffer nearly full */
  val inputFifoNearlyFull: Bool = Bool()
  when(inputFifo.io.availability < (encryptConfig.aesInputFifoDepth - 1)) {
    inputFifoNearlyFull := True
  } otherwise {
    inputFifoNearlyFull := False
  }

  /** ---------------------------------------------------------------------- */

  /** ---------------------------------------------------------------------- */

  /** OUTPUT DATA FIFO FROM CRYPTO CORE */
  // Fill outputFifo with encrypted data
  // output data FIFO
  val outputFifo = StreamFifo(
    // dataType = UInt(aes_EncConfig.dataWidth.value bits),
    dataType = AES_EncRsp(aes_EncConfig),
    depth = encryptConfig.aesOutputFifoDepth
  )
  // val streamWriteInput, streamWriteOutput = Stream(UInt(aes_EncConfig.dataWidth.value bits))
  val streamWriteInput, streamWriteOutput = Stream(AES_EncRsp(aes_EncConfig))
  outputFifo.io.push << streamWriteInput
  outputFifo.io.pop >> streamWriteOutput

  /** hold output data until all row of data multiplexed onto 32bit bus by state machine mux */
  streamWriteOutput.ready := False //

  /** ---------------------------------------------------------------------- */

  /** tag address calculations */
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

  /** state machine to read from cache memory */
  val readCacheFsm = new StateMachine {

    val idle = new State with EntryPoint
    val readIVState = new State
    val readCacheState = new State

    idle.whenIsActive {
      when(controllerio.cmd.valid) {

        /** set up read parameters */
        currentReadAddress := controllerio.cmd.payload.batchAddr.asUInt
        endCacheCmdReadLength := encryptConfig.batchLength
        endCacheRspReadLength := encryptConfig.batchLength
        currentReadBlock := 0
        muxReadRegValid := False
        lastRegValid := False
        IVRegValid := False // default unless set below to go into FIFO

        /** registered for AES */
        in_keyReg := controllerio.cmd.payload.key
        IVReg := controllerio.cmd.payload.IV.asUInt

        /** from tag address calculations */
        tagAddrReg := tagAddr
        goto(readIVState)
      }
    }

    /** 1. send IV to AES first */
    readIVState.whenIsActive {
      lastRegValid := False
      IVRegValid := True
      muxReadRegValid := True
      muxReadReg := IVReg // ToDo currently 128bits but could be size of IV (96 bits) and rest set to zero
      goto(readCacheState)
    }

    /** 2. then send data to AES to be encrypted */
    readCacheState.whenIsActive {
      lastRegValid := False
      IVRegValid := False
      muxReadRegValid := False

      /** read until end of batch length, pause if fifo full */
      // when(!(endCacheCmdReadLength === 0)) {
      when(!(endCacheCmdReadLength === 0) & !inputFifoNearlyFull) {
        cacheio.cmd.valid := True
        cacheio.cmd.payload.address := currentReadAddress.asBits
        currentReadAddress := currentReadAddress + 4 // address out to cache (goes up in 4)
        endCacheCmdReadLength := endCacheCmdReadLength - 4 // reduce in 4's too
      }

      /** put data into registered mux */
      /** fixed at 128 bit block */
      when(cacheio.rsp.valid) {
        when(currentReadBlock === 0) {
          muxReadReg(31 downto 0) := cacheio.rsp.payload.rdata.asUInt
        }
        when(currentReadBlock === 1) {
          muxReadReg(63 downto 32) := cacheio.rsp.payload.rdata.asUInt
        }
        when(currentReadBlock === 2) {
          muxReadReg(95 downto 64) := cacheio.rsp.payload.rdata.asUInt
        }
        when(currentReadBlock === 3) {
          muxReadReg(127 downto 96) := cacheio.rsp.payload.rdata.asUInt
          muxReadRegValid := True

          /** check if will be last */
          when((endCacheRspReadLength - 4) === 0) {
            lastRegValid := True
          }
        }
        currentReadBlock := currentReadBlock + 1 // wraps round after 3 for 128 bit block
        endCacheRspReadLength := endCacheRspReadLength - 4 // reduce in 4's too
      }

      /** wait for data to be written to memory */
      when(out_doneReg) {
        goto(idle)
      }
    }

  }

  /** ---------------------------------------------------------------------- */

  /** CRYPTO CORE */
  /** connect read data mux to fifo input to the core */
  streamReadInput.payload.vector_vld := IVRegValid
  streamReadInput.payload.key_vld := True // will be true when valid is true
  streamReadInput.payload.block := muxReadReg.asBits
  streamReadInput.payload.pt_vld := muxReadRegValid & !IVRegValid
  streamReadInput.payload.last_word := lastRegValid

  /** valid fifo input */
  streamReadInput.valid := muxReadRegValid
  // streamReadInput.payload.key := 0x0 // removed from fifo, key in reg
  // streamReadInput.payload.aad_vld := False // removed from fifo, not used

  /** connect key to crypto core directly */
  aesCache_enc.cmd.payload.key := in_keyReg

  /** connect inputFifo to crypto core */
  streamReadOutput.ready := aesCache_enc.cmd.ready
  aesCache_enc.cmd.valid := streamReadOutput.valid
  aesCache_enc.cmd.payload.block := streamReadOutput.payload.block.asBits
  aesCache_enc.cmd.payload.last_word := streamReadOutput.payload.last_word
  aesCache_enc.cmd.payload.vector_vld := streamReadOutput.payload.vector_vld
  aesCache_enc.cmd.payload.key_vld := streamReadOutput.payload.key_vld
  aesCache_enc.cmd.payload.pt_vld := streamReadOutput.payload.pt_vld

  /** connect crypto core to output fifo */
  streamWriteInput.valid := aesCache_enc.rsp.valid
  streamWriteInput.payload := aesCache_enc.rsp.payload

  /** ---------------------------------------------------------------------- */

  /** since we are reading from cache, we can read from cache and write to memory at the same time.
    * we don't need to wait for each other. we can write as soon as the data is ready
    */
  val writeMemFsm = new StateMachine {

    val idle = new State with EntryPoint
    val writeDataState = new State
    val writeTagState = new State
    val writeIVState = new State
    val doneState = new State

    idle.whenIsActive {
      out_doneReg := False
      currentWriteBlock := 0
      wdataValid := False
      writeReady := False
      currentWriteLength := encryptConfig.batchLength
      when(controllerio.cmd.valid) {

        /** set up write parameters */
        currentWriteAddress := controllerio.cmd.payload.batchAddr.asUInt
        endWriteLength := encryptConfig.batchLength
        goto(writeDataState)
      }
    }

    writeDataState.whenIsActive {
      wdataValid := False
      out_doneReg := False
      axiio.ibusCacheAXI.cmd.valid := False

      /** write until end of length required */
      when(!(currentWriteLength === 0)) {

        /** only extract data out the buffer when it is valid */
        when(streamWriteOutput.valid) {
          when(streamWriteOutput.payload.data_vld) {
            axiio.ibusCacheAXI.cmd.valid := True
            axiio.ibusCacheAXI.cmd.payload.address := currentWriteAddress
            axiio.ibusCacheAXI.cmd.payload.write := True
            when(counterBlock === 0) {
              axiio.ibusCacheAXI.cmd.payload.wdata := streamWriteOutput.payload
                .Out_data(31 downto 0)
                .asUInt
            }
            when(counterBlock === 1) {
              axiio.ibusCacheAXI.cmd.payload.wdata := streamWriteOutput.payload
                .Out_data(63 downto 32)
                .asUInt
            }
            when(counterBlock === 2) {
              axiio.ibusCacheAXI.cmd.payload.wdata := streamWriteOutput.payload
                .Out_data(95 downto 64)
                .asUInt
            }
            when(counterBlock === 3) {
              axiio.ibusCacheAXI.cmd.payload.wdata := streamWriteOutput.payload
                .Out_data(127 downto 96)
                .asUInt
            }
          }
        }
        when(streamWriteOutput.valid & axiio.ibusCacheAXI.cmd.ready) {
          currentWriteAddress := currentWriteAddress + 4
          counterBlock := counterBlock + 1
          currentWriteLength := currentWriteLength - 4
          when(counterBlock === 3) {
            streamWriteOutput.ready := True // pulse high for 1 clock cycle until get next valid data
          }
        }
      } otherwise {
        currentWriteAddress := tagAddrReg.asUInt // load new address with tag address
        goto(writeTagState)
      }
    }

    writeTagState.whenIsActive {

      /** only extract data out the buffer when it is valid */
      when(streamWriteOutput.valid) {
        when(streamWriteOutput.payload.tag_vld) {
          axiio.ibusCacheAXI.cmd.valid := True
          axiio.ibusCacheAXI.cmd.payload.address := currentWriteAddress
          axiio.ibusCacheAXI.cmd.payload.write := True
          when(counterBlock === 0) {
            axiio.ibusCacheAXI.cmd.payload.wdata := streamWriteOutput.payload
              .Out_data(31 downto 0)
              .asUInt
          }
          when(counterBlock === 1) {
            axiio.ibusCacheAXI.cmd.payload.wdata := streamWriteOutput.payload
              .Out_data(63 downto 32)
              .asUInt
          }
          when(counterBlock === 2) {
            axiio.ibusCacheAXI.cmd.payload.wdata := streamWriteOutput.payload
              .Out_data(95 downto 64)
              .asUInt
          }
          when(counterBlock === 3) {
            axiio.ibusCacheAXI.cmd.payload.wdata := streamWriteOutput.payload
              .Out_data(127 downto 96)
              .asUInt
          }
        }
      }
      when(streamWriteOutput.valid & axiio.ibusCacheAXI.cmd.ready) {
        currentWriteAddress := currentWriteAddress + 4
        counterBlock := counterBlock + 1
        when(counterBlock === 3) {
          streamWriteOutput.ready := True // pulse high for 1 clock cycle until get next valid data
          goto(writeIVState)
        }
      }
    }

    writeIVState.whenIsActive {

      /** only extract data out the buffer when it is valid */
      axiio.ibusCacheAXI.cmd.valid := True
      axiio.ibusCacheAXI.cmd.payload.address := currentWriteAddress
      axiio.ibusCacheAXI.cmd.payload.write := True
      when(counterBlock === 0) {
        axiio.ibusCacheAXI.cmd.payload.wdata := IVReg(31 downto 0)
      }
      when(counterBlock === 1) {
        axiio.ibusCacheAXI.cmd.payload.wdata := IVReg(63 downto 32)
      }
      when(counterBlock === 2) {
        axiio.ibusCacheAXI.cmd.payload.wdata := IVReg(95 downto 64)
      }
      when(counterBlock === 3) {
        axiio.ibusCacheAXI.cmd.payload.wdata := IVReg(127 downto 96)
      }

      when(axiio.ibusCacheAXI.cmd.ready) {
        currentWriteAddress := currentWriteAddress + 4
        counterBlock := counterBlock + 1
        when(counterBlock === 3) {
          // we can finish straight away
          out_doneReg := True // used by readCacheFsm to finish
          controllerio.rsp.payload.done := True
          controllerio.rsp.valid := True
          goto(doneState)
        }
      }
    }

    /** need this because need a delay after done */
    doneState.whenIsActive {
      goto(idle)
    }

  }

}
