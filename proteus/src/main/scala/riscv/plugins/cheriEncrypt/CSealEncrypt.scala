package riscv.plugins.cheriEncrypt

import spinal.core.{UInt, _}
import spinal.lib._
import spinal.lib.fsm._
import riscv._
import riscv.plugins.cheri
import riscv.plugins.cheri._
import AESEngine.AES_EncConfig

/** This is the CSealEncrypt instruction which replaces CSeal */

/** define generics */
case class EncryptConfig(
    fixedIV: Int, // fixed part of IV (32 bits) - determines device or context
    batchLength: Int, // length of a batch in bytes - needs to be in multiples of 16bytes (128 bits)
    lengthTagIV: Int, // size of tag and IV in bytes
    aesInputFifoDepth: Int, // 8
    aesOutputFifoDepth: Int // 8
) {

  /** can't include in list above because dependent on above parameters, so have to define as
    * method, can then index as generics the same as above
    */
  def fixedIVvalue: UInt = U(fixedIV, 32 bits)
  def batchLengthvalue: UInt = U(batchLength, 32 bits)
  def fixedAuthTagLengthInMem: UInt = lengthTagIV / 2 // bytes - storage size in memory
  def fixedIVLengthInMem: UInt = lengthTagIV / 2 // bytes - storage size in memory

  def lengthTagIVinWords: Int =
    lengthTagIV / 4 // length in number of 32 bit data words (each 32bit data word is 4 bytes)

  /** methods for bit shifts for calculation of tag address */
  /** batch length bit shift */
  def batchShiftBits: Int = log2Up(batchLength)

  /** tagIV length bit shift */
  def tagShiftBits: Int = log2Up(lengthTagIV)

  /** Tag length from base bit shift calculation */
  def tagCalcShiftBits: Int = batchShiftBits - tagShiftBits

  /** number of bits to represent burstLength for readcacheline cmd burst */
  def burstLengthBits: Int = log2Up(aesInputFifoDepth * 4)
}

/** CSealEncrypt instruction */
class CSealEncrypt(memStage: Stage)(implicit
    cheriContext: Context,
    cacheConfig: cacheConfig,
    encryptConfig: EncryptConfig,
    aes_EncConfig: AES_EncConfig
) extends Plugin[Pipeline] {
  private object Data {

    /** define CSealEncrypt instruction flag, this goes high when instruction is called */
    object CSEAL_ENCRYPT extends PipelineData(Bool())
  }

  /** CSealEncrypt setup - set up instruction flag */
  override def setup(): Unit = {
    pipeline.service[DecoderService].configure { config =>
      config.addDefault(
        Map(
          Data.CSEAL_ENCRYPT -> False
        )
      )

      /** Instruction types C-cap x-none, R-gpr */
      /** Naming scheme: <FORMAT>_<RS1_TYPE><RS2_TYPE><RD_TYPE> */
      /** CSealEncrypt (enccap, inputcap, sealcap) => CCC */
      config.addDecoding(
        Opcodes.CSealEncrypt,
        cheri.InstructionType.R_CCC,
        Map(
          Data.CSEAL_ENCRYPT -> True
        )
      )

    }
  }

  override def build(): Unit = {

    /** This creates a new area in the memory stage, not a new component */
    memStage plug new Area {
      import memStage._

      val cs1 = value(cheriContext.data.CS1_DATA) // capability to encrypt
      val cs2 = value(cheriContext.data.CS2_DATA) // seal
      val cs2Address = cs2.address
      val cs1Address = cs1.address
      val cs1Length = cs1.length
      val cs1Idx = CapIdx.gpcr(value(pipeline.data.RS1))
      val cs2Idx = CapIdx.gpcr(value(pipeline.data.RS2))

      /** IV 64 bit counter */
      val IVCounter64Reg: UInt = Reg(UInt(width = BitCount(64))) init 0

      /** saved registers for encryption of a single batch */
      val dataAddrReg: UInt = Reg(UInt(width = BitCount(cheriContext.config.xlen))) init 1
      val tagAddrReg: UInt = Reg(UInt(width = BitCount(cheriContext.config.xlen))) init 0
      val validReg: Bool = Reg(Bool()) init (False)
      val keyReg: Bits = Reg(Bits(aes_EncConfig.keyWidth)) init 0
      val startReg: Bool = Reg(Bool()) init (False)
      val cs1LengthReg: UInt = Reg(UInt(cheriContext.config.xlen bits)) // new cap length resized

      /** ------------------------------------------ */
      /** INPUTS/OUTPUTS */
      /** IO to Key generation logic */
      /** Create the master side of the KeyGenWrapperIo - KeyCSealIOService defined in
        * KeyGenWrapper2.scala
        */
      val KeyGenWrapperIo = pipeline.service[KeyCSealIOService].getKeyCSealIo(memStage)

      /** set default IO driving values, unless set further in code below */
      KeyGenWrapperIo.cmd.payload.genKey := False
      KeyGenWrapperIo.cmd.valid := False
      KeyGenWrapperIo.cmd.payload.otype := 0x0
      KeyGenWrapperIo.cmd.payload.NewNextIVCount := 0x0
      KeyGenWrapperIo.cmd.payload.storeNextIVCount := False
      KeyGenWrapperIo.CSealSelect := False
      KeyGenWrapperIo.encrypt_error := False

      /** IO to CSealEReadWrite */
      /** Create the master side of the CSealInstrIo - CSealInstrIoService defined in
        * CSealEReadWrite.scala
        */
      val CSealInstrIo = pipeline.service[CSealInstrIoService].getCSealInstrIo(memStage)

      /** set default values driven from registers */
      CSealInstrIo.cmd.valid := validReg
      CSealInstrIo.cmd.payload.dataAddress := dataAddrReg
      CSealInstrIo.cmd.payload.authTagAddress := tagAddrReg
      CSealInstrIo.cmd.payload.key := keyReg
      CSealInstrIo.cmd.payload.length := encryptConfig.batchLengthvalue // ToDo always do in batch length so don't need to set here
      CSealInstrIo.cmd.payload.start := startReg

      /** concatenate IV output split into three parts:
        *   1. upper 32 bits - fixed part set as a hardware generic 2. middle 64 bits - counter part
        *      3. lower 32 bits - pad with zeros, this part used internally by crypto core counter
        */
      CSealInstrIo.cmd.payload.IV(127 downto 96) := encryptConfig.fixedIVvalue.asBits // fixed part
      CSealInstrIo.cmd.payload.IV(95 downto 32) := IVCounter64Reg.asBits // counter part
      CSealInstrIo.cmd.payload.IV(31 downto 0) := 0x0 // padding part
      /** END INPUTS / OUTPUTS ------------------------------------------ */

      /** SET UP READY TO USE EXCEPTIONS -------------------------------- */

      /** 1. CHERI exceptions */
      /** needs the cheri. in cheri.ExceptionCause else need to specifically import above */
      def except(cause: cheri.ExceptionCause, capIdx: CapIdx) = {
        val handler = pipeline.service[cheri.ExceptionHandler]
        handler.except(memStage, cause, capIdx)
      }

      /** 2. Encryption exceptions */
      /** separate def for encryption exceptions defined in exception.scala */
      /** However convert cause directly to Int using U(cause.code) to use the second cheri def
        * `except` overload method since cheriEncrypt.ExceptionCause codes are not recognised
        * directly.
        */
      def except(cause: EncryptExceptionCause, capIdx: CapIdx) = {
        val handler = pipeline.service[cheri.ExceptionHandler]
        // use from cheri plugins services.scala: except(stage: Stage, cause: UInt, capIdx: CapIdx): Unit = {
        handler.except(memStage, U(cause.code), capIdx)
      }

      /** END SET UP READY TO USE EXCEPTIONS -------------------------------- */

      /** CSealEncrypt instruction state machine */

      val CSealEncryptFsm = new StateMachine {

        /** defines used inside state machine only */
        def finish(cd: PackedCapability) = {
          output(cheriContext.data.CD_DATA).assignFrom(cd)
          output(pipeline.data.RD_DATA_VALID) := True
          arbitration.isReady := True // release control as finished instruction
          goto(idle)
        }

        def fail(): Unit = {
          finish(PackedCapability.Null)
        }

        /** Define states for state machine */
        val idle = StateEntryPoint()
        val encStart = State()
        val encryption = State()
        val storeNextIV = State()
        val encFinish = State()

        idle
          .whenIsActive {
            when(arbitration.isValid && value(Data.CSEAL_ENCRYPT)) {
              arbitration.rs1Needed := True
              arbitration.rs2Needed := True
              when(arbitration.isRunning) {

                /** first do the standard CSeal permission checks */
                when(!cs1.tag) {
                  except(cheri.ExceptionCause.TagViolation, cs1Idx)
                } elsewhen (!cs2.tag) {
                  except(cheri.ExceptionCause.TagViolation, cs2Idx)
                } elsewhen (cs1.isSealed) {
                  except(cheri.ExceptionCause.SealViolation, cs1Idx)
                } elsewhen (cs2.isSealed) {
                  except(cheri.ExceptionCause.SealViolation, cs2Idx)
                } elsewhen (!cs2.perms.seal) {
                  except(cheri.ExceptionCause.PermitSealViolation, cs2Idx)
                } elsewhen (cs2Address < cs2.base) {
                  except(cheri.ExceptionCause.LengthViolation, cs2Idx)
                } elsewhen (cs2Address >= cs2.top) {
                  except(cheri.ExceptionCause.LengthViolation, cs2Idx)
                } elsewhen (cs2Address > cheriContext.maxOtype) {
                  except(cheri.ExceptionCause.LengthViolation, cs2Idx)
                } otherwise {

                  /** passed all standard CSeal permission checks */
                  /** now check if do standard CSeal, or continue to encryption */
                  when(!cs1.perms.encrypt) {

                    /** Normal CSeal in 1 cycle */
                    val cd = PackedCapability()
                    cd.assignFrom(cs1)
                    cd.otype.value.allowOverride
                    cd.otype.value := cs2Address.resized
                    finish(cd)
                  } otherwise {

                    /** encrypt and then CSeal */
                    /** do basic encryption check:
                      *   - check that cap length is at least 1 batch size + 1 tag + 1 IV
                      */
                    /** Note for simulation check TrapHandler_exceptionSignals_hasTrapped and
                      * TrapHandler_exceptionSignals_trapCause[3:0] for CHERI exception value of 0A
                      * and check out_CEXC_CAUSE[4:0] for specific CHERI cause
                      */
                    when(
                      cs1Length < (encryptConfig.batchLengthvalue + encryptConfig.fixedAuthTagLengthInMem + encryptConfig.fixedIVLengthInMem)
                    ) {

                      /** reset keys and raise exception */
                      KeyGenWrapperIo.CSealSelect := True
                      KeyGenWrapperIo.encrypt_error := True
                      keyReg := 0x0
                      except(EncryptExceptionCause.EncCapLenViolation, cs1Idx)
                    } otherwise {

                      /** Take control as will take more than 1 clk cycle */
                      arbitration.isReady := False

                      /** Ask for new key to be generated, then do encryption */
                      KeyGenWrapperIo.cmd.genKey := True
                      KeyGenWrapperIo.cmd.payload.otype := cs2Address.resized // otype (seal)
                      KeyGenWrapperIo.cmd.valid := True
                      KeyGenWrapperIo.CSealSelect := True // enable commands from CSealEncrypt instruction
                      goto(encStart)
                    }
                  }
                }
              }
            }
          }

        encStart
          .whenIsActive {
            arbitration.isReady := False
            KeyGenWrapperIo.CSealSelect := True

            /** wait for key to be generated and then start encryption but also check for error
              * condition and throw an exception here if there is a key table error
              */
            when(KeyGenWrapperIo.table_error) {

              /** reset keys, release processor, throw exception */
              arbitration.isReady := True
              KeyGenWrapperIo.encrypt_error := True
              keyReg := 0x0
              except(EncryptExceptionCause.EncKeyTableViolation, cs2Idx)
              goto(idle)
            } elsewhen (KeyGenWrapperIo.rsp.valid) {

              /** set up first batch of data to be encrypted and set the initial values */
              IVCounter64Reg := KeyGenWrapperIo.rsp.payload.NextIVCount.asUInt // set counter
              dataAddrReg := cs1Address
              tagAddrReg := cs1Address + cs1Length - encryptConfig.fixedAuthTagLengthInMem - encryptConfig.fixedIVLengthInMem
              cs1LengthReg := encryptConfig.batchLengthvalue // new cap length
              keyReg := KeyGenWrapperIo.rsp.payload.key
              validReg := True
              startReg := True
              goto(encryption)

            }
          }

        encryption.whenIsActive {
          arbitration.isReady := False
          validReg := False
          startReg := False
          when(CSealInstrIo.rsp.valid) {
            when(CSealInstrIo.rsp.payload.done) {

              /** do another batch if nextTagAddr > nextDataAddr - update the registers with new
                * values
                */
              IVCounter64Reg := IVCounter64Reg + 1 // add 1 to counter ready for next batch
              when(
                (tagAddrReg - encryptConfig.fixedAuthTagLengthInMem - encryptConfig.fixedIVLengthInMem) > (dataAddrReg + encryptConfig.batchLengthvalue)
              ) {
                dataAddrReg := dataAddrReg + encryptConfig.batchLengthvalue // next batch start address
                tagAddrReg := tagAddrReg - encryptConfig.fixedAuthTagLengthInMem - encryptConfig.fixedIVLengthInMem // next batch tag/IV address
                cs1LengthReg := cs1LengthReg + encryptConfig.batchLengthvalue // new cap length
                validReg := True // do another batch
                startReg := True

                /** Wait in this state until multiple batches finished */
                goto(encryption)
              } otherwise {

                /** otherwise store IVCount and finish */
                goto(storeNextIV)
              }
            }
          }
        }

        storeNextIV.whenIsActive {
          arbitration.isReady := False

          /** store NextIVcount in table */
          KeyGenWrapperIo.cmd.payload.storeNextIVCount := True
          KeyGenWrapperIo.cmd.payload.NewNextIVCount := IVCounter64Reg.asBits
          KeyGenWrapperIo.cmd.payload.otype := cs2Address.resized // otype (seal)
          KeyGenWrapperIo.cmd.valid := True
          KeyGenWrapperIo.CSealSelect := True

          goto(encFinish)
        }

        encFinish.whenIsActive {
          arbitration.isReady := False
          KeyGenWrapperIo.CSealSelect := True

          /** wait for IV to be stored */
          when(KeyGenWrapperIo.IVcountsavedDone) {

            /** clear key out of register when finished */
            keyReg := 0x0

            /** check for encryption length error. At end if the cs1 bounds were set correctly then
              * tagAddrReg = dataAddrReg + batch length
              */
            when(!(tagAddrReg === (dataAddrReg + encryptConfig.batchLengthvalue))) {

              /** reset keys in table and release processor when there is an encryption error and
                * throw an exception
                */
              KeyGenWrapperIo.encrypt_error := True
              arbitration.isReady := True
              except(EncryptExceptionCause.EncCapLenViolation, cs1Idx)
              goto(idle)
            } otherwise {

              /** Do proper seal here */
              val cd = PackedCapability()
              cd.assignFrom(cs1)
              cd.otype.value.allowOverride
              cd.otype.value := cs2Address.resized

              /** resize upper bounds after encryption */
              cd.length.allowOverride
              cd.length := cs1LengthReg
              finish(cd)
            }
          }
        }
      }

      /** END CSealEncrypt instruction state machine */

    }
  }
}
