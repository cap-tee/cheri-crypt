package riscv.plugins.cheriEncrypt

import spinal.core._
import spinal.lib._
import spinal.lib.fsm._

import riscv._
import riscv.plugins.cheri
import riscv.plugins.cheri._

/** This is the CInvokeEncrypt instruction which replaces CInvoke */

class CInvokeEncrypt(memStage: Stage)(implicit cheriContext: Context, cacheConfig: cacheConfig)
    extends Plugin[Pipeline] {
  private object Data {

    /** define CInvokeEncrypt instruction flag, this goes high when instruction is called */
    object CINVOKE_ENCRYPT extends PipelineData(Bool())
  }

  /** CInvokeEncrypt setup - set up instruction flag */
  override def setup(): Unit = {
    pipeline.service[DecoderService].configure { config =>
      config.addDefault(
        Map(
          Data.CINVOKE_ENCRYPT -> False
        )
      )

      /** CInvokeEncrypt (codecap, datacap, none) => CCx */
      /** Except that it uses rd internally, dataCap goes to c31 so format becomes: CCC */
      config.addDecoding(
        Opcodes.CInvokeEncrypt,
        cheri.InstructionType.R_CCC,
        Map(
          Data.CINVOKE_ENCRYPT -> True
        )
      )
      config.setFixedRegisters(Opcodes.CInvokeEncrypt, rd = Some(31))
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

      /** needs the cheri. in cheri.ExceptionCause else need to specifically import above */
      def except(cause: cheri.ExceptionCause, capIdx: CapIdx) = {
        val handler = pipeline.service[cheri.ExceptionHandler]
        // use from cheri plugins services.scala: def except(stage: Stage, cause: ExceptionCause, capIdx: CapIdx): Unit = {
        handler.except(memStage, cause, capIdx)
      }

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

      /** -----------------------------------------------------------------------------------------
        */
      /** INPUTS/OUTPUTS */
      /** IO to Key generation logic */
      /** Create the master side of the KeyGenWrapperIo */
      val KeyGenWrapperIo = pipeline.service[KeyCInvokeIOService].getKeyCInvokeIo(memStage)

      /** set default IO driving values, unless set below */
      KeyGenWrapperIo.cmd.getKey := False
      KeyGenWrapperIo.cmd.valid := False
      KeyGenWrapperIo.CInvokeSelect := False
      KeyGenWrapperIo.cmd.payload.otype := 0x0
      KeyGenWrapperIo.decrypt_error := False

      /** IO control to cache */
      /** Create the master side of the control to the ICache */
      val triggerICache =
        pipeline.service[ICacheCInvokeIoService].getICacheCInvokeIo(memStage)

      /** set default IO driving values, unless set below */
      triggerICache.invokeTrigger := False
      triggerICache.PCCboundsBase := 0
      triggerICache.PCCboundsTop := 0
      triggerICache.cmdAddrboundsBase := 0
      triggerICache.cmdAddrboundsTop := 0
      triggerICache.cmdAddrboundsLen := 0
      triggerICache.Key := 0

      /** Create the master side of the control to the DCache */
      val triggerDCache = pipeline.service[DCacheCInvokeIoService].getDCacheCInvokeIo(memStage)

      /** set default IO driving values, unless set below */
      triggerDCache.invokeTrigger := False
      triggerDCache.PCCboundsBase := 0
      triggerDCache.PCCboundsTop := 0
      triggerDCache.cmdAddrboundsBase := 0
      triggerDCache.cmdAddrboundsTop := 0
      triggerDCache.cmdAddrboundsLen := 0
      triggerDCache.Key := 0
      triggerDCache.otype := 0
      triggerDCache.NextIVCount := 0

      /** END INPUTS/OUTPUTS */

      /** CInvoke_Encrypt state machine */
      val CInvokeEncryptFsm = new StateMachine {

        val idle = StateEntryPoint()
        val getKeyState = State()
        idle
          .whenIsActive {

            /** if a decrypt error is raised at any point we need to raise an exception */
            /** this will happen when the encryption caches are in operation after a CInvoke and
              * when this state machine is back in the idle state so we need to check here. Also
              * exceptions are raised from a stage component and we need to release the pipeline so
              * the processor can jump to the trap vector
              */
            /** this is an authentication tag error on decryption */
            when(triggerDCache.decrypt_error | triggerICache.decrypt_error) {
              arbitration.isReady := True
              KeyGenWrapperIo.decrypt_error := True // clear keys out of key table
              except(EncryptExceptionCause.EncTagViolation, cs1Idx) // raise exception

              /** check for a CInvokeEncrypt instruction */
            } elsewhen (arbitration.isValid && value(Data.CINVOKE_ENCRYPT)) {
              arbitration.rs1Needed := True
              arbitration.rs2Needed := True
              when(!arbitration.isStalled) {
                val target = cs1.address
                target.lsb := False

                when(!cs1.tag) {
                  except(cheri.ExceptionCause.TagViolation, cs1Idx)
                } elsewhen (!cs2.tag) {
                  except(cheri.ExceptionCause.TagViolation, cs2Idx)
                } elsewhen (!cs1.isSealed) {
                  except(cheri.ExceptionCause.SealViolation, cs1Idx)
                } elsewhen (!cs2.isSealed) {
                  except(cheri.ExceptionCause.SealViolation, cs2Idx)
                } elsewhen (cs1.otype.value =/= cs2.otype.value) {
                  except(cheri.ExceptionCause.TypeViolation, cs1Idx)
                } elsewhen (!cs1.perms.cinvoke) {
                  except(cheri.ExceptionCause.PermitCInvokeViolation, cs1Idx)
                } elsewhen (!cs2.perms.cinvoke) {
                  except(cheri.ExceptionCause.PermitCInvokeViolation, cs2Idx)
                } elsewhen (!cs1.perms.execute) {
                  except(cheri.ExceptionCause.PermitExecuteViolation, cs1Idx)
                } elsewhen (cs2.perms.execute) {
                  except(cheri.ExceptionCause.PermitExecuteViolation, cs2Idx)
                } elsewhen (target < cs1.base) {
                  except(cheri.ExceptionCause.LengthViolation, cs1Idx)
                } elsewhen (target >= cs1.top) {
                  except(cheri.ExceptionCause.LengthViolation, cs1Idx)

                  /** passed all standard CInvoke permission checks */
                  /** now check encryption - throw exception if encrypt bit for both caps is not the
                    * same
                    */
                } elsewhen (cs1.perms.encrypt =/= cs2.perms.encrypt) {
                  except(EncryptExceptionCause.PermitEncryptionViolation, cs1Idx)
                } otherwise {

                  /** now check if do standard CInvoke, or continue to encryption */
                  when(!cs1.perms.encrypt & !cs2.perms.encrypt) {

                    /** Normal CInvoke in 1 cycle */
                    val targetPcc = PackedCapability()
                    targetPcc.assignFrom(cs1)
                    targetPcc.otype.value.allowOverride
                    targetPcc.otype.unseal()
                    pipeline.service[PccService].jump(memStage, targetPcc, cs1Idx)

                    val cd = PackedCapability()
                    cd.assignFrom(cs2)
                    cd.otype.value.allowOverride
                    cd.otype.unseal()
                    output(cheriContext.data.CD_DATA).assignFrom(cd)
                    output(pipeline.data.RD_DATA_VALID) := True

                  } otherwise {

                    /** Take control as will take more than 1 clk cycle */
                    arbitration.isReady := False

                    /** Get key for given otype */
                    KeyGenWrapperIo.CInvokeSelect := True
                    KeyGenWrapperIo.cmd.getKey := True
                    KeyGenWrapperIo.cmd.payload.otype := cs2.otype.value
                    KeyGenWrapperIo.cmd.valid := True
                    goto(getKeyState)
                  }
                }
              }
            }
          }
        // --
        getKeyState
          .whenIsActive {

            /** Keep control */
            arbitration.isReady := False

            /** Control input to key management */
            KeyGenWrapperIo.CInvokeSelect := True

            /** wait for key but also check for error condition */
            when(KeyGenWrapperIo.table_error) {

              /** release control and throw an exception here if there is a key table error */
              arbitration.isReady := True
              KeyGenWrapperIo.decrypt_error := True // reset keys
              except(EncryptExceptionCause.EncKeyTableViolation, cs2Idx)
              goto(idle)
            } elsewhen (KeyGenWrapperIo.rsp.valid) {

              /** Trigger instruction cache encryption circuit */
              triggerICache.invokeTrigger := True
              triggerICache.PCCboundsBase := cs1.base
              triggerICache.PCCboundsTop := cs1.top
              triggerICache.cmdAddrboundsBase := cs1.base // PCC for Icache
              triggerICache.cmdAddrboundsTop := cs1.top
              triggerICache.cmdAddrboundsLen := cs1.length
              triggerICache.Key := KeyGenWrapperIo.rsp.payload.key

              /** Trigger data cache encryption circuit */
              triggerDCache.invokeTrigger := True
              triggerDCache.PCCboundsBase := cs1.base
              triggerDCache.PCCboundsTop := cs1.top
              triggerDCache.cmdAddrboundsBase := cs2.base // DC for Dcache
              triggerDCache.cmdAddrboundsTop := cs2.top
              triggerDCache.cmdAddrboundsLen := cs2.length
              triggerDCache.Key := KeyGenWrapperIo.rsp.payload.key
              // extra for data side
              triggerDCache.otype := cs1.otype.value // needed for after writeback encryption to store IV count in table
              triggerDCache.NextIVCount := KeyGenWrapperIo.rsp.payload.NextIVCount // needed for writeback encryption

              /** do rest of normal CInvoke */
              val targetPcc = PackedCapability()
              targetPcc.assignFrom(cs1)
              targetPcc.otype.value.allowOverride
              targetPcc.otype.unseal()
              pipeline.service[PccService].jump(memStage, targetPcc, cs1Idx)

              val cd = PackedCapability()
              cd.assignFrom(cs2)
              cd.otype.value.allowOverride
              cd.otype.unseal()
              output(cheriContext.data.CD_DATA).assignFrom(cd)
              output(pipeline.data.RD_DATA_VALID) := True

              arbitration.isReady := True // release bus

              goto(idle)
            }
          }
      }

    }
  }
}
