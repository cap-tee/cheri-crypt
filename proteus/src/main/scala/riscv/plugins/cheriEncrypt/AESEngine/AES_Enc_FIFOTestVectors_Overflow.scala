package riscv.plugins.cheriEncrypt.AESEngine
import spinal.core._
//import spinal.crypto.symmetric.SymmetricCryptoBlockConfig
import spinal.lib.fsm.{EntryPoint, State, StateMachine}
import spinal.lib._

/** NIST test vectors for AES-CTR-GCM (counter mode for GCM) including GHASH algorithm encryption /
  * decryption
  */

class AES_Enc_FIFOTestVectors_Overflow(dataWidth: BitCount) extends Component {
  val config = AES_EncConfig(
    dataWidth = dataWidth,
    keyWidth = dataWidth
  )

  /** assign generics - at moment all must be same as key of 128 bits */
  val io = new Bundle {
    val in_start = in Bool ()
    val out_pass = out Bool ()

    val out_valid = out Bool ()
    val out_vector_vld = out Bool ()
    val out_aad_vld = out Bool ()
    val out_key_vld = out Bool ()
    val out_pt_vld = out Bool ()
    val out_block = out Bits (config.dataWidth)
    val out_key = out Bits (config.keyWidth)
    val out_last_word = out Bool ()
    val out_data_size = out UInt (4 bits)

    val in_aesoutput_dataValid = in Bool ()
    val in_aesoutput_data = in Bits (config.dataWidth)
    val in_data_vld = in Bool ()
    val in_tag_vld = in Bool ()
    val in_ready = in Bool ()
  }

  val vector_vldReg: Bool = Reg(Bool) init (False)
  val pt_vldReg: Bool = Reg(Bool) init (False)
  val aad_vldReg: Bool = Reg(Bool) init (False)
  val key_vldReg: Bool = Reg(Bool) init (False)
  val dataReg: Bits = Reg(Bits(128 bits)) init (0)
  val keyReg: Bits = Reg(Bits(128 bits)) init (0)
  val sizeReg: Bits = Reg(Bits(4 bits)) init (0)
  val last_wordReg: Bool = Reg(Bool) init (False)
  val validReg: Bool = Reg(Bool) init (False)
  sizeReg := B("1111")

  val passReg: Bool = Reg(Bool) init (False)
  val counterReg: UInt = Reg(UInt(4 bits)) init (0)
  val counterRegOut: UInt = Reg(UInt(128 bits)) init (0)

  /** Input test vectors  - Test case 3* */
  val key0 = UInt(128 bits);
  key0 := U"hfeffe9928665731c6d6a8f9467308308"; // include h for hex - AES key
  // val keyH0 = UInt(128 bits);  keyH0 := U"hb83b533708bf535d0aa6e52980d53b78"; //include h for hex - hash key
  val initVec0 = UInt(128 bits);
  initVec0 := U"hcafebabefacedbaddecaf88800000001"; // include h for hex
  // ONLY THE INPUT DATA CHANGES
  val plainData10 = UInt(128 bits);
  plainData10 := U"hd9313225f88406e5a55909c5aff5269a"; // include h for hex
  val plainData20 = UInt(128 bits);
  plainData20 := U"h86a7a9531534f7da2e4c303d8a318a72"; // include h for hex
  val plainData30 = UInt(128 bits);
  plainData30 := U"h1c3c0c95956809532fcf0e2449a6b525"; // include h for hex
  val plainData40 = UInt(128 bits);
  plainData40 := U"hb16aedf5aa0de657ba637b391aafd255"; // include h for hex

  /** output test vectors - test case 3 */
  val cipher10 = UInt(128 bits);
  cipher10 := U"h42831ec2217774244b7221b784d0d49c"; // include h for hex
  val cipher20 = UInt(128 bits);
  cipher20 := U"he3aa212f2c02a4e035c17e2329aca12e"; // include h for hex
  val cipher30 = UInt(128 bits);
  cipher30 := U"h21d514b25466931c7d8f6a5aac84aa05"; // include h for hex
  val cipher40 = UInt(128 bits);
  cipher40 := U"h1ba30b396a0aac973d58e091473f5985"; // include h for hex

  val tag0 = UInt(128 bits); tag0 := U"h4d5c2af327cd64a62cf35abd2ba6fab4"; // include h for hex

  val inputFifo1 = StreamFifo(
    dataType = (AES_EncCmd(config)),
    depth = 8
  )

  val streamDataInput1, streamDataOutput1 = Stream(AES_EncCmd(config))
  inputFifo1.io.push << streamDataInput1
  inputFifo1.io.pop >> streamDataOutput1

  streamDataOutput1.ready := io.in_ready
  io.out_block := streamDataOutput1.payload.block
  io.out_key := streamDataOutput1.payload.key
  io.out_valid := streamDataOutput1.valid
  io.out_vector_vld := streamDataOutput1.payload.vector_vld
  io.out_pt_vld := streamDataOutput1.payload.pt_vld
  io.out_aad_vld := False
  io.out_key_vld := streamDataOutput1.payload.key_vld
  io.out_last_word := streamDataOutput1.payload.last_word
  io.out_data_size := sizeReg.asUInt

  /** assign outputs */
  io.out_pass := passReg

  streamDataInput1.payload.block := dataReg
  streamDataInput1.payload.key := keyReg
  streamDataInput1.valid := validReg
  streamDataInput1.payload.vector_vld := vector_vldReg
  streamDataInput1.payload.pt_vld := pt_vldReg
  streamDataInput1.payload.aad_vld := False
  streamDataInput1.payload.key_vld := key_vldReg
  streamDataInput1.payload.last_word := last_wordReg

  val sm = new StateMachine {
    val sIdle: State = new State with EntryPoint {
      whenIsActive {
        counterReg := 0x0
        when(io.in_start) {
          goto(sFillfifo)
        }
      }
    }

    val sFillfifo: State = new State {
      whenIsActive {
        when(streamDataInput1.ready) {
          when(counterReg === 0) {
            dataReg := initVec0.asBits
            keyReg := key0.asBits
            vector_vldReg := True
            key_vldReg := True
            pt_vldReg := False
            last_wordReg := False
            validReg := True
          }
          when(counterReg === 1) {
            dataReg := plainData10.asBits
            keyReg := key0.asBits
            vector_vldReg := False
            pt_vldReg := True
            key_vldReg := True
            last_wordReg := False
            validReg := True
          }
          when(counterReg === 2) {
            dataReg := plainData20.asBits
            keyReg := key0.asBits
            vector_vldReg := False
            pt_vldReg := True
            key_vldReg := True
            last_wordReg := False
            validReg := True
          }
          when(counterReg === 3) {
            dataReg := plainData30.asBits
            keyReg := key0.asBits
            vector_vldReg := False
            pt_vldReg := True
            key_vldReg := True
            last_wordReg := False
            validReg := True
          }
          when(counterReg === 4) {
            dataReg := plainData40.asBits
            keyReg := key0.asBits
            vector_vldReg := False
            pt_vldReg := True
            key_vldReg := True
            last_wordReg := True
            validReg := True
          }
          when(counterReg === 5) {
            dataReg := initVec0.asBits
            keyReg := key0.asBits
            vector_vldReg := True
            key_vldReg := True
            last_wordReg := False
            pt_vldReg := False
            validReg := True
          }
          when(counterReg === 6) {
            dataReg := plainData10.asBits
            keyReg := key0.asBits
            vector_vldReg := False
            pt_vldReg := True
            key_vldReg := True
            last_wordReg := False
            validReg := True
          }
          when(counterReg === 7) {
            dataReg := plainData20.asBits
            keyReg := key0.asBits
            vector_vldReg := False
            pt_vldReg := True
            key_vldReg := True
            last_wordReg := False
            validReg := True
          }
          when(counterReg === 8) {
            dataReg := plainData30.asBits
            keyReg := key0.asBits
            vector_vldReg := False
            pt_vldReg := True
            key_vldReg := True
            last_wordReg := False
            validReg := True
          }
          when(counterReg === 9) {
            dataReg := plainData40.asBits
            keyReg := key0.asBits
            vector_vldReg := False
            pt_vldReg := True
            key_vldReg := True
            last_wordReg := True
            validReg := True
          }

          when(counterReg > 9) {
            validReg := False
            pt_vldReg := False
            key_vldReg := False
            last_wordReg := False
            goto(sEmptyfifo)
          }

          counterReg := counterReg + 1
        } otherwise {
          validReg := False
          pt_vldReg := False
          key_vldReg := False
          vector_vldReg := False
          last_wordReg := False
          goto(sWait)
        }
      }
    }

    val sWait: State = new State {
      whenIsActive {}
    }

    val sEmptyfifo: State = new State {
      whenIsActive {}
    }

    /** output state machine */
    val smOut = new StateMachine {
      val sIdle: State = new State with EntryPoint {
        whenIsActive {
          passReg := False
          counterRegOut := 0
          when(io.in_start) {
            goto(sEncValues)
          }
        }
      }

      /** Encryption tests */
      val sEncValues: State = new State {
        whenIsActive {
          passReg := False
          when(counterRegOut > 9) {
            goto(sIdle)
          }
          when(io.in_aesoutput_dataValid) {
            when(counterRegOut === 0) {
              when(io.in_aesoutput_data(127 downto 0) === cipher10.asBits) {
                passReg := True
              } otherwise {
                passReg := False
              }
            }
            when(counterRegOut === 1) {
              when(io.in_aesoutput_data(127 downto 0) === cipher20.asBits) {
                passReg := True
              } otherwise {
                passReg := False
              }
            }
            when(counterRegOut === 2) {
              when(io.in_aesoutput_data(127 downto 0) === cipher30.asBits) {
                passReg := True
              } otherwise {
                passReg := False
              }
            }
            when(counterRegOut === 3) {
              when(io.in_aesoutput_data(127 downto 0) === cipher40.asBits) {
                passReg := True
              } otherwise {
                passReg := False
              }
            }
            when(counterRegOut === 4) {
              when(io.in_aesoutput_data(127 downto 0) === tag0.asBits) {
                passReg := True
              } otherwise {
                passReg := False
              }
            }
            when(counterRegOut === 5) {
              when(io.in_aesoutput_data(127 downto 0) === cipher10.asBits) {
                passReg := True
              } otherwise {
                passReg := False
              }
            }
            when(counterRegOut === 6) {
              when(io.in_aesoutput_data(127 downto 0) === cipher20.asBits) {
                passReg := True
              } otherwise {
                passReg := False
              }
            }
            when(counterRegOut === 7) {
              when(io.in_aesoutput_data(127 downto 0) === cipher30.asBits) {
                passReg := True
              } otherwise {
                passReg := False
              }
            }
            when(counterRegOut === 8) {
              when(io.in_aesoutput_data(127 downto 0) === cipher40.asBits) {
                passReg := True
              } otherwise {
                passReg := False
              }
            }
            when(counterRegOut === 9) {
              when(io.in_aesoutput_data(127 downto 0) === tag0.asBits) {
                passReg := True
              } otherwise {
                passReg := False
              }
            }

            counterRegOut := counterRegOut + 1
          }

        }
      }
    }

  }

}
