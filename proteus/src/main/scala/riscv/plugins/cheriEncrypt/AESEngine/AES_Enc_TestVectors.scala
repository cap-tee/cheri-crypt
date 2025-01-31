package riscv.plugins.cheriEncrypt.AESEngine
import spinal.core._
//import spinal.crypto.symmetric.SymmetricCryptoBlockConfig
import spinal.lib.fsm.{EntryPoint, State, StateMachine}
import spinal.lib._

/** NIST test vectors for AES-CTR-GCM (counter mode for GCM) including GHASH algorithm encryption /
  * decryption
  */

class AES_Enc_TestVectors(dataWidth: BitCount) extends Component {
  val config = AES_EncConfig(
    dataWidth = dataWidth,
    keyWidth = dataWidth
  )

  /** assign generics - at moment all must be same as key of 128 bits */
  val io = new Bundle {
    val in_start = in Bool ()
    val io = master(AES_EncIO(config))
    val out_passBlock = out Bool ()
    val out_passTag = out Bool ()
  }

  val vector_rdyReg: Bool = Reg(Bool) init (False)
  val pt_rdyReg: Bool = Reg(Bool) init (False)
  val aad_rdyReg: Bool = Reg(Bool) init (False)
  val key_rdyReg: Bool = Reg(Bool) init (False)
  val dataReg: Bits = Reg(Bits(128 bits)) init (0)
  val keyReg: Bits = Reg(Bits(128 bits)) init (0)
  val sizeReg: Bits = Reg(Bits(4 bits)) init (0)
  val lastReg: Bool = Reg(Bool) init (False)
  val vldReg: Bool = Reg(Bool) init (False)

  val passBlockReg: Bool = Reg(Bool) init (False)
  val passTagReg: Bool = Reg(Bool) init (False)

  val counterReg: UInt = Reg(UInt(4 bits)) init (0)
  val counterRegOut: UInt = Reg(UInt(4 bits)) init (0)

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

  /** assign outputs */
  io.out_passBlock := passBlockReg
  io.out_passTag := passTagReg

  val sm = new StateMachine {
    val sIdle: State = new State with EntryPoint {
      whenIsActive {
        vector_rdyReg := False
        pt_rdyReg := False
        aad_rdyReg := False
        lastReg := False
        key_rdyReg := False
        dataReg := 0x0
        keyReg := 0x0
        counterReg := 0
        when(io.in_start) {
          goto(sPrepare)
        }
      }
    }

    val sPrepare: State = new State {
      whenIsActive {
        vldReg := True
        key_rdyReg := True
        keyReg(127 downto 0) := key0.asBits
        vector_rdyReg := True
        dataReg(127 downto 0) := initVec0.asBits
        goto(sEncValues)
      }
    }

    /** encryption tests */
    val sEncValues: State = new State {
      whenIsActive {
        when(io.io.cmd.ready === True) {
          key_rdyReg := False
          vector_rdyReg := False
          counterReg := counterReg + 1

          when(counterReg === 0) {
            pt_rdyReg := True
            dataReg(127 downto 0) := plainData10.asBits
            sizeReg := B("1111")
          }
          when(counterReg === 1) {
            pt_rdyReg := True
            dataReg(127 downto 0) := plainData20.asBits
          }
          when(counterReg === 2) {
            pt_rdyReg := True
            dataReg(127 downto 0) := plainData30.asBits
          }
          when(counterReg === 3) {
            pt_rdyReg := True
            dataReg(127 downto 0) := plainData40.asBits
            lastReg := True
            vldReg := False
            goto(sEncValues_again)
          }
        }
      }
    }

    val sEncValues_again: State = new State {
      whenIsActive {
        when(io.io.cmd.ready === True) {
          counterReg := counterReg + 1
          when(counterReg === 4) {
            pt_rdyReg := False
            vldReg := True
            key_rdyReg := True
            vector_rdyReg := True
            keyReg(127 downto 0) := key0.asBits
            dataReg(127 downto 0) := initVec0.asBits
          }

          when(counterReg === 5) {
            key_rdyReg := False
            vector_rdyReg := False
            pt_rdyReg := True
            dataReg(127 downto 0) := plainData10.asBits
            sizeReg := B("1111")
          }
          when(counterReg === 6) {
            pt_rdyReg := True
            dataReg(127 downto 0) := plainData20.asBits
          }
          when(counterReg === 7) {
            pt_rdyReg := True
            dataReg(127 downto 0) := plainData30.asBits
          }
          when(counterReg === 8) {
            pt_rdyReg := True
            dataReg(127 downto 0) := plainData40.asBits
            lastReg := True
            vldReg := False
            goto(sComplete)
          }
        }
      }
    }

    val sComplete: State = new State {
      whenIsActive {
        when(io.io.cmd.ready === True) {
          pt_rdyReg := False
          aad_rdyReg := False
        }
      }
    }
  }

  /** assign outputs */
  io.io.cmd.payload.block := dataReg
  io.io.cmd.payload.key := keyReg
  io.io.cmd.payload.vector_vld := vector_rdyReg
  io.io.cmd.payload.pt_vld := pt_rdyReg
  io.io.cmd.payload.aad_vld := aad_rdyReg
  io.io.cmd.payload.key_vld := key_rdyReg
  io.io.data_size := sizeReg.asUInt
  io.io.cmd.payload.last_word := lastReg
  io.io.cmd.valid := vldReg

  /** output state machine */
  val smOut = new StateMachine {
    val sIdle: State = new State with EntryPoint {
      whenIsActive {
        passBlockReg := False
        passTagReg := False
        counterRegOut := 0
        when(io.in_start) {
          goto(sEncValues)
        }
      }
    }

    /** Encryption tests */
    val sEncValues: State = new State {
      whenIsActive {
        passBlockReg := False
        passTagReg := False
        when(counterRegOut > 10) {
          goto(sIdle)
        }
        when(io.io.rsp.data_vld) {
          when(counterRegOut === 0) {
            when(io.io.rsp.payload.Out_data(127 downto 0) === cipher10.asBits) {
              passBlockReg := True
            } otherwise {
              passBlockReg := False
            }
          }
          when(counterRegOut === 1) {
            when(io.io.rsp.payload.Out_data(127 downto 0) === cipher20.asBits) {
              passBlockReg := True
            } otherwise {
              passBlockReg := False
            }
          }
          when(counterRegOut === 2) {
            when(io.io.rsp.payload.Out_data(127 downto 0) === cipher30.asBits) {
              passBlockReg := True
            } otherwise {
              passBlockReg := False
            }
          }
          when(counterRegOut === 3) {
            when(io.io.rsp.payload.Out_data(127 downto 0) === cipher40.asBits) {
              passBlockReg := True
            } otherwise {
              passBlockReg := False
            }
          }
          when(counterRegOut === 5) {
            when(io.io.rsp.payload.Out_data(127 downto 0) === cipher10.asBits) {
              passBlockReg := True
            } otherwise {
              passBlockReg := False
            }
          }
          when(counterRegOut === 6) {
            when(io.io.rsp.payload.Out_data(127 downto 0) === cipher20.asBits) {
              passBlockReg := True
            } otherwise {
              passBlockReg := False
            }
          }
          when(counterRegOut === 7) {
            when(io.io.rsp.payload.Out_data(127 downto 0) === cipher30.asBits) {
              passBlockReg := True
            } otherwise {
              passBlockReg := False
            }
          }
          when(counterRegOut === 8) {
            when(io.io.rsp.payload.Out_data(127 downto 0) === cipher40.asBits) {
              passBlockReg := True
            } otherwise {
              passBlockReg := False
            }
          }
          counterRegOut := counterRegOut + 1
        }
        when(io.io.rsp.tag_vld) {
          lastReg := False // todo add
          when(counterRegOut === 4) {
            when(io.io.rsp.payload.Out_data(127 downto 0) === tag0.asBits) {
              passTagReg := True
            } otherwise {
              passTagReg := False
            }
          }
          when(counterRegOut === 9) {
            when(io.io.rsp.payload.Out_data(127 downto 0) === tag0.asBits) {
              passTagReg := True
            } otherwise {
              passTagReg := False
            }
          }
          counterRegOut := counterRegOut + 1
        }
      }
    }

  }

}
