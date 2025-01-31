package riscv.plugins.cheriEncrypt.AESEngine
import spinal.core._
import spinal.lib._
//import spinal.crypto.symmetric.aes._
//import spinal.crypto.symmetric.{SymmetricCryptoBlockCmd, SymmetricCryptoBlockConfig, SymmetricCryptoBlockIO}
//import spinal.crypto.devtype._
//import spinal.crypto._
import spinal.core.{BitCount, Component}
import spinal.lib.fsm.{EntryPoint, State, StateMachine, StateParallelFsm}

case class AES_DecConfig(
    dataWidth: BitCount,
    keyWidth: BitCount
)

case class AES_DecCmd(config: AES_DecConfig) extends Bundle {
  val vector_vld = Bool() // ready signal for IV
  val ct_vld = Bool() // ready signal for ciphertext (decryption)
  val aad_vld = Bool() // ready signal for AAD
  val tag_gold = Bits(config.dataWidth) // golden tag value read from the memory
  val block = Bits(config.dataWidth) // can be the initial vector, ciphertext, and AAD
  val last_word = Bool() // last word of the input data
  val key_vld = Bool() // ready signal for key
  val key = Bits(config.keyWidth) // decryption key
}

case class AES_DecRsp(config: AES_DecConfig) extends Bundle {
  val Out_data = Bits(config.dataWidth)
  val data_vld = Bool()
  val tag_vld = Bool()
}

case class AES_DecIO(config: AES_DecConfig) extends Bundle with IMasterSlave {
  val busy, aes_done, tag_error =
    Bool() // busy: decryption is uncompleted; aes_done: decryption is completed; tag_error: tag calculation is wrong
  val data_size = UInt(width = 4 bits) // check the bit width of 'block' 128 bits or not
  val cmd = Stream(AES_DecCmd(config))
  val rsp = Flow(AES_DecRsp(config))

  override def asMaster() = {
    out(cmd, data_size)
    in(rsp, busy, aes_done, cmd.ready, tag_error)
  }
}

class AES_Dec(dataWidth: BitCount) extends Component {
  val config = AES_DecConfig(
    dataWidth = dataWidth,
    keyWidth = dataWidth
  )

  // add AES function and HASH function
  val AES = new AES_engine(dataWidth)
  val GFMUL = new gfm128_16(dataWidth)

  val io = slave(AES_DecIO(config))

  /** define inputs/outputs registers to AES, GFMUL, and AES_core */
  val in_vectorReg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val in_ctReg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val in_keyReg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val key_vldReg: Bool = Reg(Bool()) init (False)
  val init_vectorReg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val data_rdyReg: Bool = Reg(Bool()) init (False)
  val data_enc_rdyReg: Bool = Reg(Bool()) init (False)

  val out_dataReg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val nxt_dataoutReg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val data_starReg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val nxt_dataout_starReg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val data_vldReg: Bool = Reg(Bool()) init (False)
  val tag_vldReg: Bool = Reg(Bool()) init (False)
  val data_not_readyReg: Bool = Reg(Bool()) init (True)
  val errorReg: Bool = Reg(Bool()) init (False)

  /** length calculation registers */
  val aad_byte_cnt: UInt = Reg(UInt(64 bits)) init (0)
  val enc_byte_cnt: UInt = Reg(UInt(64 bits)) init (0)

  /** enable signals */
  val gfm_enable: Bool = Reg(Bool()) init (False)
  val lenAAD_enable: Bool = Reg(Bool()) init (False)
  val lenCT_enable: Bool = Reg(Bool()) init (False)

  /** test signals */
  // val flag1 : Bool = Reg(Bool()) init (False)
  // val flag2: Bool = Reg(Bool()) init (False)
  // val flag3 : Bool = Reg(Bool()) init (False)

  /** AES block signals */
  val last_wordReg: Bool = Reg(Bool()) init (False)

  /** GF Multiplier block signals */
  val hash1Reg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val gfm_input1Reg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val gfm_cnt: UInt = Reg(UInt(4 bits)) init (0)
  val gfm_resultReg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val gfm_busy: Bool = Reg(Bool()) init (False)
  val b_inReg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val z_inReg: Bits = Reg(Bits(config.dataWidth)) init (0)
  val v_inReg: Bits = Reg(Bits(config.dataWidth)) init (0)

  /** Registers for the last XOR operation for TAG calculation */
  val iv0_tagReg: Bits = Reg(Bits(config.dataWidth)) init (0)

  /** data accepted from the data port */
  data_rdyReg := io.cmd.valid & (io.cmd.ct_vld | io.cmd.vector_vld | io.cmd.aad_vld)

  /** if the accepted data is not 128-bit, then extend to 128-bit */
  when(data_rdyReg) {
    switch(io.data_size) {
      is(0) {
        data_starReg := io.cmd.block(7 downto 0) ## U"120'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 120) ## U"120'x00"
      }
      is(1) {
        data_starReg := io.cmd.block(15 downto 0) ## U"112'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 112) ## U"112'x00"
      }
      is(2) {
        data_starReg := io.cmd.block(23 downto 0) ## U"104'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 104) ## U"104'x00"
      }
      is(3) {
        data_starReg := io.cmd.block(31 downto 0) ## U"96'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 96) ## U"96'x00"
      }
      is(4) {
        data_starReg := io.cmd.block(39 downto 0) ## U"88'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 88) ## U"88'x00"
      }
      is(5) {
        data_starReg := io.cmd.block(47 downto 0) ## U"80'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 80) ## U"80'x00"
      }
      is(6) {
        data_starReg := io.cmd.block(55 downto 0) ## U"72'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 72) ## U"72'x00"
      }
      is(7) {
        data_starReg := io.cmd.block(63 downto 0) ## U"64'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 64) ## U"64'x00"
      }
      is(8) {
        data_starReg := io.cmd.block(71 downto 0) ## U"56'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 56) ## U"56'x00"
      }
      is(9) {
        data_starReg := io.cmd.block(79 downto 0) ## U"48'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 48) ## U"48'x00"
      }
      is(10) {
        data_starReg := io.cmd.block(87 downto 0) ## U"40'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 40) ## U"40'x00"
      }
      is(11) {
        data_starReg := io.cmd.block(95 downto 0) ## U"32'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 32) ## U"32'x00"
      }
      is(12) {
        data_starReg := io.cmd.block(103 downto 0) ## U"24'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 24) ## U"24'x00"
      }
      is(13) {
        data_starReg := io.cmd.block(111 downto 0) ## U"16'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 16) ## U"16'x00"
      }
      is(14) {
        data_starReg := io.cmd.block(119 downto 0) ## U"8'x00"
        nxt_dataout_starReg := nxt_dataoutReg(127 downto 8) ## U"8'x00"
      }
    }
  }

  // this subFsm is Galois Field Multiplication
  def internalFsmA() = new StateMachine {
    val Idle: State = new State with EntryPoint {
      whenIsActive {
        data_vldReg := False
        when(AES.io.BSY) {
          gfm_busy := True
          goto(GFinput_sel)
        }
      }
    }

    val GFinput_sel: State = new State {
      whenIsActive {
        when(io.data_size === 15) {
          gfm_input1Reg := in_ctReg
        } otherwise {
          gfm_input1Reg := data_starReg
        }
        gfm_enable := True
        goto(GF_mult)
      }
    }

    val GF_mult: State = new State {
      whenIsActive {
        lenAAD_enable := False
        gfm_enable := False
        when(gfm_cnt === 7) {
          when(last_wordReg) {
            exit()
          } otherwise {
            goto(Idle)
          }
        }
      }
    }
  }

  // this subFsm is AES
  def internalFsmB() = new StateMachine {
    val Inc_counter_pre: State = new State with EntryPoint {
      whenIsActive {
        key_vldReg := False
        data_enc_rdyReg := True // need to be pulled high after key_vldReg goes high
        goto(Inc_counter)
      }
    }

    val Inc_counter: State = new State {
      whenIsActive {
        AES.io.Din := in_vectorReg
        lenCT_enable := True
        data_enc_rdyReg := False
        goto(M_encrypt)
      }
    }

    val M_encrypt: State = new State {
      whenIsActive {
        lenCT_enable := False
        when(AES.io.Dvld) {
          AES.io.EN := False
          when(io.data_size === 15) {
            // out_dataReg := AES.io.Dout ^ io.cmd.block
            out_dataReg := AES.io.Dout ^ in_ctReg
            data_vldReg := True
          } otherwise {
            out_dataReg := AES.io.Dout ^ data_starReg
            nxt_dataoutReg := AES.io.Dout ^ data_starReg
            data_vldReg := True
          }
          when(last_wordReg) {
            key_vldReg := True
            goto(Init_counter_pre)
          } otherwise {
            goto(Pre_Data_accept)
          }
        }
      }
    }

    val Pre_Data_accept: State = new State {
      whenIsActive {
        data_vldReg := False
        data_not_readyReg := False
        goto(Data_accept_ready)
      }
    }

    val Data_accept_ready: State = new State {
      whenIsActive {
        data_not_readyReg := True
        goto(Data_accept)
      }
    }

    val Data_accept: State = new State {
      whenIsActive {
        when(io.cmd.ct_vld) {
          key_vldReg := True
          in_vectorReg := (in_vectorReg.asUInt + 1).asBits
          in_ctReg := io.cmd.block
          goto(Inc_counter_pre)
        }
      }
    }

    val Init_counter_pre: State = new State {
      whenIsActive {
        data_vldReg := False
        key_vldReg := False
        AES.io.EN := True
        data_enc_rdyReg := True
        goto(Init_counter)
      }
    }

    val Init_counter: State = new State {
      whenIsActive {
        AES.io.Din := init_vectorReg
        in_vectorReg := init_vectorReg
        data_enc_rdyReg := False
        goto(Encrypt_iv0)
      }
    }

    val Encrypt_iv0: State = new State {
      whenIsActive {
        when(AES.io.Dvld) {
          AES.io.EN := False
          iv0_tagReg := AES.io.Dout
          exit()
        }
      }
    }
  }

  AES.io.EN := True
  AES.io.Din := 0

  val sm = new StateMachine {

    /** sIdle: initial value for the inputs and outputs port, then pass all 0s to the encryption
      * block
      */
    val sIdle: State = new State with EntryPoint {
      whenIsActive {
        data_vldReg := False
        tag_vldReg := False
        data_not_readyReg := True
        lenCT_enable := False
        lenAAD_enable := False
        errorReg := False
        gfm_input1Reg := 0x0
        enc_byte_cnt := 0 // todo very important
        aad_byte_cnt := 0 // todo very important
        when(io.cmd.key_vld & io.cmd.vector_vld & io.cmd.valid) {
          in_keyReg := io.cmd.key
          key_vldReg := True
          init_vectorReg := io.cmd.block // todo add
          in_vectorReg := io.cmd.block // todo add
          goto(sEncrypt_0_pre)
        }
      }
    }

    val sEncrypt_0_pre: State = new State {
      whenIsActive {
        data_enc_rdyReg := True
        key_vldReg := False
        AES.io.Din := 0
        goto(sEncrypt_0) // start the hash calculation
      }
    }

    /** after the hash calculation, accept the data AAD or CT */
    val sEncrypt_0: State = new State {
      whenIsActive {
        data_enc_rdyReg := False
        when(AES.io.Dvld) {
          hash1Reg := AES.io.Dout
          AES.io.EN := False
          goto(sData_accept_pre)
        }
      }
    }

    val sData_accept_pre: State = new State {
      whenIsActive {
        data_not_readyReg := False
        goto(sData_accept) // accept the data AAD or CT
      }
    }

    /** accept the data, AAD or Ciphertext */
    val sData_accept: State = new State {
      whenIsActive {
        data_not_readyReg := True
        when(io.cmd.ct_vld) {
          in_vectorReg := (in_vectorReg.asUInt + 1).asBits
          in_ctReg := io.cmd.block
          key_vldReg := True
          gfm_resultReg := 0x0 // todo important to reset this register
          goto(sParallel)
        }.elsewhen(io.cmd.aad_vld) {
          // if AAD, go to GF multiplication
          when(io.data_size === 15) {
            gfm_input1Reg := io.cmd.block
            gfm_enable := True
            gfm_busy := True
            lenAAD_enable := True
            goto(sGF_mult)
          } otherwise {
            gfm_input1Reg := data_starReg
            gfm_enable := True
            gfm_busy := True
            lenAAD_enable := True
            goto(sGF_mult)
          }
        }
      }
    }

    val sParallel = new StateParallelFsm(internalFsmA(), internalFsmB()) {
      whenCompleted {
        gfm_busy := True
        goto(sPre_tag_cal)
      }
    }

    val sGF_mult: State = new State {
      whenIsActive {
        lenAAD_enable := False
        gfm_enable := False
        data_vldReg := False
        data_not_readyReg := True
        when(gfm_cnt === 7) {
          when(last_wordReg) {
            gfm_busy := True
            goto(sPre_tag_cal)
          } otherwise {
            goto(sData_accept)
          }
        }
      }
    }

    val sPre_tag_cal: State = new State {
      whenIsActive {
        gfm_input1Reg := { aad_byte_cnt |<< 3 } ## { enc_byte_cnt |<< 3 }
        gfm_enable := True
        goto(sTag_cal)
      }
    }

    val sTag_cal: State = new State {
      whenIsActive {
        gfm_enable := False
        when(gfm_cnt === 7) {
          out_dataReg := iv0_tagReg ^ GFMUL.z_out // calculated tag
          tag_vldReg := True
          // gfm_busy := False //todo? notice this line
          data_not_readyReg := False // todo add on 13rd September
          goto(sCompare)
        }
      }
    }

    val sCompare: State = new State {
      whenIsActive {
        data_not_readyReg := True
        tag_vldReg := False
        when(out_dataReg === io.cmd.payload.tag_gold) {
          errorReg := False
        } otherwise {
          errorReg := True
        }
        goto(sIdle)
      }
    }
  }

  when(gfm_busy) {
    switch(gfm_enable) {
      is(True) {
        v_inReg := hash1Reg
        z_inReg := 0
        gfm_cnt := 0
        b_inReg := gfm_input1Reg ^ gfm_resultReg
      }
      is(False) {
        when(gfm_cnt =/= 7) {
          v_inReg := GFMUL.v_out
          z_inReg := GFMUL.z_out
          b_inReg := b_inReg |<< 16
          gfm_cnt := gfm_cnt + 1
        } otherwise {
          gfm_busy := False
          gfm_resultReg := GFMUL.z_out
          gfm_cnt := 0
        }
      }
    }
  }

  aad_byte_cnt := aad_byte_cnt
  when(lenAAD_enable) {
    aad_byte_cnt := aad_byte_cnt + io.data_size + 1
  }

  enc_byte_cnt := enc_byte_cnt
  when(lenCT_enable) {
    enc_byte_cnt := enc_byte_cnt + io.data_size + 1
  }

  io.rsp.Out_data := out_dataReg
  io.rsp.data_vld := data_vldReg
  io.rsp.tag_vld := tag_vldReg
  io.rsp.valid := data_vldReg | tag_vldReg
  io.busy := AES.io.BSY
  io.aes_done := AES.io.Dvld
  io.tag_error := errorReg
  // todo add@AES is ready to accept data
  io.cmd.ready := !data_not_readyReg

  GFMUL.b_in := b_inReg(127 downto 112)
  GFMUL.v_in := v_inReg
  GFMUL.z_in := z_inReg

  // AES.Din := aes_text
  AES.io.Drdy := data_enc_rdyReg
  AES.io.Krdy := key_vldReg
  AES.io.Key := in_keyReg
  last_wordReg := io.cmd.last_word
}

object AES_Decverilog {
  def main(args: Array[String]) {
    SpinalVerilog(new AES_Dec(dataWidth = 128 bits))
  }
}
