package riscv.plugins.cheriEncrypt.table

import spinal.core._
import spinal.lib._
//import spinal.crypto.hash._
//import spinal.crypto.mac.hmac._
//import spinal.crypto.mac.hmac.{HMACCoreStdIO, HMACCoreStdConfig, HMACCoreStdCmd, HMACCore_Std}
//import spinal.crypto.hash._
//import spinal.crypto.hash.md5._
//import spinal.crypto.hash.{HashCoreConfig, HashCoreIO}
import spinal.lib.fsm.{EntryPoint, State, StateMachine}

/** This is the KeyGenerator component. It generates a new key everytime a valid otype is presented
  * on the input
  */

/** KeyGenerator generics */
/** keyWidth is in bits because the aes core defines it like that */
/** oTypeWidth is an integer because CHERI-proteus core defines otypeLen (length) as integer */
case class KeyGenConfig(
    keyWidth: BitCount,
    oTypeWidth: Int
)

/** define input / output signals for key generator component */
/** first define the inputs in a bundle */
case class KeyGeneratorCmd(keyGenConfig: KeyGenConfig) extends Bundle {

  /** otype is defined as a UInt in CHERI-proteus */
  val otype = UInt(keyGenConfig.oTypeWidth bits)
}

/** and then define the outputs in a bundle */
case class KeyGeneratorRsp(keyGenConfig: KeyGenConfig) extends Bundle {

  /** key is defined as Bits in AES spinal block */
  val key = Bits(keyGenConfig.keyWidth)
}

/** then use master/slave handshake so can include both in/out signals in one bundle */
case class KeyGeneratorIO(keyGenConfig: KeyGenConfig) extends Bundle with IMasterSlave {

  /** use Flow to include payload and valid for each signal bundle */
  val cmd = Flow(KeyGeneratorCmd(keyGenConfig))
  val rsp = Flow(KeyGeneratorRsp(keyGenConfig))

  /** Set the direction of each bundle from a master point of view */
  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    out(cmd)

    /** declare inputs for master, so will be outputs for slave */
    in(rsp)
  }
}

/** key generator component */
class KeyGenerator(val config: KeyGenConfig) extends Component {

  /** set the component name */
  setDefinitionName("KeyGenerator")
  // assert(config.keyWidth == config.gHash.hashBlockWidth, "For the moment, the key must have the same width than the hash block")

  /** define in and out signals of component from classes defined above */
  /** declare as slave */
  /** implicit keyGenConfig gets passed automatically */
  val io = slave(KeyGeneratorIO(config))

  val seed: Bits = Reg(Bits(config.keyWidth)) init (0)
  val counterReg: UInt = Reg(UInt(config.keyWidth)) init (0)
  val validReg: Bool = Reg(Bool) init (False)
  val keyReg: Bits = Reg(Bits(config.keyWidth)) init (0)
  val flag: Bool = Reg(Bool) init (False)
  val otypeReg: UInt = Reg(UInt(width = BitCount(config.oTypeWidth))) init (0x0)

  val entropy = UInt(128 bits); entropy := U"hd9313225f88406e5a55909c5aff5269a";
  val personalstring = UInt(128 bits); personalstring := U"h0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";

  val AES = new AES_engine(config.keyWidth)

  AES.io.EN := True
  AES.io.Din := 0
  AES.io.Key := 0
  AES.io.Drdy := False
  AES.io.Krdy := False

  /** set any default output values here the DRBG has 3 main funcions: Instantiate, Reseed, and
    * Generation
    */
  val sm = new StateMachine {
    val sIdle: State = new State with EntryPoint {
      whenIsActive {
        validReg := False
        when(io.cmd.valid === True) {
          flag := True
          AES.io.EN := True
          otypeReg := io.cmd.payload.otype
          goto(sInstantiate)
        }
      }
    }

    val sInstantiate: State = new State {
      whenIsActive {
        counterReg := counterReg + 1
        seed := entropy.asBits ^ personalstring.asBits ^ counterReg.asBits
        AES.io.Krdy := True
        goto(sGeneration_pre)
      }
    }

    val sGeneration_pre: State = new State {
      whenIsActive {
        AES.io.Krdy := False
        AES.io.Drdy := True
        // AES.io.Din := (otypeReg + counterReg).resize(config.oTypeWidth).asBits ## U"64'x00"
        AES.io.Din := (otypeReg + counterReg).resize(config.oTypeWidth).asBits ## B(
          0,
          (128 - config.oTypeWidth) bits
        )
        goto(sGeneration)
      }
    }

    val sGeneration: State = new State {
      whenIsActive {
        when(AES.io.BSY === True) {
          AES.io.Drdy := False
        } elsewhen (AES.io.Dvld === True) {
          keyReg := AES.io.Dout
          validReg := AES.io.Dvld
          goto(sIdle)
        }
      }
    }

  }

  io.rsp.payload.key := keyReg
  io.rsp.valid := validReg
  // AES.io.Krdy := key_rdy

}

object KeyGenerator_verilog {
  val config = new KeyGenConfig(keyWidth = BitCount(128), oTypeWidth = 12)
  def main(args: Array[String]): Unit = {
    SpinalVerilog(new KeyGenerator(config))
  }
}

//val dataLength : UInt = log2Up(personalstring)
//val size = UInt(log2Up(config.gHash.dataWidth.value / 8) bits)
//when(dataLength < 128) {
//dataLength := dataLength ## U"(128-dataLength)'x00"
// println(s"Number of bits of the string is : $dataLength")
