//define package name
package riscv.plugins.cheriEncrypt.table

//include imported libraries here
import spinal.core._
import spinal.lib._

/** This component includes the key generator and table for storing keys
  */

/** define input / output signals for Wrapper component */

/** first define the inputs in a bundle */
case class TableKeyGenTopCmd(tableConfig: TableConfig) extends Bundle {

  /** otype is defined as a UInt in CHERI-proteus */
  val otype = UInt(tableConfig.oTypeWidth bits)
  val NewNextIVCount = Bits(tableConfig.IVWidth)
  val genKey, getKey, storeNextIVCount = Bool()
}

/** and then define the outputs in a bundle */
case class TableKeyGenTopRsp(tableConfig: TableConfig) extends Bundle {

  /** key is defined as Bits in AES spinal block */
  val key = Bits(tableConfig.keyWidth)
  val NextIVCount = Bits(tableConfig.IVWidth)
  // val error = Bool() //take the error out from the response
}

/** then use master/slave handshake so can include both in/out signals in one bundle */
case class TableKeyGenTopIo(tableConfig: TableConfig) extends Bundle with IMasterSlave {

  /** use Flow to include payload and valid for each signal bundle */
  // val genKey, getKey, storeNextIVCount, decrypt_error = Bool()
  val cmd = Flow(TableKeyGenTopCmd(tableConfig))
  val rsp = Flow(TableKeyGenTopRsp(tableConfig))
  val error, decrypt_error, IVcountsavedDone = Bool()

  /** Set the direction of each bundle from a master point of view */
  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    out(cmd, decrypt_error)

    /** declare inputs for master, so will be outputs for slave */
    in(rsp, error, IVcountsavedDone)
  }
}

//ToDo change io to master-slave setup
class TableKeyGenTop(tableConfig: TableConfig, keyGenConfig: KeyGenConfig) extends Component {

  /** inputs / outputs */
  val io = slave(TableKeyGenTopIo(tableConfig))

  /** create table */
  val table = new Table(tableConfig, keyGenConfig)

  /** create key generator block */
  val keyGenerator = new KeyGenerator(keyGenConfig)

  /** connect Table to key generator */
  // input to key generator
  keyGenerator.io.cmd.payload.otype := table.keyGenio.cmd.payload.otype
  keyGenerator.io.cmd.valid := table.keyGenio.cmd.valid
  // input to table
  table.keyGenio.rsp.payload.key := keyGenerator.io.rsp.payload.key
  table.keyGenio.rsp.valid := keyGenerator.io.rsp.valid
  table.tableio.cmd.genKey := io.cmd.genKey
  table.tableio.cmd.getKey := io.cmd.getKey
  table.tableio.cmd.storeNextIVCount := io.cmd.storeNextIVCount
  table.tableio.decrypt_error := io.decrypt_error
  table.tableio.cmd.payload.otype := io.cmd.payload.otype
  table.tableio.cmd.payload.NewNextIVCount := io.cmd.payload.NewNextIVCount
  table.tableio.cmd.valid := io.cmd.valid

  // outputs from this component
  io.rsp.payload.key := table.tableio.rsp.payload.key
  io.rsp.payload.NextIVCount := table.tableio.rsp.payload.NextIVCount
  io.rsp.valid := table.tableio.rsp.valid
  io.error := table.tableio.error
  io.IVcountsavedDone := table.tableio.IVcountsavedDone // todo add on 13rd September

}

//output options:
//Generate Verilog output
object TableKeyGenTopVerilog {

  /** specify generic values */
  val keyGenConfig = new KeyGenConfig(keyWidth = BitCount(128), oTypeWidth = (12))
  val tableConfig = new TableConfig(
    keyWidth = BitCount(128),
    oTypeWidth = (12),
    IVWidth = BitCount(64),
    numTableEntries = 3
  )
  def main(args: Array[String]) {
    SpinalVerilog(new TableKeyGenTop(tableConfig, keyGenConfig))
  }
}
