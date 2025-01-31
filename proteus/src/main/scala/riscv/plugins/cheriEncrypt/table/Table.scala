package riscv.plugins.cheriEncrypt.table

import spinal.core._
import spinal.lib._
import spinal.lib.fsm._

/** This is the Table component. It stores the otypes and the keys. The state machine can store a
  * new key against an otype, or retrieve an existing key
  */
//Done - add an error signal in the response to cause an exception rather than return without valid as may cause other parts to hang on error
//ToDo - consider implementing a look up address otype table for fixed addressing time, but takes up more resources.
// Maybe can have an option to implement either approach
//ToDo - consider generating keys on the fly instead of storing them, but takes processing time.
/** Table block generics */
/** keyWidth is in bits because the aes core defines it like that */
/** oTypeWidth is an integer because CHERI-proteus core defines otypeLen (length) as integer */
/** numTableEntries is the number of fixed table entries */
/** if the table is full and try to add an entry, we need to make sure we can return an
  * error/exception
  */
//todo - pusle rsp valid high when error output is pulled high?
case class TableConfig(
    keyWidth: BitCount,
    IVWidth: BitCount,
    oTypeWidth: Int,
    numTableEntries: Int
)

/** define entry types in table. Define entries that are specific to each class instance */
/** (case classes have an apply method by default) */
/** a new class for each entry */
case class TableEntry(tableConfig: TableConfig) extends Bundle {
  // otype is defined as a UInt in CHERI-proteus
  val otype = UInt(tableConfig.oTypeWidth bits)
  val NextIVCount = Bits(tableConfig.IVWidth: BitCount)
  val key = Bits(tableConfig.keyWidth: BitCount)
  val used = Bool()
  val usedCounter = UInt(2 bits) // 2 bits to count the time of key usage
}

/** The companion class or object can access the private members of its companion. Companion objects
  * are used for methods and values that are not specific to instances of the companion class.
  * define stuff that can be used by any instance of the companion class
  */
object TableEntry {
  def Empty(tableConfig: TableConfig): TableEntry = {
    val entry = TableEntry(tableConfig: TableConfig)
    entry.otype.setAll() // set to FFF (-1)
    entry.key := (0)
    entry.NextIVCount := (0)
    entry.usedCounter := (0)
    entry.used := False
    entry // return the newly created entry
  }
}

/** define input / output signals for Table component */
/** first define the inputs in a bundle */
case class TableCmd(tableConfig: TableConfig) extends Bundle {

  /** otype is defined as a UInt in CHERI-proteus */
  val otype = UInt(tableConfig.oTypeWidth bits)
  val NewNextIVCount = Bits(tableConfig.IVWidth)
  val genKey, getKey, storeNextIVCount = Bool()
}

/** and then define the outputs in a bundle */
case class TableRsp(tableConfig: TableConfig) extends Bundle {

  /** key is defined as Bits in AES spinal block */
  val key = Bits(tableConfig.keyWidth)
  val NextIVCount = Bits(tableConfig.IVWidth)
}

/** then use master/slave handshake so can include both in/out signals in one bundle */
case class TableIo(tableConfig: TableConfig) extends Bundle with IMasterSlave {

  // trigger signals
  // 'decrypt_error' used for test, will connect the 'tag_error' in the decryption block
  val error, decrypt_error = Bool()
  val IVcountsavedDone = Bool()
  // use Flow to include payload and valid for each signal bundle
  val cmd = Flow(TableCmd(tableConfig)) // otype, NewNextIVCount
  val rsp = Flow(TableRsp(tableConfig)) // key, NextIVCount

  // trigger state machine to generate a new key and get key back
  // def genNewKey(): Flow[TableRsp] = {
  //  genKey := True
  //  rsp
  // }

  // trigger state machine to get existing key and get key back
  // def getExistingKey(): Flow[TableRsp] = {
  //  getKey := True
  //  rsp
  // }

  /** Set the direction of each bundle/signal from a master point of view */
  override def asMaster(): Unit = {
    // declare outputs for master, so will be inputs for slave
    out(cmd, decrypt_error)
    // declare inputs for master, so will be outputs for slave
    in(rsp, error, IVcountsavedDone)
  }
}

/** Actual Table component */
class Table(tableConfig: TableConfig, keyConfig: KeyGenConfig) extends Component {
//class Table(tableConfig: TableConfig, keyConfig: KeyGenConfig, DecConfig: AES_DecConfig) extends Component { //todo add later
  // check number of entries
  assert(tableConfig.numTableEntries > 0)
  // set the component name
  setDefinitionName("Table")

  /** define in and out signals of component from classes already defined */
  /** IO to key generator and AES block */
  // declare as master
  val keyGenio = master(KeyGeneratorIO(keyConfig: KeyGenConfig))
  // val aesDecio = master(AES_DecIO(DecConfig: AES_DecConfig)) //todo replace logic input 'decrypt_error' with 'aesDecio.tag_error'

  /** IO to CSealEncrypt instruction */
  // declare as slave
  val tableio = slave(TableIo(tableConfig: TableConfig))

  // todo registers for the decryption error detection
  val otypeReg: UInt = Reg(UInt(width = BitCount(tableConfig.oTypeWidth))) init (0x0)
  val searchIdx = Counter(tableConfig.numTableEntries)
  val decrypt_errorReg: Bool = Reg(Bool()) init (False)
  val IVcountsavedDoneReg: Bool = Reg(Bool()) init (False)

  /** set any default output values */
  keyGenio.cmd.payload.otype := 0xfff
  keyGenio.cmd.valid := False
  // tableio.decrypt_error := False
  tableio.rsp.payload.key := 0x0
  tableio.rsp.payload.NextIVCount := 0x0
  tableio.rsp.valid := False
  tableio.error := False // when table search fails, an error signal will be generated
  tableio.IVcountsavedDone := IVcountsavedDoneReg

  /** allocate memory for table */
  val entries = Mem(Seq.fill(tableConfig.numTableEntries) {
    TableEntry.Empty(tableConfig)
  })

  for (i <- 0 to (tableConfig.numTableEntries - 1)) {

    /** set signal names for each entry */
    val entry = TableEntry(tableConfig).setName(s"entry_$i")
    // asynchronous read?
    entry := entries.readAsync(U(i).resized, writeFirst)
  }

  /** state machine to be triggered */
  val tableFsm = new StateMachine {

    // val searchIdx = Counter(tableConfig.numTableEntries) //todo remove outside the tableFsm
    // ToDo temp reg, make this code better?
    // save current otype and IV counter
    // val otypeReg: UInt = Reg(UInt(width = BitCount(tableConfig.oTypeWidth))) init (0x0) //todo remove outside the tableFsm
    val NewNextIVCountReg: Bits = Reg(Bits(width = tableConfig.IVWidth)) init (0x0)
    // val FlagReg: Bits = Reg(Bits(2 bits)) init (0x0) //signal for debugging

    def tableRsp: TableRsp = new TableRsp(tableConfig) // key & nextIVCount
    val keyReg: TableRsp = Reg(tableRsp)
    // default reg outputs
    // keyReg.key := 0

    def fail() = {
      // Done do we want to return an error signal here?
      tableio.rsp.valid := False
      tableio.rsp.payload.key.setAll()
      tableio.rsp.payload.NextIVCount.setAll()
    }

    /** state machine states */
    val idleState = StateEntryPoint()
    val PregenKeyState = State()
    val genKeyState = State()
    val storeKeyState = State()
    val getKeySealState = State()
    val getKeyInvokeState = State()
    val storeNextIVState = State()
    val storeNextIVDone = State()
    // val eraseKeyState = State()

    idleState.onEntry {
      searchIdx.clear()
    }
    idleState.whenIsActive {
      tableio.error := False
      IVcountsavedDoneReg := False
      when(tableio.cmd.genKey && tableio.cmd.valid) {
        // Done - do need to check otype valid or fail
        // when genkey, go to key generation state
        keyGenio.cmd.payload.otype := tableio.cmd.payload.otype
        keyGenio.cmd.valid := tableio.cmd.valid
        otypeReg := tableio.cmd.payload.otype
        goto(PregenKeyState)
      } elsewhen (tableio.cmd.getKey && tableio.cmd.valid) {
        // Done - do need to check otype valid or fail
        // when getkey, go to key extraction state
        otypeReg := tableio.cmd.payload.otype
        goto(getKeyInvokeState)
      } elsewhen (tableio.cmd.storeNextIVCount && tableio.cmd.valid) {
        // Done - do need to check otype vaild or fail
        // when storeNextIVCount, go to IV counter storing state
        otypeReg := tableio.cmd.payload.otype // save otype in reg
        NewNextIVCountReg := tableio.cmd.payload.NewNextIVCount // save new IV counter in reg
        goto(storeNextIVState)
      }
    }

    PregenKeyState.onEntry {
      searchIdx.clear()
    }
    PregenKeyState.whenIsActive {
      val entry = entries(searchIdx)
      // when no key existing for an otype or key exists but used twice, then request a new key
      // when key exists for an otype and only used once, then get the key from the table
      when(entry.used && (entry.otype === otypeReg)) {
        when(entry.key === 0x0 | entry.usedCounter === 2) {
          // FlagReg := 0x1   //signal for debugging
          goto(genKeyState)
        } elsewhen (entry.usedCounter === 1) {
          // FlagReg := 0x2    //signal for debugging
          goto(getKeySealState)
        }
      } elsewhen (entry.used === False) {
        // FlagReg := 0x3    //signal for debugging
        goto(genKeyState)
      } elsewhen (searchIdx.willOverflowIfInc) {
        fail()
        tableio.error := True
        goto(idleState)
      } otherwise {
        searchIdx.increment()
      }
    }

    genKeyState.whenIsActive {
      // Wait for a new valid key
      when(keyGenio.rsp.valid) {
        // save key in reg
        keyReg.key := keyGenio.rsp.payload.key
        keyReg.NextIVCount := 0x0 // reset the IV counter once a new key is generated
        goto(storeKeyState)
      }
    }

    storeKeyState.onEntry {
      searchIdx.clear()
    }
    storeKeyState.whenIsActive {
      // store the key in the table
      // Done change to search for otype, then unused
      // as may need to generate new key for same otype
      // 1. search for otype, if the otype has been used, update the key in the entry with the same otype
      // otherwise search for unused entry and store the key
      when(entries(searchIdx).used && entries(searchIdx).otype === otypeReg) {
        val updatedEntry = TableEntry.Empty(tableConfig).allowOverride
        updatedEntry.usedCounter := 1
        updatedEntry.used := True
        updatedEntry.otype := otypeReg
        updatedEntry.key := keyReg.key // todo
        updatedEntry.NextIVCount := keyReg.NextIVCount // todo
        // write the updated entry back to the memory
        entries(searchIdx) := updatedEntry
        // 2.push new key to output for encryption
        tableio.rsp.push(
          keyReg
        ) // push the data from keyReg to the rsp output interface, making it valid
        otypeReg := 0xfff
        keyReg.key := 0
        goto(idleState)
        // 3. search for unused entry
      } elsewhen (entries(searchIdx).used === False) {
        // 4. store otype and key in table
        val newEntry = TableEntry.Empty(tableConfig).allowOverride
        newEntry.used := True
        newEntry.key := keyReg.key
        newEntry.otype := otypeReg
        newEntry.NextIVCount := keyReg.NextIVCount
        newEntry.usedCounter := 1
        entries(searchIdx) := newEntry // write the updated entry back to the memory
        // 5.push new key to output for encryption
        // push sets valid to true as well as pushing keyextIVCountReg := 0x0
        tableio.rsp.push(
          keyReg
        ) // push the data from keyReg to the rsp output interface,making it valid
        // reset registers - ToDo don't necessarily need this
        otypeReg := 0xfff
        keyReg.key := 0
        goto(idleState)
      } elsewhen (searchIdx.willOverflowIfInc) {
        fail()
        tableio.error := True
        // reset registers - ToDo don't necessarily need this
        otypeReg := 0xfff
        keyReg.key := 0
        goto(idleState)
      } otherwise {
        searchIdx.increment()
      }
    }

    getKeySealState.onEntry {
      // on entry do reset here
      searchIdx.clear()
    }
    getKeySealState.whenIsActive {
      val entry = entries(searchIdx)
      // look for matching otype
      when(entry.used && (entry.otype === otypeReg)) {
        // Todo could also use push here?
        tableio.rsp.payload.key := entry.key
        tableio.rsp.payload.NextIVCount := entry.NextIVCount
        tableio.rsp.valid := True
        // create a new entry with updated usedCounter
        val updatedEntry = TableEntry.Empty(tableConfig).allowOverride
        updatedEntry.usedCounter := entry.usedCounter + 1
        updatedEntry.used := entry.used
        updatedEntry.otype := entry.otype
        updatedEntry.key := entry.key
        updatedEntry.NextIVCount := entry.NextIVCount
        // write the updated entry back to the memory
        entries(searchIdx) := updatedEntry
        goto(idleState)
      } elsewhen (searchIdx.willOverflowIfInc) {
        fail()
        tableio.error := True
        goto(idleState)
      } otherwise {
        searchIdx.increment()
      }
    }

    getKeyInvokeState.onEntry {
      // on entry do reset here
      searchIdx.clear()
    }
    getKeyInvokeState.whenIsActive {
      val entry = entries(searchIdx)
      // look for matching otype
      when(entry.used && (entry.otype === otypeReg)) {
        // Todo could also use push here?
        tableio.rsp.payload.key := entry.key
        tableio.rsp.payload.NextIVCount := entry.NextIVCount
        tableio.rsp.valid := True
        // goto(eraseKeyState) //todo decrypt_error here?
        goto(idleState)
      } elsewhen (searchIdx.willOverflowIfInc) {
        fail()
        tableio.error := True
        goto(idleState)
      } otherwise {
        searchIdx.increment()
      }
    }

    storeNextIVState.onEntry {
      searchIdx.clear()
    }
    storeNextIVState.whenIsActive {
      val entry = entries(searchIdx)
      // look for matching otype
      when(entry.used && (entry.otype === otypeReg)) {
        // create a new entry with updated IVCounter
        val updatedEntry = TableEntry.Empty(tableConfig).allowOverride
        updatedEntry.usedCounter := entry.usedCounter
        updatedEntry.used := entry.used
        updatedEntry.otype := entry.otype
        updatedEntry.key := entry.key
        updatedEntry.NextIVCount := NewNextIVCountReg
        // write the updated entry back to the memory
        entries(searchIdx) := updatedEntry
        goto(storeNextIVDone)
        // IVcountsavedDoneReg:= True
        // goto(idleState)
      } elsewhen (searchIdx.willOverflowIfInc) {
        fail()
        tableio.error := True
        goto(idleState)
      } otherwise {
        searchIdx.increment()
      }
    }

    storeNextIVDone.whenIsActive {
      IVcountsavedDoneReg := True // todo one clock late after the IVcount has been stored
      goto(idleState)
    }
  }
  // Todo decrypt_error here? erase all the stored keys in the table
  when(tableio.decrypt_error) {
    searchIdx := 0
    decrypt_errorReg := tableio.decrypt_error
  }

  when(decrypt_errorReg) {
    val entry = entries(searchIdx)
    // erase all the keys stored in the table
    when(entry.used) {
      // when (entry.used && (entry.otype === otypeReg)) {
      val updatedEntry = TableEntry.Empty(tableConfig).allowOverride
      updatedEntry.usedCounter := (0)
      updatedEntry.used := False
      updatedEntry.otype := 0xfff
      updatedEntry.key := (0)
      updatedEntry.NextIVCount := (0)
      // write the updated entry back to the memory
      entries(searchIdx) := updatedEntry
      // decrypt_errorReg := False
    } elsewhen (searchIdx.willOverflowIfInc) {
      decrypt_errorReg := False
      tableio.error := True
    } otherwise {
      searchIdx.increment()
    }
  }
  // }
}

//object Table_verilog {
//val config1 = TableConfig(keyWidth = BitCount(128), IVWidth = BitCount(64), oTypeWidth = 12, numTableEntries = 3)
//val config2 = KeyGenConfig(keyWidth = BitCount(128), oTypeWidth = 12)
//def main(args: Array[String]): Unit = {
//SpinalVerilog(new Table(config1, config2))
//}
//}
