package riscv.plugins.cheriEncrypt
import spinal.core._
import spinal.lib._

/** This is the cacheBoundsChecker component used by the cache controller */

/** This component does the following: */
/** 1) Stores the required bounds for the current CInvokeEncrypt (enclave) on an update signal. */
/** 2) Clears the bounds when exiting from the current Invoke (enclave). */
/** 3) Checks an input fetch address (cmdAddress from ibus) against the required bounds and sets an
  * output flag when the address is outside the bounds region.
  */
/** 4) Checks the current PCC against the required bounds and sets an output flag when the address
  * is outside the bounds region.
  */
/** 5) Outputs the held registered version of the CInvokeEncrypt bounds, base and length which is
  * used during readcacheline /writeback cacheline operations for calculating the Auth Tag address.
  */
/** Note: The Fetch stage pre-fetches instructions meaning that the fetch address will go outside
  * the bounds before the current PCC. When this happens we want the instruction cache to fetch from
  * memory and not the encryption cache. This doesn't mean we have left the enclave if PCC is still
  * within the bounds so we need to continue the cache afterwards. (For example the enclave code may
  * contain jump instructions to jump backwards)
  */

/** define inputs/outputs in a bundle */
case class boundsCheckerIO(cacheConfig: cacheConfig) extends Bundle with IMasterSlave {
  // cmdAddress out to AXI from fetch/memory (includes pre-fetching instructions so will go outside enclave bounds)
  val currentCmdAddress = UInt(cacheConfig.addrWidth) // UInt() // Bits(cacheConfig.addrWidth)
  val currentCmdAddress_vld = Bool() // high when command address is valid
  // PCC bounds from fetch (stays with these bounds until exit from enclave)
  val currentPCCboundsBase = UInt(cacheConfig.addrWidth)
  val currentPCCboundsTop = UInt(cacheConfig.addrWidth)
  // bounds from CInvoke instruction (these are the required bounds)
  val CInvokePCCboundsBase = UInt(cacheConfig.addrWidth)
  val CInvokePCCboundsTop = UInt(cacheConfig.addrWidth)
  // for instruction cache this is pcc bounds, for data cache this is dc bounds
  val CInvokecmdAddrboundsBase = UInt(cacheConfig.addrWidth)
  // for instruction cache this is pcc bounds, for data cache this is dc bounds
  val CInvokeCmdAddrboundsTop = UInt(cacheConfig.addrWidth)
  // this is registered and fed back out to be used for capLen during readcacheline /writeback cacheline to calc tagAddr location
  // kept in this block where the rest of the cinvoke inputs are registered and cleared
  val CInvokeCmdAddrboundsLen = UInt(cacheConfig.addrWidth)
  val CInvokeboundsUpdate = Bool() // high when new bounds values need to be updated
  // when exit the enclave clear the bounds by the controller
  val clearBounds = Bool() // high when bounds values need to be reset to 0
  // outputs (these are not registered outputs and will flag for the current input address)
  val addrOutOfBounds = Bool() // output high when the cmdAddress is out of the enclave bounds
  val PCCOutOfBounds = Bool() // output high when fetch PCC is out of the enclave bounds
  // outputs - registered outputs used for read/write cacheline
  val capBase = UInt(
    cacheConfig.addrWidth
  ) // output registered capBase (CInvokeCmdAddrboundsBaseReg)
  val capLen = UInt(cacheConfig.addrWidth) // output registered capLen (CInvokeCmdAddrboundsLenReg)
  /** Set the direction of each bundle/signal from a master point of view */
  override def asMaster(): Unit = {

    /** declare outputs for master, so will be inputs for slave */
    out(currentCmdAddress)
    out(currentCmdAddress_vld)
    out(currentPCCboundsBase)
    out(currentPCCboundsTop)
    out(CInvokePCCboundsBase)
    out(CInvokePCCboundsTop)
    out(CInvokecmdAddrboundsBase)
    out(CInvokeCmdAddrboundsTop)
    out(CInvokeCmdAddrboundsLen)
    out(CInvokeboundsUpdate)
    out(clearBounds)

    /** declare inputs for master, so will be outputs for slave */
    in(addrOutOfBounds)
    in(PCCOutOfBounds)
    in(capLen)
    in(capBase)
  }
}

class cacheBoundsChecker(cacheConfig: cacheConfig) extends Component {

  /** Inputs / Outputs */
  val io = slave(boundsCheckerIO(cacheConfig))

  /** register CInvoke_encrypt bounds - only update bounds values on a trigger input, otherwise hold
    * their values, and reset when done to clear them
    */
  val CInvokePCCboundsBaseReg: UInt = Reg(UInt(cacheConfig.addrWidth)) init (0x0)
  val CInvokePCCboundsTopReg: UInt = Reg(UInt(cacheConfig.addrWidth)) init (0x0)
  val CInvokecmdAddrboundsBaseReg: UInt = Reg(UInt(cacheConfig.addrWidth)) init (0x0)
  val CInvokeCmdAddrboundsTopReg: UInt = Reg(UInt(cacheConfig.addrWidth)) init (0x0)
  val CInvokeCmdAddrboundsLenReg: UInt = Reg(UInt(cacheConfig.addrWidth)) init (0x0)
  when(io.CInvokeboundsUpdate) {
    CInvokePCCboundsBaseReg := io.CInvokePCCboundsBase
    CInvokePCCboundsTopReg := io.CInvokePCCboundsTop
    CInvokecmdAddrboundsBaseReg := io.CInvokecmdAddrboundsBase
    CInvokeCmdAddrboundsTopReg := io.CInvokeCmdAddrboundsTop
    CInvokeCmdAddrboundsLenReg := io.CInvokeCmdAddrboundsLen
  } elsewhen (io.clearBounds) {
    CInvokePCCboundsBaseReg := 0
    CInvokePCCboundsTopReg := 0
    CInvokecmdAddrboundsBaseReg := 0
    CInvokeCmdAddrboundsTopReg := 0
    CInvokeCmdAddrboundsLenReg := 0
  }

  /** Assign capLen capBase straight to output */
  io.capLen := CInvokeCmdAddrboundsLenReg
  io.capBase := CInvokecmdAddrboundsBaseReg

  /** compare the cmdAddress value to the CInvoke_encrypt bounds, and flag high when out of bounds
    */
  /** This means we are prefetching outside the enclave */

  when(io.currentCmdAddress_vld) {
    when(io.currentCmdAddress < CInvokecmdAddrboundsBaseReg) {
      io.addrOutOfBounds := True // out of bounds
    } elsewhen (io.currentCmdAddress >= CInvokeCmdAddrboundsTopReg) {
      io.addrOutOfBounds := True // out of bounds
    } otherwise {
      io.addrOutOfBounds := False // in bounds
    }
  } otherwise {
    io.addrOutOfBounds := False // in bounds because not valid
  }

  /** compare the PCC bounds to the CInvoke_encrypt bounds, and flag high when out of bounds */
  /** This means we have exited out of the enclave */
  when(io.currentPCCboundsBase =/= CInvokePCCboundsBaseReg) {
    io.PCCOutOfBounds := True // out of bounds when not equal
  } elsewhen (io.currentPCCboundsTop =/= CInvokePCCboundsTopReg) {
    io.PCCOutOfBounds := True // out of bounds
  } otherwise {
    io.PCCOutOfBounds := False // in bounds
  }

}

/** Generate VHDL */
object cacheBoundsCheckerVhdl {
  def main(args: Array[String]) {
    val cacheConfig = new cacheConfig(
      addrWidth = 32 bits, // 8
      dataWidth = 32 bits,
      sizeCacheLine = 16, // In bytes 256
      numCacheLines = 4,
      maskWidth = 4 bits
    )
    SpinalVhdl(new cacheBoundsChecker(cacheConfig))
  }
}
