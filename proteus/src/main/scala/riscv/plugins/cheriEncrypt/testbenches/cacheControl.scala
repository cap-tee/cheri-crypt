package riscv.plugins.cheriEncrypt.testbenches

import riscv.plugins.cheriEncrypt.{cache, cacheConfig, cacheIo}
import spinal.core._
import spinal.lib._

class cacheControl(cacheConfig: cacheConfig) extends Component {

  /** Inputs / Outputs */
  val io = slave(cacheIo(cacheConfig))
  // val cmdRdy = Bool()
  // val rspRdy = Bool()

  val icache = new cache(cacheConfig: cacheConfig)
  // register inputs for alignment of data and clk whilst simulation testing
  icache.io.cmd.valid := RegNext(io.cmd.valid).init(False)
  icache.io.cmd.payload := RegNext(io.cmd.payload)
  // io.cmd.ready := icache.io.cmd.ready

  // only valid to fetch if doing a read and there was a hit
  // ValidProcRead
  // io.rsp.valid := icache.io.rsp.valid && icache.io.rsp.payload.procread && icache.io.rsp.payload.hit
  io.rsp.valid := icache.io.rsp.valid
  io.rsp.payload.rdata := icache.io.rsp.payload.rdata

  // If there was a miss we need to set cmdRdy to low as we can't accept any more commands until
  // we have updated the cache
  // cmdRdy := Reg(icache.io.rsp.valid, !icache.io.rsp.payload.hit)

  // output to fetch not req
  io.rsp.payload.hit := icache.io.rsp.payload.hit
  io.rsp.payload.procread := icache.io.rsp.payload.procread
  io.rsp.payload.rtag := icache.io.rsp.payload.rtag
  io.rsp.payload.rdirty := icache.io.rsp.payload.rdirty
  io.rsp.payload.readLineAddr := icache.io.rsp.payload.readLineAddr
  io.rsp.payload.writebackLineAddr := icache.io.rsp.payload.writebackLineAddr

  io.rsp.payload.currentAddr := icache.io.rsp.payload.currentAddr
  io.rsp.payload.currentWmask := icache.io.rsp.payload.currentWmask
  io.rsp.payload.curentWdata := icache.io.rsp.payload.curentWdata
  io.rsp.payload.currentMemwrite := icache.io.rsp.payload.currentMemwrite
  io.rsp.payload.currentProcwrite := icache.io.rsp.payload.currentProcwrite
  io.rsp.payload.currentInputFromMem := icache.io.rsp.payload.currentInputFromMem

  io.rsp.payload.memread := icache.io.rsp.payload.memread
  io.rsp.payload.outputForMem := icache.io.rsp.payload.outputForMem
  io.rsp.payload.rProcWriteHit := icache.io.rsp.payload.rProcWriteHit

}
