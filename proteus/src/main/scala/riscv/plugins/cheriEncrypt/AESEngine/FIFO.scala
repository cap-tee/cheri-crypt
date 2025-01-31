package riscv.plugins.cheriEncrypt.AESEngine

import spinal.core._
import spinal.lib._

import spinal.core._
import spinal.lib._

class SingleClockFifo(width: Int, depth: Int) extends Component {
  val io = new Bundle {
    val push = slave Stream (Bits(width bits)) // Input side (write)
    val pop = master Stream (Bits(width bits)) // Output side (read)
  }

  // Instantiate a StreamFifo with the given width and depth
  val fifo = StreamFifo(Bits(width bits), depth)

  // Connect push and pop interfaces
  fifo.io.push << io.push
  io.pop << fifo.io.pop
}

object SingleClockFifo {
  def main(args: Array[String]): Unit = {
    SpinalVerilog(new SingleClockFifo(width = 8, depth = 16))
  }
}
