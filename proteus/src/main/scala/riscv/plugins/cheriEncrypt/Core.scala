package riscv.plugins.cheriEncrypt

import AESEngine.{AES_DecConfig, AES_EncConfig}
import spinal.core._
import spinal.core.sim._
import riscv._
import riscv.soc._
import riscv.sim._
import riscv.StaticPipeline
import riscv.plugins.StaticMemoryBackbone
import riscv.plugins.cheri

object createCheriEncryptPipeline {
  def apply(memorySize: BigInt)(implicit conf: Config): StaticPipeline = {
    val pipeline = new Component with StaticPipeline {
      setDefinitionName("Pipeline")

      val fetch = new Stage("IF")
      val decode = new Stage("ID")
      val execute = new Stage("EX")
      val memory = new Stage("MEM")
      val writeback = new Stage("WB")

      override val stages = Seq(fetch, decode, execute, memory, writeback)
      override val passThroughStage: Stage = execute // TODO: ?
      override val config: Config = conf
      override val data: StandardPipelineData = new StandardPipelineData(conf)
      override val pipelineComponent: Component = this
    }

    /** add riscv parts */
    import riscv.{plugins => rvp}

    pipeline.addPlugins(
      Seq(
        new rvp.scheduling.static.Scheduler,
        new rvp.scheduling.static.DataHazardResolver(firstRsReadStage = pipeline.execute),
        new rvp.TrapHandler(pipeline.writeback),
        new rvp.TrapStageInvalidator, // TODO: ?
        new StaticMemoryBackbone,
        // new rvp.Fetcher(pipeline.fetch), // Fetcher now part of FetcherEncrypt in CHERI-Crypt
        new rvp.Decoder(pipeline.decode),
        new rvp.RegisterFileAccessor(pipeline.decode, pipeline.writeback),
        new rvp.IntAlu(Set(pipeline.execute)),
        new rvp.Shifter(Set(pipeline.execute)),
        new rvp.Lsu(Set(pipeline.memory), Seq(pipeline.memory), pipeline.memory),
        new rvp.BranchUnit(Set(pipeline.execute)),
        new rvp.scheduling.static.PcManager(0x80000000L),
        new rvp.CsrFile(pipeline.writeback, pipeline.writeback), // TODO: ugly
        new rvp.Timers,
        new rvp.MachineMode(pipeline.execute, addMepc = false, addMtvec = false),
        new rvp.Interrupts(pipeline.writeback),
        new rvp.MulDiv(Set(pipeline.execute))
      )
    )

    /** add cheri parts */
    implicit val context = cheri.Context(pipeline)

    pipeline.addPlugins(
      Seq(
        new cheri.RegisterFile(pipeline.decode, pipeline.writeback),
        new cheri.Access(pipeline.execute),
        new cheri.ScrFile(pipeline.writeback),
        new cheri.Lsu(pipeline.memory),
        new cheri.ExceptionHandler,
        new cheri.Ccsr,
        // new cheri.MemoryTagger(0x80000000L, memorySize), // memory tagger now part of MemoryEncrypt2 in CHERI-Crypt
        new cheri.PccManager(pipeline.execute),
        new cheri.Sealing(pipeline.execute),
        new cheri.MachineMode
      )
    )

    /** then add CHERI-crypt encryption parts */

    /** define batch size and AES fifo depths here */
    /** Warning! make sure the core memory size is large enough, if you get a soc_dbusAXI_decoder ->
      * decodedCmdError then check size is big enough. set to min of 256 KiB to pass all encryption
      * tests
      */
    val batchSize: Int =
      32 // length of a batch in bytes - needs to be in multiples of 16bytes (128 bits), and power of 2
    val aesInputFifoDepth: Int = 8
    val aesOutputFifoDepth: Int = 8

    assert(aesInputFifoDepth > 3)
    assert(aesOutputFifoDepth > 3)

    /** define other generics */

    implicit val keyGenConfig =
      new table.KeyGenConfig(keyWidth = BitCount(128), oTypeWidth = 12)
    implicit val tableConfig =
      new table.TableConfig(
        keyWidth = BitCount(128),
        oTypeWidth = (12),
        numTableEntries = 3,
        IVWidth = BitCount(64)
      )

    implicit val cacheConfig = new cacheConfig(
      addrWidth = 32 bits,
      dataWidth = 32 bits,
      maskWidth = 4 bits,
      sizeCacheLine = batchSize, // 32 bytes is 8 32 bit words
      numCacheLines = 4 // 4 x 32 gives 128 bytes in total
    )

    implicit val encryptConfig = new EncryptConfig(
      fixedIV = 55, // fixed part of IV (32 bits) - determines device or context
      batchLength =
        batchSize, // length of a batch in bytes - needs to be in multiples of 16bytes (128 bits)
      lengthTagIV =
        32, // size of tag and IV in bytes should be 32 bytes, could also design with 16 bytes
      aesInputFifoDepth = aesInputFifoDepth, // ToDo merge this with CSealReadWriteConfig?
      aesOutputFifoDepth = aesOutputFifoDepth
    )

    implicit val csealConfig = new CSealReadWriteConfig(
      aesInputFifoDepth = aesInputFifoDepth,
      aesOutputFifoDepth = aesOutputFifoDepth
    )

    /** AES_core generics */
    implicit val aes_DecConfig = new AES_DecConfig(
      dataWidth = 128 bits,
      keyWidth = 128 bits
    )
    implicit val aes_EncConfig = new AES_EncConfig(
      dataWidth = 128 bits,
      keyWidth = 128 bits
    )

    pipeline.addPlugins(
      Seq(
        /** CHERI-Crypt Design components add */
        /** process CSealEncrypt Instruction, connects to both memoryEncrypt2 and KeyGenWrapper2 */
        new CSealEncrypt(pipeline.memory),

        /** CsealEncrypt read/write control */
        new CSealEReadWrite(),

        /** contains table and key generator from library import */
        new KeyGenWrapper2(),

        /** process CInvokeEncrypt instruction, connects to both caches and KeyGenWrapper2 */
        new CInvokeEncrypt(pipeline.memory),

        /** This replaces the fetcher component in the RISCV part */
        /** We modify fetcher to include an ibus control selector to route the AXI bus to the
          * encryption ibus cache
          */
        new FetcherEncrypt(pipeline.fetch),
        /** encryption cache for the ibus */
        new InstructionCacheEncrypt(aes_DecConfig, aes_EncConfig),

        /** AES control selector */
        new AESCntrlSelector(),
        /** AES Core */
        new AESTopWrapper(),

        /** encryption cache for the dbus */
        new DataCacheEncrypt(aes_DecConfig, aes_EncConfig),

        /** memory encrypt with DbusCntrlSelector */
        /** This includes the CHERI Tagger component and dbus control selector to route the AXI bus
          * to the encryption dbus cache
          */
        new MemoryEncrypt2(0x80000000L, memorySize)
      )
    )

    pipeline.build()
    pipeline
  }
}

object SoC {
  def static(ramType: RamType): SoC = {
    new SoC(
      ramType,
      config => {
        createCheriEncryptPipeline(memorySize = ramType.size)(config)
      }
    )
  }
}

object Core {
  def main(args: Array[String]) {
    SpinalVerilog(SoC.static(RamType.OnChipRam(10 MiB, args.headOption)))
  }
}

object CoreSim {
  def main(args: Array[String]) {
    SimConfig.withWave.compile(SoC.static(RamType.OnChipRam(10 MiB, Some(args(0))))).doSim { dut =>
      dut.clockDomain.forkStimulus(10)

      val byteDevSim = new StdioByteDev(dut.io.byteDev)

      var done = false

      while (!done) {
        dut.clockDomain.waitSampling()

        if (dut.io.charOut.valid.toBoolean) {
          val char = dut.io.charOut.payload.toInt.toChar

          if (char == 4) {
            println("Simulation halted by software")
            done = true
          } else {
            print(char)
          }
        }

        byteDevSim.eval()
      }
    }
  }
}

object CoreExtMem {
  def main(args: Array[String]) {
    SpinalVerilog(SoC.static(RamType.ExternalAxi4(10 MiB)))
  }
}
