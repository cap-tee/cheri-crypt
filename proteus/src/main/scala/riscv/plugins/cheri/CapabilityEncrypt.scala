//To incorporate extra encrypt permission:
//This file includes extended traits and classes with the added permission
//The original capability file has been modified as:
//renaming so new extended version in capabilityEncrypt.scala has original name
//replaced Permissions with Permissions_standard
//replaced PackedPermissions with PackedPermissions_standard
//replaced memPermissions with memPermissions_standard
//   (except MemPermissions in MemCapability, and permissions in trait Capability)

package riscv.plugins.cheri

import spinal.core._

//extend cheri permissions trait to include encrypt permission
trait Permissions extends Permissions_standard {
  // add new permission
  def encrypt: Bool

  // use override to change the setAll method to set encrypt permission
  override def setAll(value: Bool): Unit = {
    // first set all that exist already
    super.setAll(value)
    // then set new permission
    encrypt := value
  }

  override def allowAll(): Unit = setAll(True)
  override def allowNone(): Unit = setAll(False)

  override def asIsaBits: Bits = {
    // add encrypt to bit list
    encrypt ## B"0" ## accessSystemRegisters ## unseal ## cinvoke ## seal ## B"0" ##
      storeCapability ## loadCapability ## store ## load ## execute ## B"0" resized
  }

  override def assignFromIsaBits(bits: Bits): Unit = {
    // first set all that exist already
    super.assignFromIsaBits(bits: Bits)
    // then set new permission at bit 12
    encrypt := bits(12)
  }

  // don't use override here because Permissions in constructor is
  // different from cheri standard permissions
  def assignFrom(other: Permissions): Unit = {
    // first assign all that exist already
    super.assignFrom(other: Permissions)
    // then assign new permission
    encrypt := other.encrypt
  }

}

//extend PackedPermissions class with new Permissions trait
case class PackedPermissions() extends Bundle with Permissions {
  override val execute = Bool()
  override val load = Bool()
  override val store = Bool()
  override val loadCapability = Bool()
  override val storeCapability = Bool()
  override val seal = Bool()
  override val cinvoke = Bool()
  override val unseal = Bool()
  override val accessSystemRegisters = Bool()
  // add encrypt val, when true no encryption
  override val encrypt = Bool()
}

//case class ObjectType doesn't need changing
//trait capability doesn't need changing
//class and companion object PackedCapabilityFields doesn't need changing
//class and companion object PackedCapability doesn't need changing
//class and companion object RegCapability doesn't need changing

//extend MemPermissions class with new Permissions trait
case class MemPermissions() extends Bundle with Permissions {
  private val padding1 = B"0"
  override val execute = Bool()
  override val load = Bool()
  override val store = Bool()
  override val loadCapability = Bool()
  override val storeCapability = Bool()
  private val padding2 = B"0"
  override val seal = Bool()
  override val cinvoke = Bool()
  override val unseal = Bool()
  override val accessSystemRegisters = Bool()
  // add encrypt val
  override val encrypt = Bool()
  // reduce padding bits from 4 to 3
  private val padding3 = B"000"

  assert(getBitsWidth == 15)
}

//case class MemCapability doesn't need changing
