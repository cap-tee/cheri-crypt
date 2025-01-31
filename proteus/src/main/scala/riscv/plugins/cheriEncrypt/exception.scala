package riscv.plugins.cheriEncrypt

/** List of CHERI-Crypt exception causes added */
sealed abstract class EncryptExceptionCause(val code: Int)

/** last cheri exception cause code is PermitSetCidViolation extends ExceptionCause(0x1c) so start
  * after that. see cheri.scala
  */

/** NOTE the exception cause is limited to 5 bits, so 1f is the highest code we can use. This means
  * only 3 codes available above 0x1c. However 0x0b to 0x0f are also unused.
  */

object EncryptExceptionCause {

  /** encryption permission bit violation */
  case object PermitEncryptionViolation extends EncryptExceptionCause(0x1d)

  /** errors encountered during encryption */
  /** key table run out of slots */
  case object EncKeyTableViolation extends EncryptExceptionCause(0x1e)

  /** encryption capability length error */
  /** capability length does not fit within multiples of the batch length plus IV and authTag space
    */
  case object EncCapLenViolation extends EncryptExceptionCause(0x0b)

  /** decryption tag error */
  case object EncTagViolation extends EncryptExceptionCause(0x1f)

}
