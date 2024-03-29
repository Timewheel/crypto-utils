package io.timewheel.crypto.cipher

import io.timewheel.crypto.NonceProvider
import io.timewheel.crypto.RandomNonceGenerator
import io.timewheel.crypto.encoding.BadFormatException
import io.timewheel.crypto.encoding.EncodableType
import io.timewheel.crypto.encoding.encodableType
import io.timewheel.util.ByteArrayWrapper
import io.timewheel.util.wrap
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.GCMParameterSpec

/**
 * Algorithm implementation for AES. Modes are implemented as separate algorithms under AES, as
 * they provide their own types of [AlgorithmParameterSpec].
 */
abstract class AES<
    EncryptionInputsType : Algorithm.EncryptionInputs<DecryptionInputsType>,
    DecryptionInputsType : Algorithm.DecryptionInputs
> (
    keyLength: KeyLength
) : Algorithm<EncryptionInputsType, DecryptionInputsType>(keyLength) {

    override fun transformation(): String {
        return "${getName()}/${getMode()}"
    }

    override fun getName() = "AES"

    /**
     * Gets the mode of operation for the AES implementation.
     */
    abstract fun getMode(): String

    /**
     * Implementation of GCM with no padding.
     */
    class GcmNoPadding(keyLength: KeyLength) : AES<GcmNoPadding.EncryptionInputs, GcmNoPadding.DecryptionInputs>(keyLength) {

        override fun getMode() = "GCM/NoPadding"

        override fun getDecryptionInputs(encryptionInputs: EncryptionInputs) = with(encryptionInputs.getDecryptionInputs()) {
            Pair(getParameterSpec(this), this)
        }

        override fun getDecryptionInputs(mapping: Map<String, EncodableType>): DecryptionInputs {
            val tagLength = mapping["tl"] as? EncodableType.Int ?: throw BadFormatException()
            val iv = mapping["iv"] as? EncodableType.ByteArray ?: throw BadFormatException()
            return DecryptionInputs(tagLength.value, iv.value)
        }

        override fun getParameterSpec(decryptionInputs: DecryptionInputs): AlgorithmParameterSpec {
            return GCMParameterSpec(decryptionInputs.tagLength, decryptionInputs.iv.data)
        }

        override fun equals(other: Any?): Boolean {
            if (other is GcmNoPadding) {
                return other.keyLength == keyLength
            }
            return false
        }

        override fun hashCode(): Int {
            return javaClass.hashCode()
        }

        /**
         * Inputs for AES - GCM, No Padding. Includes the following:
         *
         * - [tagLength]: length in bits of the authentication tag. Defaults to 128, the maximum value.
         * - [ivProvider]:
         */
        class EncryptionInputs(
            val tagLength: Int = 128,
            val ivProvider: NonceProvider = RandomNonceGenerator.ofNonceSize(96/8)
        ) : Algorithm.EncryptionInputs<DecryptionInputs>() {
            override fun getDecryptionInputs() = DecryptionInputs(
                tagLength, ivProvider.provideNonce().wrap()
            )
        }

        data class DecryptionInputs(
            val tagLength: Int = 128,
            val iv: ByteArrayWrapper
        ) : Algorithm.DecryptionInputs() {
            override fun getEncodingMapping() = mapOf(
                "tl" to tagLength.encodableType(),
                "iv" to iv.data.encodableType()
            )
        }
    }

    /**
     * Key length of AES. Supported lengths are the following:
     * - [L128]: 128 bits.
     * - [L192]: 192 bits.
     * - [L256]: 256 bits.
     */
    sealed class KeyLength(bits: Int) : Algorithm.KeyLength(bits) {
        /**
         * 128-bit.
         */
        object L128 : KeyLength(128)

        /**
         * 192-bit.
         */
        object L192 : KeyLength(192)

        /**
         * 256-bit.
         */
        object L256 : KeyLength(256)
    }
}
