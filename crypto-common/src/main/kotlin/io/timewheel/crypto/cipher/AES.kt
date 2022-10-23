package io.timewheel.crypto.cipher

import io.timewheel.crypto.NonceProvider
import io.timewheel.crypto.RandomNonceGenerator
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
    private val mode: String,
    keyLength: KeyLength
) : Algorithm<EncryptionInputsType, DecryptionInputsType>("AES", keyLength) {

    override fun transformation(): String {
        return "$name/$mode"
    }

    /**
     * Implementation of GCM with no padding.
     */
    class GcmNoPadding(keyLength: KeyLength) : AES<GcmNoPadding.EncryptionInputs, GcmNoPadding.DecryptionInputs>("GCM/NoPadding", keyLength) {

        override fun getDecryptionInputs(encryptionInputs: EncryptionInputs) = with(encryptionInputs.getDecryptionInputs()) {
            Pair(getParameterSpec(this), this)
        }

        override fun getParameterSpec(decryptionInputs: DecryptionInputs): AlgorithmParameterSpec {
            return GCMParameterSpec(decryptionInputs.tagLength, decryptionInputs.iv)
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
            override fun getDecryptionInputs() =
                DecryptionInputs(tagLength, ivProvider.provideNonce())
        }

        data class DecryptionInputs(
            val tagLength: Int = 128,
            val iv: ByteArray
        ) : Algorithm.DecryptionInputs()
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
