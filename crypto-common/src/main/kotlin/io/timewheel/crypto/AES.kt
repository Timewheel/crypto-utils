package io.timewheel.crypto

import io.timewheel.crypto.encoding.EncodableType


/**
 * AES algorithm and its parameters.
 */
class AES(val mode: Mode, val keyLength: KeyLength) : EncryptionAlgorithm("AES") {

    override fun mode() = mode.modeString

    override fun keyLength() = keyLength.keyLength

    /**
     * AES modes.
     */
    sealed class Mode(internal val modeString: String) {



        /**
         * GCM.
         */
        object GCM : Mode("GCM/NoPadding") {

            data class Input(
                val tagLength: Int = 128,
                val ivLength: Int = 96
            ) : io.timewheel.crypto.cipher.Algorithm.EncryptionInputs<Output>() {
                val name: String = ""

                override fun getDecryptionInputs(): Output {
                    return Output(tagLength, getRandomNonce(ivLength/8))
                }
            }

            data class Output(
                val tagLength: Int,
                val iv: ByteArray
            ) : io.timewheel.crypto.cipher.Algorithm.DecryptionInputs() {

                override fun getEncodingMapping(): Map<String, EncodableType> {
                    TODO("Not yet implemented")
                }
            }

//            companion object {
//                /**
//                 * Creates a default GCM specification with the following parameters:
//                 *
//                 * - Tag length: 128 bits.
//                 *   - TODO explain decision.
//                 * - Initialization vector length: 96 bits.
//                 *   - TODO explain decision.
//                 */
//                fun default() = GCM(tagLength = 128, ivLength = 96)
//            }
        }
    }

    /**
     * Key length of AES.
     */
    sealed class KeyLength(internal val keyLength: Int) {
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

    companion object {
        /**
         * Creates a default AES specification with the following parameters:
         *
         * - Mode: default [Mode.GCM], see [Mode.GCM.default].
         * - Key length: 256 bits.
         *   - A 256 bit key is the longest and most secure key length for AES.
         */
        fun default() = AES(mode = Mode.GCM, keyLength = KeyLength.L256)
    }
}
