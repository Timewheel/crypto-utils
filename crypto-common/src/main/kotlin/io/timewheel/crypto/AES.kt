package io.timewheel.crypto

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
        class GCM(val tagLength: Int, val ivLength: Long) : Mode("GCM/NoPadding") {

            companion object {
                /**
                 * Creates a default GCM specification with the following parameters:
                 *
                 * - Tag length: 128 bits.
                 *   - TODO explain decision.
                 * - Initialization vector length: 96 bits.
                 *   - TODO explain decision.
                 */
                fun default() = GCM(tagLength = 128, ivLength = 96)
            }
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
        fun default() = AES(mode = Mode.GCM.default(), keyLength = KeyLength.L256)
    }
}
