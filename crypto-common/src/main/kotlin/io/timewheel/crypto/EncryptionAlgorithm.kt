package io.timewheel.crypto

import javax.crypto.Cipher

/**
 * Encryption algorithm.
 */
sealed class EncryptionAlgorithm(internal val name: String) {
    /**
     * Describes the full transformation to use in the [Cipher].
     */
    fun transformation() = "$name/${mode()}"

    /**
     * Describes the mode for the [Cipher] transformation.
     */
    internal abstract fun mode(): String

    /**
     * Key length in bits for the algorithm.
     */
    internal abstract fun keyLength(): Int
}
