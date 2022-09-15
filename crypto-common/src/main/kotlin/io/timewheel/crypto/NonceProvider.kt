package io.timewheel.crypto

import java.security.SecureRandom

/**
 * Provides nonces.
 */
interface NonceProvider {
    /**
     * Provides a nonce.
     */
    fun provideNonce(): ByteArray
}

/**
 * Generates nonces of a given size.
 */
class RandomNonceGenerator private constructor(private val nonceSizeBytes: Int) : NonceProvider {

    private val secureRandom = SecureRandom()

    override fun provideNonce(): ByteArray {
        val nonce = ByteArray(nonceSizeBytes)
        secureRandom.nextBytes(nonce)
        return nonce
    }

    companion object {
        /**
         * Creates a [RandomNonceGenerator] providing nonces of length [nonceSizeBytes].
         *
         * @throws [IllegalArgumentException] if the nonce length is negative.
         */
        @JvmStatic
        @Throws(IllegalArgumentException::class)
        fun ofNonceSize(nonceSizeBytes: Int) : RandomNonceGenerator {
            if (nonceSizeBytes < 0) {
                throw IllegalArgumentException("Nonce size can't be negative")
            }
            return RandomNonceGenerator(nonceSizeBytes)
        }
    }
}

/**
 * Provides a single nonce.
 */
class StaticNonceProvider(nonce: ByteArray) : NonceProvider {
    private val nonce = nonce.copyOf()

    override fun provideNonce() = nonce.copyOf()
}
