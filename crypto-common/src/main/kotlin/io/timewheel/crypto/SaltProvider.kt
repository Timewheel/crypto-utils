package io.timewheel.crypto

import java.security.SecureRandom

/**
 * Provides salts.
 */
interface SaltProvider {
    /**
     * Provides a salt.
     */
    fun provideSalt(): ByteArray
}

/**
 * Generates salts of a given length.
 */
class RandomSaltGenerator private constructor(private val saltLengthBytes: Int) : SaltProvider {

    private val secureRandom = SecureRandom()

    override fun provideSalt(): ByteArray {
        val salt = ByteArray(saltLengthBytes)
        secureRandom.nextBytes(salt)
        return salt
    }

    companion object {
        /**
         * Creates a [RandomSaltGenerator] providing salts of length [saltLengthBytes].
         */
        @JvmStatic
        @Throws(IllegalArgumentException::class)
        fun ofSaltLength(saltLengthBytes: Int) : RandomSaltGenerator {
            if (saltLengthBytes < 0) {
                throw IllegalArgumentException("Salt length can't be negative")
            }
            return RandomSaltGenerator(saltLengthBytes)
        }
    }
}

/**
 * Provides a single salt.
 */
class StaticSaltProvider(salt: ByteArray) : SaltProvider {
    private val salt = salt.copyOf()

    override fun provideSalt() = salt.copyOf()
}
