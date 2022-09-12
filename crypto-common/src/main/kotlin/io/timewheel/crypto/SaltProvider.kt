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
 * Generates salts of a given size.
 */
class RandomSaltGenerator private constructor(private val saltSizeBytes: Int) : SaltProvider {

    private val secureRandom = SecureRandom()

    override fun provideSalt(): ByteArray {
        val salt = ByteArray(saltSizeBytes)
        secureRandom.nextBytes(salt)
        return salt
    }

    companion object {
        /**
         * Creates a [RandomSaltGenerator] providing salts of length [saltSizeBytes].
         */
        @JvmStatic
        @Throws(IllegalArgumentException::class)
        fun ofSaltLength(saltSizeBytes: Int) : RandomSaltGenerator {
            if (saltSizeBytes < 0) {
                throw IllegalArgumentException("Salt size can't be negative")
            }
            return RandomSaltGenerator(saltSizeBytes)
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
