package io.timewheel.crypto.cipher

import io.timewheel.util.Result
import java.security.NoSuchAlgorithmException
import javax.crypto.KeyGenerator
import kotlin.jvm.Throws

/**
 * Provides cryptographic keys for a given [Algorithm]. To create a provider use the [create] method.
 */
interface KeyProvider {
    /**
     * Provides a key.
     */
    fun provideKey(): ByteArray

    companion object {
        /**
         * Creates a [KeyProvider] for the requested [algorithm]. Returns a [Result.Failure] with
         * a [CreationError] if the process fails.
         */
        @JvmStatic
        fun create(algorithm: Algorithm<*, *>): Result<KeyProvider, CreationError> {
            return create(algorithm, KeyGeneratorProviderImpl())
        }

        internal fun create(
            algorithm: Algorithm<*, *>,
            keyGeneratorProvider: KeyGeneratorProvider
        ): Result<KeyProvider, CreationError> {
            return try {
                Result.Success(KeyProviderImpl(keyGeneratorProvider.provideKeyGenerator(algorithm)))
            } catch (x: NoSuchAlgorithmException) {
                Result.Failure(CreationError.AlgorithmNotSupported(algorithm))
            }
        }
    }

    sealed class CreationError {
        data class AlgorithmNotSupported(val algorithm: Algorithm<*, *>) : CreationError()
    }
}

internal class KeyProviderImpl(private val keyGenerator: KeyGenerator) : KeyProvider {
    override fun provideKey(): ByteArray = keyGenerator.generateKey().encoded
}

internal interface KeyGeneratorProvider {
    @Throws(NoSuchAlgorithmException::class)
    fun provideKeyGenerator(algorithm: Algorithm<*, *>): KeyGenerator
}

internal class KeyGeneratorProviderImpl : KeyGeneratorProvider {
    @Throws(NoSuchAlgorithmException::class)
    override fun provideKeyGenerator(algorithm: Algorithm<*, *>): KeyGenerator {
        val generator =  KeyGenerator.getInstance(algorithm.getName())
        generator.init(algorithm.keyLength.size)
        return generator
    }
}
