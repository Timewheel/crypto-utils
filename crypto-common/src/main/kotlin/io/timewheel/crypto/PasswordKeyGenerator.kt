package io.timewheel.crypto

import io.timewheel.util.Result
import java.security.NoSuchAlgorithmException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.jvm.Throws

/**
 * Creates encryption keys from passwords.
 */
interface PasswordKeyGenerator {
    /**
     * Generates a key from a [password] for the requested [encryptionAlgorithm] and with the
     * specified [options].
     */
    fun generateKey(
        password: String,
        encryptionAlgorithm: EncryptionAlgorithm,
        options: Options
    ) : Result<Data, Error>

    /**
     * Algorithms to generate keys from passwords with. Currently supports the following out of
     * the box:
     *
     * - [PBKDF2WithHmacSHA256]: PBKDF2, Hmac SHA-256.
     *
     * This class is extensible; it can be subclassed, providing the algorithm [name] as taken by
     * [SecretKeyFactory.getInstance], to use a custom algorithm to generate a key from a password.
     */
    abstract class Algorithm(val name: String) {
        object PBKDF2WithHmacSHA256 : Algorithm("PBKDF2WithHmacSHA256")
    }

    /**
     * Options for key generation. Includes de following:
     *
     * - [algorithm]: the algorithm to use to generate the key.
     * - [saltProvider]: a [SaltProvider].
     * - [iterationCount]: the number of iterations
     */
    class Options(
        val algorithm: Algorithm = DEFAULT_ALGORITHM,
        val saltProvider: SaltProvider = RandomSaltGenerator.ofSaltLength(DEFAULT_SALT_LENGTH_BYTES),
        val iterationCount: Int = DEFAULT_ITERATION_COUNT
    ) {
        companion object {
            val DEFAULT_ALGORITHM = Algorithm.PBKDF2WithHmacSHA256
            const val DEFAULT_SALT_LENGTH_BYTES = 16
            const val DEFAULT_ITERATION_COUNT = 65536
        }
    }

    /**
     * Result of generating
     */
    class Data(
        val keySpec: SecretKeySpec,
        val salt: ByteArray
    )

    sealed class Error {
        data class InvalidArgument(val argumentName: String, val value: String, val requirement: String) : Error()
        data class AlgorithmNotSupported(val algorithm: Algorithm) : Error()
    }

    companion object {
        /**
         * Creates a [PasswordKeyGenerator].
         */
        @JvmStatic
        fun create(): PasswordKeyGenerator {
            return PasswordKeyGeneratorImpl(SecretKeyFactoryProviderImpl())
        }
    }
}

internal class PasswordKeyGeneratorImpl(
    private val secretKeyFactoryProvider: SecretKeyFactoryProvider
) : PasswordKeyGenerator {
    override fun generateKey(
        password: String,
        encryptionAlgorithm: EncryptionAlgorithm,
        options: PasswordKeyGenerator.Options
    ) : Result<PasswordKeyGenerator.Data, PasswordKeyGenerator.Error> {

        // Validation
        if (options.iterationCount < 0) {
            return Result.Fail(PasswordKeyGenerator.Error.InvalidArgument(
                "iterationCount",
                "${options.iterationCount}",
                ">=0"
            ))
        }

        // Create the factory first to fail fast
        val factory: SecretKeyFactory = try {
            secretKeyFactoryProvider.provideSecretKeyFactory(options.algorithm)
        } catch (x: NoSuchAlgorithmException) {
            return Result.Fail(PasswordKeyGenerator.Error.AlgorithmNotSupported(options.algorithm))
        }

        // Generate the key
        val salt = options.saltProvider.provideSalt()
        val passwordKeySpec = PBEKeySpec(
            password.toCharArray(),
            salt,
            options.iterationCount,
            encryptionAlgorithm.keyLength()
        )
        val keySpec = SecretKeySpec(
            factory.generateSecret(passwordKeySpec).encoded,
            encryptionAlgorithm.name
        )

        // Return success data
        return Result.Success(PasswordKeyGenerator.Data(keySpec, salt))
    }
}

/**
 * Provides non-static access to [SecretKeyFactory].
 */
internal interface SecretKeyFactoryProvider {
    /**
     * Provides a [SecretKeyFactory] for the requested [algorithm].
     */
    @Throws(NoSuchAlgorithmException::class)
    fun provideSecretKeyFactory(algorithm: PasswordKeyGenerator.Algorithm): SecretKeyFactory
}

/**
 * Production implementation of [SecretKeyFactoryProvider]. Calls [SecretKeyFactory.getInstance].
 */
internal class SecretKeyFactoryProviderImpl : SecretKeyFactoryProvider {
    @Throws(NoSuchAlgorithmException::class)
    override fun provideSecretKeyFactory(algorithm: PasswordKeyGenerator.Algorithm): SecretKeyFactory {
        return SecretKeyFactory.getInstance(algorithm.name)
    }
}
