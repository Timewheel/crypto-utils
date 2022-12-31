package io.timewheel.crypto.cipher.password

import io.timewheel.crypto.NonceProvider
import io.timewheel.crypto.StaticNonceProvider
import io.timewheel.crypto.encoding.BadFormatException
import io.timewheel.crypto.encoding.Encodable
import io.timewheel.crypto.encoding.EncodableType
import io.timewheel.crypto.encoding.encodableType
import io.timewheel.util.ByteArrayWrapper
import io.timewheel.util.Result
import io.timewheel.util.wrap
import java.security.NoSuchAlgorithmException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlin.jvm.Throws

/**
 * Creates encryption keys from passwords.
 */
interface PasswordKeyGenerator {
    /**
     * Generates a key from a [password] using the parameters specified in [options].
     */
    fun generateKey(password: String, options: Options): Result<ResultData, Error>

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
     * - [saltProvider]: a [NonceProvider].
     * - [algorithm]: the algorithm to use to generate the key.
     * - [iterationCount]: the number of iterations the password is hashed to get the key.
     * - [keyLength]: the length of the resulting key in bits.
     */
    class Options(
        val saltProvider: NonceProvider,
        val algorithm: Algorithm,
        val iterationCount: Int,
        val keyLength: Int
    ) {
        companion object {
            @JvmStatic
            internal fun fromEncodingMapping(
                keyLength: Int,
                algorithm: Algorithm,
                mapping: Map<String, EncodableType>
            ): Options {
                val salt = mapping["s"] as? EncodableType.ByteArray ?: throw BadFormatException()
                val iterationCount = mapping["i"] as? EncodableType.Int ?: throw BadFormatException()

                return Options(
                    StaticNonceProvider(salt.value.data),
                    algorithm,
                    iterationCount.value,
                    keyLength
                )
            }
        }
    }

    /**
     * Result of generating a key from a password. Includes the [key] as well as the [salt], just
     * in case the default or another random salt provider was used.
     */
    data class ResultData(
        val key: ByteArrayWrapper,
        val salt: ByteArrayWrapper,
        val iterationCount: Int
    ) : Encodable {
        constructor(key: ByteArray, salt: ByteArray, iterationCount: Int) : this(key.wrap(), salt.wrap(), iterationCount)

        override fun getEncodingMapping() = mapOf(
            "s" to salt.data.encodableType(),
            "i" to iterationCount.encodableType()
        )
    }

    /**
     * Errors that could arise in the process of generating a key from a password.
     */
    sealed class Error {
        /**
         * One of the supplied arguments was invalid. Provides the [argumentName] as well as the
         * [value] and the [requirement].
         */
        data class InvalidArgument(val argumentName: String, val value: String, val requirement: String) : Error()

        /**
         * The requested [algorithm] to generate a key is not supported by your platform.
         */
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
        options: PasswordKeyGenerator.Options
    ): Result<PasswordKeyGenerator.ResultData, PasswordKeyGenerator.Error> {

        // Validation
        if (options.iterationCount <= 1000) {
            return Result.Failure(PasswordKeyGenerator.Error.InvalidArgument(
                argumentName = "iterationCount",
                value = "${options.iterationCount}",
                requirement = ">1000"
            ))
        }
        if (options.keyLength <= 0 || options.keyLength % 8 != 0) {
            // PBKeySpec will take a key of at least 8 bits and will generate a key even if the
            // number of bits does not align with a whole number of bytes, flooring to the closest
            // whole byte. The choice to throw an error here is that all these parameters must be
            // chosen intentionally; passing a parameter that isn't a multiple of 8 implies that it
            // wasn't chosen carefully enough and the choice must be revisited.
            return Result.Failure(PasswordKeyGenerator.Error.InvalidArgument(
                argumentName = "keyLength",
                value = "${options.keyLength}",
                requirement = "> 0 AND a multiple of 8"
            ))
        }

        // Create the factory first to fail fast if need be.
        val keyFactory: SecretKeyFactory = try {
            secretKeyFactoryProvider.provideSecretKeyFactory(options.algorithm)
        } catch (x: NoSuchAlgorithmException) {
            return Result.Failure(PasswordKeyGenerator.Error.AlgorithmNotSupported(options.algorithm))
        }

        // Generate the key
        val salt = options.saltProvider.provideNonce()
        val key = keyFactory.generateSecret(
            PBEKeySpec(
                password.toCharArray(),
                salt,
                options.iterationCount,
                options.keyLength
            )
        ).encoded

        // Return success data
        return Result.Success(PasswordKeyGenerator.ResultData(key, salt, options.iterationCount))
    }
}

/**
 * Provides non-static access to [SecretKeyFactory].
 */
internal interface SecretKeyFactoryProvider {
    /**
     * Provides a [SecretKeyFactory] for the requested [algorithm]. Note that this method throws
     * instead of delivering a [Result]. This is because of two reasons:
     * - This is an internal component designed to provide testability to the component.
     * - The only exception [SecretKeyFactory.getInstance] throws is [NoSuchAlgorithmException].
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
