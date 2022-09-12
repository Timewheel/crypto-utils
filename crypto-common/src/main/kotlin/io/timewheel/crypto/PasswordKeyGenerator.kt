package io.timewheel.crypto

import io.timewheel.util.Result
import java.security.NoSuchAlgorithmException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

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
     * Algorithms to generate keys from passwords with. Currently supports the following:
     *
     * - [PBKDF2WithHmacSHA256]: PBKDF2, Hmac SHA-256
     */
    sealed class Algorithm(internal val name: String) {
        object PBKDF2WithHmacSHA256 : Algorithm("PBKDF2WithHmacSHA256")
    }

    /**
     * Options for key generation. Includes de following:
     *
     * - [algorithm]: the algorithm to use to generate the key.
     * - [saltLengthBytes]: the length of the salt in bytes.
     * - [iterationCount]: the
     */
    class Options(
        val algorithm: Algorithm = DEFAULT_ALGORITHM,
        val saltLengthBytes: Int = DEFAULT_SALT_LENGTH_BYTES,
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
}

class PasswordKeyGeneratorImpl : PasswordKeyGenerator {
    override fun generateKey(
        password: String,
        encryptionAlgorithm: EncryptionAlgorithm,
        options: PasswordKeyGenerator.Options
    ) : Result<PasswordKeyGenerator.Data, PasswordKeyGenerator.Error> {

        // Validation
        if (options.saltLengthBytes < 0) {
            return Result.Fail(PasswordKeyGenerator.Error.InvalidArgument(
                "saltLengthBytes",
                "${options.saltLengthBytes}",
                ">= 0"
            ))
        }
        if (options.iterationCount < 0) {
            return Result.Fail(PasswordKeyGenerator.Error.InvalidArgument(
                "iterationCount",
                "${options.iterationCount}",
                ">= 0"
            ))
        }

        // Create the factory first to fail fast
        val factory: SecretKeyFactory = try {
            SecretKeyFactory.getInstance(options.algorithm.name)
        } catch (x: NoSuchAlgorithmException) {
            return Result.Fail(PasswordKeyGenerator.Error.AlgorithmNotSupported(options.algorithm))
        }

        // Generate the key
        val salt = getRandomNonce(options.saltLengthBytes)
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
