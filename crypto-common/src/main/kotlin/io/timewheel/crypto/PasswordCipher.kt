package io.timewheel.crypto

import io.timewheel.crypto.DecryptionError.*
import io.timewheel.crypto.DecryptionResult.Failed
import io.timewheel.crypto.DecryptionResult.Success
import io.timewheel.crypto.cipher.password.PasswordKeyGenerator
import io.timewheel.util.Result
import java.nio.ByteBuffer
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.text.Charsets.UTF_8

/**
 * First version of the structure of the encryption output.
 */
private const val V1 = 1

/**
 * Current version of the structure of the encryption output.
 */
private const val CURRENT_OUTPUT_VERSION = V1

/**
 * Utility class to encrypt and decrypt [String]s with a password using AES and GCM. The format
 * of the output strings is a base 64 encoded string whose byte information is the following:
 *
 * - 4 bytes with the version of the structure of the encryption output.
 * - 4 bytes with the length of the algorithm string.
 * - Next n bytes will be the UTF8 byte encoding of the algorithm string.
 * - 4 bytes with the length of the salt.
 * - Next n bytes will be the salt.
 * - 4 bytes with the iteration count.
 * - 4 bytes with the key length.
 * - 4 bytes with the length of the IV.
 * - Next n bytes will be the IV.
 * - 4 bytes with the tag length.
 * - The remaining bytes will be the cipher text.
 */
// @AnyThread // Stateless
interface PasswordCipher {
    /**
     * Encrypts a single [input] string using a [password].
     */
    fun encrypt(input: String, password: String, options: Options): Result<String, EncryptionError>

    /**
     * Encrypts a list of [input] strings with a [password].
     */
    fun encrypt(input: List<String>, password: String, options: Options): List<Result<String, EncryptionError>>

    /**
     * Decrypts an [input] string that was produced with the [encrypt] method using a [password].
     * Returns a [DecryptionResult].
     */
    fun decrypt(input: String, password: String): Result<String, DecryptionError>

    /**
     * Builds instances of [PasswordCipher].
     */
    class Builder internal constructor(private val base64Coder: Base64Coder){
        private var saltLength = DEFAULT_SALT_LENGTH_BYTES
        private var ivLength = DEFAULT_IV_LENGTH_BYTES
        private var iterationCount = DEFAULT_ITERATION_COUNT
        private var keyLength = DEFAULT_KEY_LENGTH_BITS
        private var tagLength = DEFAULT_TAG_LENGTH_BITS

        fun setSaltLengthBytes(saltLength: Int) = this.also {
            this.saltLength = saltLength
        }

        fun setIvLengthBytes(ivLength: Int) = this.also {
            this.ivLength = ivLength
        }

        fun setIterationCount(iterationCount: Int) = this.also {
            this.iterationCount = iterationCount
        }

        fun setKeyLengthBits(keyLength: Int) = this.also {
            this.keyLength = keyLength
        }

        fun setTagLengthBits(tagLength: Int) = this.also {
            this.tagLength = tagLength
        }

        fun build(): PasswordCipher = PasswordCipherImpl(
            base64Coder,
            PasswordKeyGenerator.create(),
            AES.default(),
            saltLength,
            ivLength,
            iterationCount,
            keyLength,
            tagLength
        )

        companion object {

            /**
             * Default salt length. 16 bytes worth of salt should be good enough.
             */
            const val DEFAULT_SALT_LENGTH_BYTES = 16

            /**
             * According to [NIST](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf),
             * 96 bits IVs are the most efficient.
             */
            const val DEFAULT_IV_LENGTH_BYTES = 12

            /**
             * Default number of iterations used to generate the key from a password. 2^16 feels secure enough.
             */
            const val DEFAULT_ITERATION_COUNT = 65536

            /**
             * Default to AES256, which uses a key length of 256.
             */
            const val DEFAULT_KEY_LENGTH_BITS = 256

            /**
             * By default, use the highest tag length specified by
             * [NIST](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
             */
            const val DEFAULT_TAG_LENGTH_BITS = 128
        }
    }

    data class Options(
        val algorithm: EncryptionAlgorithm,
        val keyGenerationOptions: PasswordKeyGenerator.Options
    )

    companion object {
        fun build(base64Coder: Base64Coder, block: (Builder.() -> Unit)): PasswordCipher {
            val builder = Builder(base64Coder)
            block(builder)
            return builder.build()
        }

        // fun newInstance(coder: Base64Coder): PasswordCipher = PasswordCipherImpl(coder)
    }
}

// @AnyThread // Stateless
// @VisibleForTesting
internal class PasswordCipherImpl internal constructor(
    private val coder: Base64Coder,
    private val passwordKeyGenerator: PasswordKeyGenerator,
    private val algorithm: EncryptionAlgorithm,
    private val saltLengthBytes: Int,
    private val ivLengthBytes: Int,
    private val iterationCount: Int,
    private val keyLengthBits: Int,
    private val tagLengthBits: Int
): PasswordCipher {
    override fun encrypt(input: String, password: String, options: PasswordCipher.Options): Result<String, EncryptionError> {
        return encrypt(listOf(input), password, options).first()
    }

    override fun encrypt(input: List<String>, password: String, options: PasswordCipher.Options): List<Result<String, EncryptionError>> {
        val cipher: Cipher = try {
            Cipher.getInstance(algorithm.transformation())
        } catch (x: NoSuchAlgorithmException) {
            return listOf(Result.Failure(EncryptionError.AlgorithmNotSupported(options.algorithm)))
        } catch (x: NoSuchPaddingException) {
            return listOf(Result.Failure(EncryptionError.AlgorithmNotSupported(options.algorithm)))
        }

        return mutableListOf<Result<String, EncryptionError>>().apply {
            for (cleartext in input) {
                // Secret key from password
                passwordKeyGenerator.generateKey(password, options.keyGenerationOptions)
                    .doIfFailure {
                        // Add the relevant failure to the result list
                        add(Result.Failure(
                            when (it) {
                                is PasswordKeyGenerator.Error.InvalidArgument -> {
                                    EncryptionError.InvalidArgument(
                                        "keyGenerationOptions.${it.argumentName}",
                                        it.value,
                                        it.requirement
                                    )
                                }
                                is PasswordKeyGenerator.Error.AlgorithmNotSupported -> {
                                    EncryptionError.KeyGenerationAlgorithmNotSupported(it.algorithm)
                                }
                            }
                        ))
                    }.doIfSuccess {
                        add(encrypt(cipher, cleartext, it, options.algorithm))
                    }
            }
        }.toList()
    }

    private fun encrypt(
        cipher: Cipher,
        input: String,
        keyData: PasswordKeyGenerator.ResultData,
        algorithm: EncryptionAlgorithm
    ): Result<String, EncryptionError> {
        // Initialization vector
        val iv = getRandomNonce(ivLengthBytes)

        // AES-GCM needs GCMParameterSpec
        // Must initialize every time
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyData.key.data, algorithm.name), GCMParameterSpec(tagLengthBits, iv))

        // Encrypt the input
        val cipherText = cipher.doFinal(input.toByteArray(UTF_8))

        val algorithmBytes = algorithm.transformation().toByteArray(UTF_8)

        // Calculate the buffer size
        val bufferSize =
            // Version length
            Int.SIZE_BYTES +
                // Algorithm string length and the string as bytes
                Int.SIZE_BYTES +
                algorithmBytes.size +
                // Salt length and salt
                Int.SIZE_BYTES +
                keyData.salt.data.size +
                // Iteration count, key length
                2 * Int.SIZE_BYTES +
                // IV length and IV
                Int.SIZE_BYTES +
                iv.size +
                // Tag length
                Int.SIZE_BYTES +
                // Cipher text size
                cipherText.size

        // Encode the result
        val result = ByteBuffer.allocate(bufferSize)
            .putInt(CURRENT_OUTPUT_VERSION)
            .putInt(algorithmBytes.size)
            .put(algorithmBytes)
            .putInt(saltLengthBytes)
            .put(keyData.salt.data)
            .putInt(iterationCount)
            .putInt(keyLengthBits)
            .putInt(ivLengthBytes)
            .put(iv)
            .putInt(tagLengthBits)
            .put(cipherText)
            .array()

        // Add the result to the output
        return Result.Success(coder.encode(result))
    }

    override fun decrypt(input: String, password: String): Result<String, DecryptionError> {
        // Decode the base 64 input
        val buffer = ByteBuffer.wrap(coder.decode(input))

        // Decode version
        return when (buffer.int) {
            V1 -> decryptV1(buffer, password)
            else -> Result.Failure(BadFormat)
        }
    }

    private fun decryptV1(buffer: ByteBuffer, password: String): Result<String, DecryptionError> {
        // Decode Algorithm
        val algorithmBytes = ByteArray(buffer.int)
        buffer.get(algorithmBytes)
        val algorithmString = algorithmBytes.toString(UTF_8)
        if (algorithmString != "AES/GCM/NoPadding") {
            return Result.Failure(BadFormat)
        }

        // Decode Salt and IV
        val salt = ByteArray(buffer.int)
        buffer.get(salt)
        val iterationCount = buffer.int
        val keyLength = buffer.int

        // Get back the aes key from the same password and salt
        val aesKeyFromPassword = getAESKeyFromPassword(
            password.toCharArray(),
            salt,
            iterationCount,
            keyLength
        )

        val iv = ByteArray(buffer.int)
        buffer.get(iv)

        val tagLengthBits = buffer.int

        val cipherText = ByteArray(buffer.remaining())
        buffer.get(cipherText)

        // Create the cipher for the algorithm
        val cipher: Cipher = Cipher.getInstance(algorithmString)
        cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, GCMParameterSpec(tagLengthBits, iv))

        return try {
            Result.Success(cipher.doFinal(cipherText).toString(UTF_8))
        } catch (exception: Exception) {
            when (exception) {
                is AEADBadTagException -> Result.Failure(WrongPassword)
                else -> Result.Failure(Other(exception))
            }
        }
    }

    // AES secret key derived from a password
    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    private fun getAESKeyFromPassword(
        password: CharArray,
        salt: ByteArray,
        iterationCount: Int,
        keyLength: Int
    ): SecretKey {
        val factory: SecretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password, salt, iterationCount, keyLength)
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }
}

/**
 * Result from [PasswordCipher.decrypt]. Can be one of the following:
 * - [Success]: when the decryption succeeds. Includes the [Success.result].
 * - [Failed]: when the decryption fails. Includes the [Failed.error].
 */
sealed class DecryptionResult {
    data class Success(val result: String) : DecryptionResult()
    data class Failed(val error: DecryptionError) : DecryptionResult()
}

sealed class EncryptionError {
    data class InvalidArgument(val argumentName: String, val value: String, val requirement: String) : EncryptionError()
    data class AlgorithmNotSupported(val algorithm: EncryptionAlgorithm) : EncryptionError()
    data class KeyGenerationAlgorithmNotSupported(val algorithm: PasswordKeyGenerator.Algorithm) : EncryptionError()
}

/**
 * Why a decryption failed. Can be one of the following:
 * - [BadFormat]: If the input had an unexpected format.
 * - [WrongPassword]: the provided password was wrong.
 * - [Other]: some other reason. Includes the [Other.exception].
 */
sealed class DecryptionError {
    object BadFormat : DecryptionError()
    object WrongPassword : DecryptionError()
    data class Other(val exception: Exception) : DecryptionError()
}
