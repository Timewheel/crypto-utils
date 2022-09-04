package io.timewheel.crypto

import java.nio.ByteBuffer
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.spec.InvalidKeySpecException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.Exception
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
 *
 * The lengths of the salt, key, and IV as well as the iteration count are encoded into the
 * results should the lengths need changed at some point in the future.
 */
// @AnyThread // Stateless
interface AesGcmCipher {
    /**
     * Encrypts a single [input] string using a [password].
     */
    fun encrypt(input: String, password: String): String

    /**
     * Encrypts a list of [input] strings with a [password].
     */
    fun encrypt(input: List<String>, password: String): List<String>

    /**
     * Decrypts an [input] string that was produced with the [encrypt] method using a [password].
     * Returns a [DecryptionResult].
     */
    fun decrypt(input: String, password: String): DecryptionResult

    /**
     * Supported AES algorithms.
     */
    enum class Algorithm(internal val algorithmString: String) {
        /**
         * Galois Counting Mode with no padding.
         */
        GcmNoPadding("AES/GCM/NoPadding");

        companion object {
            internal fun fromString(algorithmString: String): Algorithm? {
                for (algorithm in values()) {
                    if (algorithm.algorithmString == algorithmString) {
                        return algorithm
                    }
                }
                return null
            }
        }
    }

    /**
     * Builds instances of [AesGcmCipher].
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

        fun build(): AesGcmCipher = AesGcmCipherImpl(
            base64Coder,
            Algorithm.GcmNoPadding,
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

    companion object {
        fun build(base64Coder: Base64Coder, block: (Builder.() -> Unit)): AesGcmCipher {
            // NOTE: AesGcmCipherBuilderImpl is defined by sourcing modules to provide a
            // platform specific implementation of Base64Coder.
            val builder = Builder(base64Coder)
            block(builder)
            return builder.build()
        }
    }
}

// @AnyThread // Stateless
// @VisibleForTesting
internal class AesGcmCipherImpl constructor(
    private val coder: Base64Coder,
    private val algorithm: AesGcmCipher.Algorithm,
    private val saltLengthBytes: Int,
    private val ivLengthBytes: Int,
    private val iterationCount: Int,
    private val keyLengthBits: Int,
    private val tagLengthBits: Int
): AesGcmCipher {
    override fun encrypt(input: String, password: String): String {
        return encrypt(listOf(input), password).first()
    }

    override fun encrypt(input: List<String>, password: String): List<String> {
        val cipher: Cipher = Cipher.getInstance(algorithm.algorithmString)

        return mutableListOf<String>().apply {
            input.forEach {
                // Salt and initialization vector
                val salt = getRandomNonce(saltLengthBytes)
                val iv = getRandomNonce(ivLengthBytes)

                // Secret key from password
                val aesKeyFromPassword = getAESKeyFromPassword(
                    password.toCharArray(),
                    salt,
                    iterationCount,
                    keyLengthBits
                )

                // AES-GCM needs GCMParameterSpec
                cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, GCMParameterSpec(tagLengthBits, iv))

                // Encrypt the input
                val cipherText = cipher.doFinal(it.toByteArray(UTF_8))

                val algorithmBytes = algorithm.algorithmString.toByteArray(UTF_8)

                // Calculate the buffer size
                val bufferSize =
                    // Version length
                    Int.SIZE_BYTES +
                    // Algorithm string length and the string as bytes
                    Int.SIZE_BYTES +
                    algorithmBytes.size +
                    // Salt length and salt
                    Int.SIZE_BYTES +
                    salt.size +
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
                    .put(salt)
                    .putInt(iterationCount)
                    .putInt(keyLengthBits)
                    .putInt(ivLengthBytes)
                    .put(iv)
                    .putInt(tagLengthBits)
                    .put(cipherText)
                    .array()

                // Add the result to the output
                add(coder.encode(result))
            }
        }.toList()
    }

    override fun decrypt(input: String, password: String): DecryptionResult {
        // Decode the base 64 input
        val buffer = ByteBuffer.wrap(coder.decode(input))

        // Decode version
        return when (buffer.int) {
            V1 -> decryptV1(buffer, password)
            else -> DecryptionResult.Failed(DecryptionError.BadFormat)
        }
    }

    private fun decryptV1(buffer: ByteBuffer, password: String): DecryptionResult {
        // Decode Algorithm
        val algorithmBytes = ByteArray(buffer.int)
        buffer.get(algorithmBytes)
        val algorithm = AesGcmCipher.Algorithm.fromString(algorithmBytes.toString(UTF_8))
            ?: return DecryptionResult.Failed(DecryptionError.BadFormat)

        // Create the cipher for the algorithm
        val cipher: Cipher = Cipher.getInstance(algorithm.algorithmString)

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
        cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, GCMParameterSpec(tagLengthBits, iv))

        val cipherText = ByteArray(buffer.remaining())
        buffer.get(cipherText)

        return try {
            DecryptionResult.Success(cipher.doFinal(cipherText).toString(UTF_8))
        } catch (exception: Exception) {
            when (exception) {
                is AEADBadTagException -> DecryptionResult.Failed(DecryptionError.WrongPassword)
                else -> DecryptionResult.Failed(DecryptionError.Other(exception))
            }
        }
    }

    /**
     * Creates a random nonce of the specified byte length.
     */
    //@VisibleForTesting // I have some tests that check the behavior of encoding and decoding
    internal fun getRandomNonce(numBytes: Int) = ByteArray(numBytes).apply {
        SecureRandom().nextBytes(this)
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
 * Result from [AesGcmCipher.decrypt]. Can be one of the following:
 * - [Success]: when the decryption succeeds. Includes the [Success.result].
 * - [Failed]: when the decryption fails. Includes the [Failed.error].
 */
sealed class DecryptionResult {
    data class Success(val result: String) : DecryptionResult()
    data class Failed(val error: DecryptionError) : DecryptionResult()
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
