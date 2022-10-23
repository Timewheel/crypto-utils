package io.timewheel.crypto.cipher

import io.timewheel.util.Result
import java.security.NoSuchAlgorithmException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException

/**
 * Encrypts and decrypts byte arrays with keys.
 */
interface KeyCipher {
    /**
     * Encrypts the [input] using the [key] with the provided [options]. The [Options] object should
     * contain an [Algorithm] as well as the [Algorithm.EncryptionInputs] associated to the algorithm.
     *
     * If the operation succeeds, it returns a [Result.Success] containing an [EncryptionResultData],
     * which has the [EncryptionResultData.ciphertext] and the [Algorithm.DecryptionInputs] that you
     * can use to decrypt the ciphertext.
     *
     * If the operation fails, it returns a [Result.Failure] containing an [EncryptionError].
     */
    fun <
        AlgorithmType : Algorithm<InputType, OutputType>,
        InputType : Algorithm.EncryptionInputs<OutputType>,
        OutputType : Algorithm.DecryptionInputs
    > encrypt(
        input: ByteArray,
        key: ByteArray,
        options: Options<AlgorithmType, InputType>
    ): Result<EncryptionResultData<OutputType>, EncryptionError>

    /**
     * Decrypts the [ciphertext] using the [key] with the provided [options]. The [Options] object
     * should contain an instance of the [Algorithm] used to encrypt the ciphertext as well as an
     * instance of the [Algorithm.DecryptionInputs] containing the parameters that were used to
     * produce the ciphertext. If you used the [encrypt] method to produce the ciphertext, the
     * [EncryptionResultData] would have had the necessary inputs.
     *
     * If the operation succeeds, it returns a [Result.Success] containing the original text.
     *
     * If the operation fails, it returns a [Result.Failure] containing a [DecryptionError].
     */
    fun <
        AlgorithmType : Algorithm<*, InputType>,
        InputType : Algorithm.DecryptionInputs
    > decrypt(
        ciphertext: ByteArray,
        key: ByteArray,
        options: Options<AlgorithmType, InputType>
    ): Result<ByteArray, DecryptionError>

    /**
     * Encryption or decryption options. Include the [Algorithm] to be used and the [input] to
     * be used; [Algorithm.EncryptionInputs] for encryption or [Algorithm.DecryptionInputs] for
     * decryption.
     */
    data class Options<AlgorithmType, InputType>(
        val algorithm: AlgorithmType,
        val input: InputType
    )

    /**
     * Result of [encrypt]. Contains the [ciphertext] and the output type of the algorithm, which
     * will always be an [Algorithm.DecryptionInputs].
     */
    data class EncryptionResultData<OutputType>(
        val ciphertext: ByteArray,
        val algorithmData: OutputType
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as EncryptionResultData<*>

            if (!ciphertext.contentEquals(other.ciphertext)) return false
            if (algorithmData != other.algorithmData) return false

            return true
        }

        override fun hashCode(): Int {
            var result = ciphertext.contentHashCode()
            result = 31 * result + (algorithmData?.hashCode() ?: 0)
            return result
        }
    }

    /**
     * Error result of [encrypt]. Can be one of the following:
     * - [AlgorithmNotSupported]
     * - [InvalidKey]
     */
    sealed class EncryptionError {
        /**
         * The algorithm is not supported by the platform. Contains the [algorithm].
         */
        data class AlgorithmNotSupported<
            InputType : Algorithm.EncryptionInputs<OutputType>,
            OutputType : Algorithm.DecryptionInputs
        > (
            val algorithm: Algorithm<InputType, OutputType>
        ) : EncryptionError()

        /**
         * The provided key is invalid because the length of the key didn't match the algorithm spec.
         */
        object InvalidKey : EncryptionError()
    }

    /**
     * Error result of [decrypt]. Can be one of the following:
     * - [AlgorithmNotSupported]
     * - [InvalidKey]
     * - [WrongKey]
     * - [Other]
     */
    sealed class DecryptionError {
        /**
         * The algorithm is not supported by the platform. Contains the [algorithm].
         */
        data class AlgorithmNotSupported<
            InputType : Algorithm.EncryptionInputs<OutputType>,
            OutputType : Algorithm.DecryptionInputs
        > (
            val algorithm: Algorithm<InputType, OutputType>
        ) : DecryptionError()

        /**
         * The provided key is invalid because the length of the key didn't match the algorithm spec.
         */
        object InvalidKey : DecryptionError()

        /**
         * The provided key was not the key used to encrypt the ciphertext.
         */
        object WrongKey : DecryptionError()

        /**
         * An unidentified error occurred. Contains the [exception].
         */
        data class Other(val exception: Exception) : DecryptionError()
    }

    companion object {
        /**
         * Creates a KeyCipher.
         */
        fun create(): KeyCipher = KeyCipherImpl(CipherProviderImpl())
    }
}

internal class KeyCipherImpl(private val cipherProvider: CipherProvider) : KeyCipher {
    override fun <
        AlgorithmType: Algorithm<InputType, OutputType>,
        InputType : Algorithm.EncryptionInputs<OutputType>,
        OutputType : Algorithm.DecryptionInputs
    > encrypt(
        input: ByteArray,
        key: ByteArray,
        options: KeyCipher.Options<AlgorithmType, InputType>
    ): Result<KeyCipher.EncryptionResultData<OutputType>, KeyCipher.EncryptionError> {

        // Get the key spec
        return options.algorithm.getKeySpec(key)
            // Map the failure to an EncryptionError
            .mapFailure<KeyCipher.EncryptionError> { keyError ->
                when (keyError) {
                    is Algorithm.KeyError.InvalidKey -> KeyCipher.EncryptionError.InvalidKey
                }
            }
            // Combine with the cipher for the algorithm
            .combineWith(
                cipherProvider.provideCipher(options.algorithm)
                    // Mapping the error to an EncryptionError
                    .mapFailure { cipherError ->
                        when (cipherError) {
                            is CipherProvider.Error.AlgorithmNotSupported -> {
                                KeyCipher.EncryptionError.AlgorithmNotSupported(cipherError.algorithm)
                            }
                        }
                    }
            ) { keySpec, cipher ->
                // Create the spec and the decryption inputs
                val specOutputPair = options.algorithm.getDecryptionInputs(options.input)
                // Init the cipher
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, specOutputPair.first)
                // Encrypt the input
                val cipherText = cipher.doFinal(input)
                // Encapsulate the result
                KeyCipher.EncryptionResultData(cipherText, specOutputPair.second)
            }
    }

    override fun <
        AlgorithmType : Algorithm<*, InputType>,
        InputType : Algorithm.DecryptionInputs
    > decrypt(
        ciphertext: ByteArray,
        key: ByteArray,
        options: KeyCipher.Options<AlgorithmType, InputType>
    ): Result<ByteArray, KeyCipher.DecryptionError> {

        // Get the key spec
        return options.algorithm.getKeySpec(key)
            // Map the failure to an EncryptionError
            .mapFailure<KeyCipher.DecryptionError> { keyError ->
                when (keyError) {
                    is Algorithm.KeyError.InvalidKey -> KeyCipher.DecryptionError.InvalidKey
                }
            }
            // Combine with the cipher for the algorithm
            .combineWith(
                cipherProvider.provideCipher(options.algorithm)
                    // Mapping the error to an EncryptionError
                    .mapFailure { cipherError ->
                        when (cipherError) {
                            is CipherProvider.Error.AlgorithmNotSupported -> {
                                KeyCipher.DecryptionError.AlgorithmNotSupported(cipherError.algorithm)
                            }
                        }
                    }
            ) { keySpec, cipher ->
                // Return the cipher
                cipher.also {
                    // But initialize it first
                    cipher.init(
                        Cipher.DECRYPT_MODE,
                        keySpec,
                        options.algorithm.getParameterSpec(options.input)
                    )
                }
            }.map { result ->
                return when (result) {
                    // If the result is a Failure, return it
                    is Result.Failure -> Result.Failure(result.error)
                    is Result.Success -> try {
                        // Otherwise return the decryption result
                        Result.Success(result.result.doFinal(ciphertext))
                    } catch (exception: Exception) {
                        // Unless we hit a snag
                        return Result.Failure(when (exception) {
                            is AEADBadTagException -> KeyCipher.DecryptionError.WrongKey
                            else -> KeyCipher.DecryptionError.Other(exception)
                        })
                    }
                }
            }
    }
}

/**
 * Provides non static access to [Cipher] for testability.
 */
internal interface CipherProvider {
    fun provideCipher(algorithm: Algorithm<*, *>): Result<Cipher, Error>

    sealed class Error {
        data class AlgorithmNotSupported(val algorithm: Algorithm<*, *>) : Error()
    }
}

internal class CipherProviderImpl : CipherProvider {
    override fun provideCipher(algorithm: Algorithm<*, *>): Result<Cipher, CipherProvider.Error> {
        return try {
            Result.Success(Cipher.getInstance(algorithm.transformation()))
        } catch (x: NoSuchAlgorithmException) {
            Result.Failure(CipherProvider.Error.AlgorithmNotSupported(algorithm))
        } catch (x: NoSuchPaddingException) {
            Result.Failure(CipherProvider.Error.AlgorithmNotSupported(algorithm))
        }
    }
}
