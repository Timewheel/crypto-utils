package io.timewheel.crypto.cipher

import io.timewheel.crypto.encoding.Encodable
import io.timewheel.crypto.encoding.EncodableType
import io.timewheel.crypto.encoding.ResultEncoder
import io.timewheel.crypto.encoding.encodableType
import io.timewheel.crypto.toPairArray
import io.timewheel.util.ByteArrayWrapper
import io.timewheel.util.Result
import io.timewheel.util.wrap
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
    ): Result<ByteArrayWrapper, DecryptionError>

    /**
     * Decrypts the [input] encoded string using the provided [options].
     *
     * If the operation succeeds, it returns a [Result.Success] containing the original text.
     *
     * If the operation fails, it returns a [Result.Failure] containing a [DecryptionError].
     */
    fun <
        AlgorithmType : Algorithm<*, InputType>,
        InputType : Algorithm.DecryptionInputs
    > decrypt(
        input: String,
        key: ByteArray,
        options: DecodingOptions<AlgorithmType, InputType>
    ): Result<ByteArrayWrapper, DecryptionError>

    /**
     * Encryption or decryption options. Include the [Algorithm] to be used and the [input] to
     * be used; [Algorithm.EncryptionInputs] for encryption or [Algorithm.DecryptionInputs] for
     * decryption.
     */
    data class Options<AlgorithmType, InputType>(
        val algorithm: AlgorithmType,
        val input: InputType
    ) {
        companion object {
            /**
             * Creates an options object from the provided encoding.
             */
            @JvmStatic
            internal fun <
                AlgorithmType : Algorithm<*, InputType>,
                InputType : Algorithm.DecryptionInputs
            > fromEncodingMapping(
                algorithm: AlgorithmType,
                mapping: Map<String, EncodableType>
            ): Options<AlgorithmType, InputType> {
                return Options(
                    algorithm,
                    algorithm.getDecryptionInputs(mapping)
                )
            }
        }
    }

    /**
     * Options for decrypting using an encoded output. Must provide the following:
     *
     * - [algorithm]: the algorithm used to encrypt the input.
     */
    data class DecodingOptions<
        AlgorithmType : Algorithm<*, InputType>,
        InputType : Algorithm.DecryptionInputs
    >(
        val algorithm: AlgorithmType
    )

    /**
     * Result of [encrypt]. Contains the [ciphertext] and the output type of the algorithm, which
     * will always be an [Algorithm.DecryptionInputs].
     */
    data class EncryptionResultData<OutputType : Algorithm.DecryptionInputs>(
        val ciphertext: ByteArrayWrapper,
        val algorithmData: OutputType
    ) : Encodable {

        private lateinit var resultEncoder: ResultEncoder

        internal fun setEncoder(resultEncoder: ResultEncoder) {
            this.resultEncoder = resultEncoder
        }

        fun encode() = encode("tl%iv%s%i%c")

        fun encode(format: String): String {
            return (resultEncoder.encode(format, this) as Result.Success).result
        }

        override fun getEncodingMapping() = mapOf(
            *algorithmData.getEncodingMapping().toPairArray(),
            "c" to ciphertext.data.encodableType()
        )
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
        data class AlgorithmNotSupported(val algorithm: Algorithm<*, *>) : EncryptionError()

        /**
         * The provided key is invalid because the length of the key didn't match the algorithm spec.
         */
        object InvalidKey : EncryptionError()
    }

    /**
     * Error result of [decrypt]. Can be one of the following:
     * - [BadFormat]
     * - [AlgorithmNotSupported]
     * - [InvalidKey]
     * - [WrongKey]
     * - [Other]
     */
    sealed class DecryptionError {
        /**
         * When the input encoded string has a bad format.
         */
        object BadFormat : DecryptionError()

        /**
         * The algorithm is not supported by the platform. Contains the [algorithm].
         */
        data class AlgorithmNotSupported(val algorithm: Algorithm<*, *>) : DecryptionError()

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
        fun create(): KeyCipher = KeyCipherImpl(CipherProviderImpl(), ResultEncoder.create())
    }
}

internal class KeyCipherImpl(
    private val cipherProvider: CipherProvider,
    private val resultEncoder: ResultEncoder,
) : KeyCipher {
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
            .mapFailure { keyError -> keyError.toEncryptionError() }
            // Combine with the cipher for the algorithm
            .combineWith(
                cipherProvider.provideCipher(options.algorithm)
                    // Mapping the error to an EncryptionError
                    .mapFailure { cipherError -> cipherError.toEncryptionError() }
            ) { keySpec, cipher ->
                // Create the spec and the decryption inputs
                val specOutputPair = options.algorithm.getDecryptionInputs(options.input)
                // Init the cipher
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, specOutputPair.first)
                // Encrypt the input
                val cipherText = cipher.doFinal(input)
                // Encapsulate the result
                KeyCipher.EncryptionResultData(cipherText.wrap(), specOutputPair.second)
            }
    }

    override fun <
        AlgorithmType : Algorithm<*, InputType>,
        InputType : Algorithm.DecryptionInputs
    > decrypt(
        ciphertext: ByteArray,
        key: ByteArray,
        options: KeyCipher.Options<AlgorithmType, InputType>
    ): Result<ByteArrayWrapper, KeyCipher.DecryptionError> {

        // Get the key spec
        return options.algorithm.getKeySpec(key)
            // Map the failure to an EncryptionError
            .mapFailure { keyError -> keyError.toDecryptionError() }
            // Combine with the cipher for the algorithm
            .combineWith(
                cipherProvider.provideCipher(options.algorithm)
                    // Mapping the error to an DecryptionError
                    .mapFailure { cipherError -> cipherError.toDecryptionError() }
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
                        Result.Success(result.result.doFinal(ciphertext).wrap())
                    } catch (exception: Exception) {
                        // Unless we hit a snag
                        return Result.Failure(exception.toDecryptionError())
                    }
                }
            }
    }

    override fun <
        AlgorithmType : Algorithm<*, InputType>,
        InputType : Algorithm.DecryptionInputs
    > decrypt(
        input: String,
        key: ByteArray,
        options: KeyCipher.DecodingOptions<AlgorithmType, InputType>
    ): Result<ByteArrayWrapper, KeyCipher.DecryptionError> {
        return when (val mappingResult = resultEncoder.decode(input)) {
            is Result.Failure -> Result.Failure(KeyCipher.DecryptionError.BadFormat)
            is Result.Success -> {
                val mapping = mappingResult.result
                val ciphertext = mapping["c"]?.byteArrayOrNull() ?: return Result.Failure(KeyCipher.DecryptionError.BadFormat)
                val fullOptions = KeyCipher.Options.fromEncodingMapping(
                    options.algorithm,
                    mapping
                )
                return decrypt(ciphertext.value.data, key, fullOptions)
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

// region Model Mappings

private fun Algorithm.KeyError.toEncryptionError(): KeyCipher.EncryptionError = when (this) {
    is Algorithm.KeyError.InvalidKey -> KeyCipher.EncryptionError.InvalidKey
}

private fun Algorithm.KeyError.toDecryptionError(): KeyCipher.DecryptionError = when (this) {
    is Algorithm.KeyError.InvalidKey -> KeyCipher.DecryptionError.InvalidKey
}

private fun CipherProvider.Error.toEncryptionError() = when (this) {
    is CipherProvider.Error.AlgorithmNotSupported -> {
        KeyCipher.EncryptionError.AlgorithmNotSupported(algorithm)
    }
}

private fun CipherProvider.Error.toDecryptionError() = when (this) {
    is CipherProvider.Error.AlgorithmNotSupported -> {
        KeyCipher.DecryptionError.AlgorithmNotSupported(algorithm)
    }
}

private fun Exception.toDecryptionError() = when (this) {
    is AEADBadTagException -> KeyCipher.DecryptionError.WrongKey
    else -> KeyCipher.DecryptionError.Other(this)
}

// endregion Model Mappings
