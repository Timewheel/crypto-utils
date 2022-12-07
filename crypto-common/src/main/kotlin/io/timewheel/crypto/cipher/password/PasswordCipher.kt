package io.timewheel.crypto.cipher.password

import io.timewheel.crypto.cipher.Algorithm
import io.timewheel.crypto.cipher.KeyCipher
import io.timewheel.util.ByteArrayWrapper
import io.timewheel.util.Result

/**
 * Provides password based encryption and decryption.
 */
interface PasswordCipher {
    /**
     * Encrypts the [input] using the [password] with the provided [options]. The [Options] object
     * should contain an [Algorithm] as well as the [Algorithm.EncryptionInputs] associated to the
     * algorithm.
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
        password: String,
        options: Options<AlgorithmType, InputType>
    ): Result<EncryptionResultData<OutputType>, EncryptionError>

    /**
     * Decrypts the [ciphertext] using the [password] with the provided [options]. The [Options]
     * object should contain an instance of the [Algorithm] used to encrypt the ciphertext as well
     * as an instance of the [Algorithm.DecryptionInputs] containing the parameters that were used
     * to produce the ciphertext. If you used the [encrypt] method to produce the ciphertext, the
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
        password: String,
        options: Options<AlgorithmType, InputType>
    ): Result<ByteArrayWrapper, DecryptionError>

    /**
     * Encryption or decryption options. Include the [Algorithm] to be used and the [input] to
     * be used; [Algorithm.EncryptionInputs] for encryption or [Algorithm.DecryptionInputs] for
     * decryption.
     */
    data class Options<AlgorithmType, InputType>(
        val algorithm: AlgorithmType,
        val input: InputType,
        val passwordKeyGeneratorOptions: PasswordKeyGenerator.Options
    ) {
        internal fun toKeyCipherOptions() = KeyCipher.Options(algorithm, input)
    }

    data class EncryptionResultData<OutputType>(
        val ciphertext: ByteArrayWrapper,
        val algorithmData: OutputType,
        val passwordData: PasswordKeyGenerator.ResultData
    )

    sealed class EncryptionError {
        /**
         * The algorithm is not supported by the platform. Contains the [algorithm].
         */
        data class AlgorithmNotSupported(val algorithm: Algorithm<*, *>) : EncryptionError()

        /**
         * An error occurred while generating a key from the provided password. See [error].
         */
        data class KeyGenerationError(val error: PasswordKeyGenerator.Error) : EncryptionError()
    }

    sealed class DecryptionError {
        /**
         * The algorithm is not supported by the platform. Contains the [algorithm].
         */
        data class AlgorithmNotSupported(val algorithm: Algorithm<*, *>) : DecryptionError()

        /**
         * An error occurred while generating a key from the provided password. See [error].
         */
        data class KeyGenerationError(val error: PasswordKeyGenerator.Error) : DecryptionError()

        /**
         * The provided password didn't decrypt the ciphertext.
         */
        object WrongPassword : DecryptionError()

        /**
         * Some other error occurred. The [exception] is provided.
         */
        data class Other(val exception: Exception) : DecryptionError()
    }

    companion object {
        fun create() : PasswordCipher {
            return PasswordCipherImpl(PasswordKeyGenerator.create(), KeyCipher.create())
        }
    }
}

internal class PasswordCipherImpl(
    private val passwordKeyGenerator: PasswordKeyGenerator,
    private val keyCipher: KeyCipher
) : PasswordCipher {
    override fun <
        AlgorithmType : Algorithm<InputType, OutputType>,
        InputType : Algorithm.EncryptionInputs<OutputType>,
        OutputType : Algorithm.DecryptionInputs
    > encrypt(
        input: ByteArray,
        password: String,
        options: PasswordCipher.Options<AlgorithmType, InputType>
    ): Result<PasswordCipher.EncryptionResultData<OutputType>, PasswordCipher.EncryptionError> {
        return passwordKeyGenerator.generateKey(password, options.passwordKeyGeneratorOptions)
            .mapFailure { keyGenError -> keyGenError.toEncryptionError() }
            .flatMap { pkgResultData ->
                keyCipher.encrypt(input, pkgResultData.key.data, options.toKeyCipherOptions())
                    .map({ encryptionResultData ->
                        PasswordCipher.EncryptionResultData(
                            encryptionResultData.ciphertext,
                            encryptionResultData.algorithmData,
                            pkgResultData
                        )
                    }) { keyCipherError -> keyCipherError.toEncryptionError() }
            }
    }

    override fun <
        AlgorithmType : Algorithm<*, InputType>,
        InputType : Algorithm.DecryptionInputs
    > decrypt(
        ciphertext: ByteArray,
        password: String,
        options: PasswordCipher.Options<AlgorithmType, InputType>
    ): Result<ByteArrayWrapper, PasswordCipher.DecryptionError> {
        return passwordKeyGenerator.generateKey(password, options.passwordKeyGeneratorOptions)
            .mapFailure { keyGenError -> keyGenError.toDecryptionError() }
            .flatMap { pkgResultData ->
                keyCipher.decrypt(ciphertext, pkgResultData.key.data, options.toKeyCipherOptions())
                    .mapFailure { keyCipherError -> keyCipherError.toDecryptionError() }
            }
    }
}

// region Model Mappings

private fun PasswordKeyGenerator.Error.toEncryptionError(): PasswordCipher.EncryptionError {
    return PasswordCipher.EncryptionError.KeyGenerationError(this)
}

private fun PasswordKeyGenerator.Error.toDecryptionError(): PasswordCipher.DecryptionError {
    return PasswordCipher.DecryptionError.KeyGenerationError(this)
}

private fun KeyCipher.EncryptionError.toEncryptionError() = when (this) {
    is KeyCipher.EncryptionError.AlgorithmNotSupported -> {
        PasswordCipher.EncryptionError.AlgorithmNotSupported(algorithm)
    }
    is KeyCipher.EncryptionError.InvalidKey -> {
        throw IllegalStateException("Keys generated by the password cipher should be correct")
    }
}

private fun KeyCipher.DecryptionError.toDecryptionError() = when (this) {
    is KeyCipher.DecryptionError.AlgorithmNotSupported -> {
        PasswordCipher.DecryptionError.AlgorithmNotSupported(algorithm)
    }
    is KeyCipher.DecryptionError.WrongKey -> {
        PasswordCipher.DecryptionError.WrongPassword
    }
    is KeyCipher.DecryptionError.InvalidKey -> {
        throw IllegalStateException("Keys generated by the password cipher should be correct")
    }
    is KeyCipher.DecryptionError.Other -> {
        PasswordCipher.DecryptionError.Other(exception)
    }
}

// endregion Model Mappings
