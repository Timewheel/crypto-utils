package io.timewheel.crypto.cipher.password

import io.timewheel.crypto.cipher.AES
import io.timewheel.crypto.cipher.KeyCipher
import io.timewheel.crypto.getRandomNonce
import io.timewheel.util.ByteArrayWrapper
import io.timewheel.util.Result
import io.timewheel.util.Result.Success
import io.timewheel.util.Result.Failure
import io.timewheel.util.wrap
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.mockito.kotlin.*

class PasswordCipherImplTest {
    private lateinit var mockPasswordKeyGenerator: PasswordKeyGenerator
    private lateinit var mockKeyCipher: KeyCipher

    private lateinit var subject: PasswordCipherImpl

    @BeforeEach
    fun setUp() {
        mockPasswordKeyGenerator = mock()
        mockKeyCipher = mock()

        subject = PasswordCipherImpl(mockPasswordKeyGenerator, mockKeyCipher)
    }

    // region Encrypt

    @Test
    fun encrypt_shouldGenerateKeyFromPassword() {
        // Given - PKG fails to short circuit the rest of the method
        whenever(mockPasswordKeyGenerator.generateKey(any(), any())) doReturn Failure(
            PasswordKeyGenerator.Error.AlgorithmNotSupported(mock())
        )

        // When
        subject.encrypt(getRandomNonce(8), "abc", encryptionOptions())

        // Then
        verify(mockPasswordKeyGenerator).generateKey(any(), any())
    }

    @Test
    fun encrypt_shouldEncryptWithKeyCipher() {
        // Given
        whenever(mockPasswordKeyGenerator.generateKey(any(), any())) doReturn Success(
            PasswordKeyGenerator.ResultData(ByteArray(0).wrap(), ByteArray(0).wrap())
        )
        whenever(mockKeyCipher.encrypt(
            any(),
            any(),
            any<KeyCipher.Options<AES.GcmNoPadding, AES.GcmNoPadding.EncryptionInputs>>())
        ) doReturn Failure(
            KeyCipher.EncryptionError.AlgorithmNotSupported(AES.GcmNoPadding(AES.KeyLength.L256))
        )

        // When
        subject.encrypt(getRandomNonce(8), "abc", encryptionOptions())

        // Then
        verify(mockKeyCipher).encrypt(any(), any(), any<KeyCipher.Options<AES.GcmNoPadding, AES.GcmNoPadding.EncryptionInputs>>())
    }

    @Test
    fun encrypt_shouldThrowWhenKeyCipherReportsInvalidKey() {
        // Given
        whenever(mockPasswordKeyGenerator.generateKey(any(), any())) doReturn Success(
            PasswordKeyGenerator.ResultData(ByteArray(0).wrap(), ByteArray(0).wrap())
        )
        whenever(mockKeyCipher.encrypt(
            any(),
            any(),
            any<KeyCipher.Options<AES.GcmNoPadding, AES.GcmNoPadding.EncryptionInputs>>()
        )) doReturn Failure(KeyCipher.EncryptionError.InvalidKey)

        // Then
        assertThrows<IllegalStateException> {
            // When
            subject.encrypt(getRandomNonce(8), "abc", encryptionOptions())
        }
    }

    @ParameterizedTest
    @MethodSource("encryptionTestInput")
    fun encrypt_shouldProduceCorrectOutputs(data: PasswordCipherEncryptionData) {
        // Given
        whenever(mockPasswordKeyGenerator.generateKey(any(), any())) doReturn data.passwordKeyGeneratorResult
        whenever(mockKeyCipher.encrypt(
            any(),
            any(),
            any<KeyCipher.Options<AES.GcmNoPadding, AES.GcmNoPadding.EncryptionInputs>>())
        ) doReturn data.keyCipherResult

        // When
        val result = subject.encrypt(getRandomNonce(8), "abc", encryptionOptions())

        // Then
        assertEquals(data.expectedResult, result)
    }

    @ParameterizedTest
    @MethodSource("encryptionTestInput")
    fun encrypt_whenPasswordKeyGeneratorFails_shouldNotInteractWithKeyCipher(data: PasswordCipherEncryptionData) {
        // Given
        whenever(mockPasswordKeyGenerator.generateKey(any(), any())) doReturn data.passwordKeyGeneratorResult
        whenever(mockKeyCipher.encrypt(
            any(),
            any(),
            any<KeyCipher.Options<AES.GcmNoPadding, AES.GcmNoPadding.EncryptionInputs>>())
        ) doReturn data.keyCipherResult

        // When
        subject.encrypt(getRandomNonce(8), "abc", encryptionOptions())

        if (data.passwordKeyGeneratorResult is Failure) {
            verifyNoInteractions(mockKeyCipher)
        } else {
            verify(mockKeyCipher).encrypt(
                any(),
                any(),
                any<KeyCipher.Options<AES.GcmNoPadding, AES.GcmNoPadding.EncryptionInputs>>()
            )
        }
    }

    private fun encryptionOptions() = PasswordCipher.Options(
        AES.GcmNoPadding(AES.KeyLength.L256),
        AES.GcmNoPadding.EncryptionInputs(),
        PasswordKeyGenerator.Options(
            mock(),
            PasswordKeyGenerator.Algorithm.PBKDF2WithHmacSHA256,
            0,
            0
        )
    )

    // endregion Encrypt

    // region Decrypt

    @Test
    fun decrypt_shouldGenerateKeyFromPassword() {
        // Given - PKG fails to short circuit the rest of the method
        whenever(mockPasswordKeyGenerator.generateKey(any(), any())) doReturn Failure(
            PasswordKeyGenerator.Error.AlgorithmNotSupported(mock())
        )

        // When
        subject.decrypt(getRandomNonce(8), "abc", decryptionOptions())

        // Then
        verify(mockPasswordKeyGenerator).generateKey(any(), any())
    }

    @Test
    fun decrypt_shouldEncryptWithKeyCipher() {
        // Given
        whenever(mockPasswordKeyGenerator.generateKey(any(), any())) doReturn Success(
            PasswordKeyGenerator.ResultData(ByteArray(0).wrap(), ByteArray(0).wrap())
        )
        whenever(mockKeyCipher.decrypt(
            any(),
            any(),
            any<KeyCipher.Options<AES.GcmNoPadding, AES.GcmNoPadding.DecryptionInputs>>())
        ) doReturn Failure(
            KeyCipher.DecryptionError.AlgorithmNotSupported(AES.GcmNoPadding(AES.KeyLength.L256))
        )

        // When
        subject.decrypt(getRandomNonce(8), "abc", decryptionOptions())

        // Then
        verify(mockKeyCipher).decrypt(any(), any(), any<KeyCipher.Options<AES.GcmNoPadding, AES.GcmNoPadding.DecryptionInputs>>())
    }

    @Test
    fun decrypt_shouldThrowWhenKeyCipherReportsInvalidKey() {
        // Given
        whenever(mockPasswordKeyGenerator.generateKey(any(), any())) doReturn Success(
            PasswordKeyGenerator.ResultData(ByteArray(0).wrap(), ByteArray(0).wrap())
        )
        whenever(mockKeyCipher.decrypt(
            any(),
            any(),
            any<KeyCipher.Options<AES.GcmNoPadding, AES.GcmNoPadding.DecryptionInputs>>()
        )) doReturn Failure(KeyCipher.DecryptionError.InvalidKey)

        // Then
        assertThrows<IllegalStateException> {
            // When
            subject.decrypt(getRandomNonce(8), "abc", decryptionOptions())
        }
    }

    @ParameterizedTest
    @MethodSource("decryptionTestInput")
    fun decrypt_shouldProduceCorrectOutputs(data: PasswordCipherDecryptionData) {
        // Given
        whenever(mockPasswordKeyGenerator.generateKey(any(), any())) doReturn data.passwordKeyGeneratorResult
        whenever(mockKeyCipher.decrypt(
            any(),
            any(),
            any<KeyCipher.Options<AES.GcmNoPadding, AES.GcmNoPadding.DecryptionInputs>>())
        ) doReturn data.keyCipherResult

        // When
        val result = subject.decrypt(getRandomNonce(8), "abc", decryptionOptions())

        // Then
        assertEquals(data.expectedResult, result)
    }

    @ParameterizedTest
    @MethodSource("decryptionTestInput")
    fun decrypt_whenPasswordKeyGeneratorFails_shouldNotInteractWithKeyCipher(data: PasswordCipherDecryptionData) {
        // Given
        whenever(mockPasswordKeyGenerator.generateKey(any(), any())) doReturn data.passwordKeyGeneratorResult
        whenever(mockKeyCipher.decrypt(
            any(),
            any(),
            any<KeyCipher.Options<AES.GcmNoPadding, AES.GcmNoPadding.DecryptionInputs>>())
        ) doReturn data.keyCipherResult

        // When
        subject.decrypt(getRandomNonce(8), "abc", decryptionOptions())

        if (data.passwordKeyGeneratorResult is Failure) {
            verifyNoInteractions(mockKeyCipher)
        } else {
            verify(mockKeyCipher).decrypt(
                any(),
                any(),
                any<KeyCipher.Options<AES.GcmNoPadding, AES.GcmNoPadding.DecryptionInputs>>()
            )
        }
    }

    private fun decryptionOptions() = PasswordCipher.Options(
        AES.GcmNoPadding(AES.KeyLength.L256),
        AES.GcmNoPadding.DecryptionInputs(iv = getRandomNonce(8).wrap()),
        PasswordKeyGenerator.Options(
            mock(),
            PasswordKeyGenerator.Algorithm.PBKDF2WithHmacSHA256,
            0,
            0
        )
    )

    // endregion Decrypt

    data class PasswordCipherEncryptionData(
        val passwordKeyGeneratorResult: Result<PasswordKeyGenerator.ResultData, PasswordKeyGenerator.Error>,
        val keyCipherResult: Result<KeyCipher.EncryptionResultData<AES.GcmNoPadding.DecryptionInputs>, KeyCipher.EncryptionError>,
        val expectedResult: Result<PasswordCipher.EncryptionResultData<AES.GcmNoPadding.DecryptionInputs>, PasswordCipher.EncryptionError>
    )

    data class PasswordCipherDecryptionData(
        val passwordKeyGeneratorResult: Result<PasswordKeyGenerator.ResultData, PasswordKeyGenerator.Error>,
        val keyCipherResult: Result<ByteArrayWrapper, KeyCipher.DecryptionError>,
        val expectedResult: Result<ByteArrayWrapper, PasswordCipher.DecryptionError>
    )

    companion object {
        /**
         * Input to [encrypt_whenPasswordKeyGeneratorFails_shouldNotInteractWithKeyCipher] and
         * [encrypt_shouldProduceCorrectOutputs].
         */
        @JvmStatic
        @Suppress("unused")
        fun encryptionTestInput() = listOf(
            // [1] Password key generator fails with AlgorithmNotSupported
            PasswordCipherEncryptionData(
                passwordKeyGeneratorResult = Failure(
                    PasswordKeyGenerator.Error.AlgorithmNotSupported(
                        PasswordKeyGenerator.Algorithm.PBKDF2WithHmacSHA256
                    )
                ),
                keyCipherResult = Failure(KeyCipher.EncryptionError.AlgorithmNotSupported(
                    AES.GcmNoPadding(AES.KeyLength.L256)
                )),
                expectedResult = Failure(PasswordCipher.EncryptionError.KeyGenerationError(
                    PasswordKeyGenerator.Error.AlgorithmNotSupported(
                        PasswordKeyGenerator.Algorithm.PBKDF2WithHmacSHA256
                    )
                ))
            ),
            // [2] Password key generator fails with InvalidArgument
            PasswordCipherEncryptionData(
                passwordKeyGeneratorResult = Failure(
                    PasswordKeyGenerator.Error.InvalidArgument("arg", "-5", ">0")
                ),
                keyCipherResult = Failure(KeyCipher.EncryptionError.AlgorithmNotSupported(
                    AES.GcmNoPadding(AES.KeyLength.L256)
                )),
                expectedResult = Failure(PasswordCipher.EncryptionError.KeyGenerationError(
                    PasswordKeyGenerator.Error.InvalidArgument("arg", "-5", ">0")
                ))
            ),
            // [3] Key cipher fails with AlgorithmNotSupported
            PasswordCipherEncryptionData(
                passwordKeyGeneratorResult = Success(
                    PasswordKeyGenerator.ResultData(getRandomNonce(8), getRandomNonce(8))
                ),
                keyCipherResult = Failure(KeyCipher.EncryptionError.AlgorithmNotSupported(
                    AES.GcmNoPadding(AES.KeyLength.L256)
                )),
                expectedResult = Failure(PasswordCipher.EncryptionError.AlgorithmNotSupported(
                    AES.GcmNoPadding(AES.KeyLength.L256)
                ))
            ),
            // [4] Key cipher succeeds
            PasswordCipherEncryptionData(
                passwordKeyGeneratorResult = Success(
                    PasswordKeyGenerator.ResultData(
                        byteArrayOf(4, 4, 5, 5, 6, 6, 7, 7), // key
                        byteArrayOf(0, 0, 1, 1, 2, 2, 3, 3) // salt
                    )
                ),
                keyCipherResult = Success(KeyCipher.EncryptionResultData(
                    byteArrayOf(7, 6, 5, 4, 3, 2, 1, 0).wrap(),
                    AES.GcmNoPadding.DecryptionInputs(iv = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8).wrap())
                )),
                expectedResult = Success(PasswordCipher.EncryptionResultData(
                    byteArrayOf(7, 6, 5, 4, 3, 2, 1, 0).wrap(),
                    AES.GcmNoPadding.DecryptionInputs(iv = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8).wrap()),
                    PasswordKeyGenerator.ResultData(
                        byteArrayOf(4, 4, 5, 5, 6, 6, 7, 7), // key
                        byteArrayOf(0, 0, 1, 1, 2, 2, 3, 3) // salt
                    )
                ))
            )
        )
        /**
         * Input to [decrypt_whenPasswordKeyGeneratorFails_shouldNotInteractWithKeyCipher] and
         * [decrypt_shouldProduceCorrectOutputs].
         */
        @JvmStatic
        @Suppress("unused")
        fun decryptionTestInput() = listOf(
            // [1] Password key generator fails with AlgorithmNotSupported
            PasswordCipherDecryptionData(
                passwordKeyGeneratorResult = Failure(
                    PasswordKeyGenerator.Error.AlgorithmNotSupported(
                        PasswordKeyGenerator.Algorithm.PBKDF2WithHmacSHA256
                    )
                ),
                keyCipherResult = Failure(KeyCipher.DecryptionError.AlgorithmNotSupported(
                    AES.GcmNoPadding(AES.KeyLength.L256)
                )),
                expectedResult = Failure(PasswordCipher.DecryptionError.KeyGenerationError(
                    PasswordKeyGenerator.Error.AlgorithmNotSupported(
                        PasswordKeyGenerator.Algorithm.PBKDF2WithHmacSHA256
                    )
                ))
            ),
            // [2] Password key generator fails with InvalidArgument
            PasswordCipherDecryptionData(
                passwordKeyGeneratorResult = Failure(
                    PasswordKeyGenerator.Error.InvalidArgument("arg", "-5", ">0")
                ),
                keyCipherResult = Failure(KeyCipher.DecryptionError.AlgorithmNotSupported(
                    AES.GcmNoPadding(AES.KeyLength.L256)
                )),
                expectedResult = Failure(PasswordCipher.DecryptionError.KeyGenerationError(
                    PasswordKeyGenerator.Error.InvalidArgument("arg", "-5", ">0")
                ))
            ),
            // [3] Key cipher fails with AlgorithmNotSupported
            PasswordCipherDecryptionData(
                passwordKeyGeneratorResult = Success(
                    PasswordKeyGenerator.ResultData(getRandomNonce(8), getRandomNonce(8))
                ),
                keyCipherResult = Failure(KeyCipher.DecryptionError.AlgorithmNotSupported(
                    AES.GcmNoPadding(AES.KeyLength.L256)
                )),
                expectedResult = Failure(PasswordCipher.DecryptionError.AlgorithmNotSupported(
                    AES.GcmNoPadding(AES.KeyLength.L256)
                ))
            ),
            // [4] Key cipher succeeds
            PasswordCipherDecryptionData(
                passwordKeyGeneratorResult = Success(
                    PasswordKeyGenerator.ResultData(getRandomNonce(8), getRandomNonce(8))
                ),
                keyCipherResult = Success(byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7).wrap()),
                expectedResult = Success(byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7).wrap())
            )
        )
    }
}
