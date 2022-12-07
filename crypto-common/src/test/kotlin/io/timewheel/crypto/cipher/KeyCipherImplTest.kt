package io.timewheel.crypto.cipher

import io.timewheel.crypto.getRandomNonce
import io.timewheel.util.ByteArrayWrapper
import io.timewheel.util.Result
import io.timewheel.util.wrap
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.mockito.kotlin.*
import javax.crypto.Cipher

class KeyCipherImplTest {
    private lateinit var cipherProviderFixture: CipherProviderFixture

    private lateinit var subject : KeyCipherImpl

    @BeforeEach
    fun setUp() {
        cipherProviderFixture = CipherProviderFixture()

        subject = KeyCipherImpl(cipherProviderFixture)
    }

    @Test
    fun encrypt_withUnsupportedAlgorithm_fails() {
        // Given - an unsupported algorithm
        val unsupportedAlgorithm = AES.GcmNoPadding(AES.KeyLength.L256)
        cipherProviderFixture.mockResponse(
            Result.Failure(CipherProvider.Error.AlgorithmNotSupported(unsupportedAlgorithm))
        )

        // When - encrypting with a valid key
        val result = subject.encrypt(
            byteArrayOf(),
            getRandomNonce(256/8),
            KeyCipher.Options(unsupportedAlgorithm, AES.GcmNoPadding.EncryptionInputs())
        )

        // Then - returns an error describing an algorithm that isn't supported
        assertEquals(
            Result.Failure<KeyCipher.EncryptionResultData<AES.GcmNoPadding.DecryptionInputs>, KeyCipher.EncryptionError>(
                KeyCipher.EncryptionError.AlgorithmNotSupported(unsupportedAlgorithm)
            ),
            result
        )
    }

    @Test
    fun encrypt_withInvalidKey_fails() {
        // Given - an invalid key
        val invalidKey = byteArrayOf(45, 38, 72)

        // When - encrypting
        val result = subject.encrypt(
            byteArrayOf(),
            invalidKey,
            KeyCipher.Options(AES.GcmNoPadding(AES.KeyLength.L256), AES.GcmNoPadding.EncryptionInputs())
        )

        // Then - returns an error describing an invalid key
        assertEquals(
            Result.Failure<KeyCipher.EncryptionResultData<AES.GcmNoPadding.DecryptionInputs>, KeyCipher.EncryptionError>(
                KeyCipher.EncryptionError.InvalidKey
            ),
            result
        )
    }

    @Test
    fun decrypt_withUnsupportedAlgorithm_fails() {
        // Given - an unsupported algorithm
        val unsupportedAlgorithm = AES.GcmNoPadding(AES.KeyLength.L256)
        cipherProviderFixture.mockResponse(
            Result.Failure(CipherProvider.Error.AlgorithmNotSupported(unsupportedAlgorithm))
        )

        // When - decrypting with a valid key
        val result = subject.decrypt(
            byteArrayOf(),
            getRandomNonce(256/8),
            KeyCipher.Options(unsupportedAlgorithm, AES.GcmNoPadding.DecryptionInputs(5, byteArrayOf().wrap()))
        )

        // Then - returns an error describing an algorithm that isn't supported
        assertEquals(
            Result.Failure<KeyCipher.EncryptionResultData<AES.GcmNoPadding.DecryptionInputs>, KeyCipher.DecryptionError>(
                KeyCipher.DecryptionError.AlgorithmNotSupported(unsupportedAlgorithm)
            ),
            result
        )
    }

    @Test
    fun decrypt_withInvalidKey_fails() {
        // Given - an invalid key
        val invalidKey = byteArrayOf(45, 38, 72)

        // When - decrypting
        val result = subject.decrypt(
            byteArrayOf(),
            invalidKey,
            KeyCipher.Options(AES.GcmNoPadding(AES.KeyLength.L256), AES.GcmNoPadding.DecryptionInputs(5, byteArrayOf().wrap()))
        )

        // Then - returns an error describing an invalid key
        assertEquals(
            Result.Failure<KeyCipher.EncryptionResultData<AES.GcmNoPadding.DecryptionInputs>, KeyCipher.DecryptionError>(
                KeyCipher.DecryptionError.InvalidKey
            ),
            result
        )
    }

    @Test
    fun decrypt_withWrongKey_fails() {
        // Given - an algorithm
        val algorithm = AES.GcmNoPadding(AES.KeyLength.L256)

        // And - a wrong decryption key
        val encryptionKey = getRandomNonce(256/8)
        val decryptionKey = encryptionKey.clone()
        decryptionKey[decryptionKey.size-1] = (if (decryptionKey[decryptionKey.size-1] == 0.toByte()) {
            1
        } else {
            decryptionKey[decryptionKey.size-1]-1
        }).toByte()

        // And - some cleartext
        val cleartext = getRandomNonce(512)

        // When - encrypting
        val encryptionResult = subject.encrypt(
            cleartext,
            encryptionKey,
            KeyCipher.Options(algorithm, AES.GcmNoPadding.EncryptionInputs())
        ) as Result.Success

        // When - decrypting
        val result = subject.decrypt(
            encryptionResult.result.ciphertext.data,
            decryptionKey,
            KeyCipher.Options(AES.GcmNoPadding(AES.KeyLength.L256), AES.GcmNoPadding.DecryptionInputs(iv = encryptionResult.result.algorithmData.iv))
        )

        // Then - returns an error describing an invalid key
        assertEquals(
            Result.Failure<KeyCipher.EncryptionResultData<AES.GcmNoPadding.DecryptionInputs>, KeyCipher.DecryptionError>(
                KeyCipher.DecryptionError.WrongKey
            ),
            result
        )
    }

    @ParameterizedTest
    @MethodSource("symmetryInput")
    fun encryption_decryption_areSymmetric(options: KeyCipher.Options<Algorithm<Algorithm.EncryptionInputs<Algorithm.DecryptionInputs>, Algorithm.DecryptionInputs>, Algorithm.EncryptionInputs<Algorithm.DecryptionInputs>>) {
        // Given - plaintext, key, and input data
        val plaintext = getRandomNonce(1024)
        val key = KeyProvider.create(options.algorithm).getResultOrDoAndReturnOnFailure {
            fail("Algorithm not supported in testing platform")
        }.provideKey()

        // When - encrypting
        val result = subject.encrypt(plaintext, key, options).getResultOrDoAndReturnOnFailure {
            fail()
        }

        // And - decrypting
        val resultWithPlaintext = subject.decrypt(result.ciphertext.data, key, KeyCipher.Options(options.algorithm, result.algorithmData))

        // Then - decrypted plaintext equals original plaintext
        assertEquals(Result.Success<ByteArrayWrapper, KeyCipher.DecryptionError>(plaintext.wrap()), resultWithPlaintext)
    }

    internal class CipherProviderFixture : CipherProvider {
        private val mock = mock<CipherProvider>()
        private val real = CipherProviderImpl()

        init {
            whenever(mock.provideCipher(any())) doAnswer {
                real.provideCipher(it.getArgument(0))
            }
        }

        override fun provideCipher(algorithm: Algorithm<*, *>): Result<Cipher, CipherProvider.Error> {
            return mock.provideCipher(algorithm)
        }

        internal fun mockResponse(result: Result<Cipher, CipherProvider.Error>) {
            whenever(mock.provideCipher(any())) doReturn result
        }
    }

    companion object {
        @JvmStatic
        fun symmetryInput() = listOf(
            KeyCipher.Options(
                AES.GcmNoPadding(AES.KeyLength.L128),
                AES.GcmNoPadding.EncryptionInputs()
            ),
            KeyCipher.Options(
                AES.GcmNoPadding(AES.KeyLength.L192),
                AES.GcmNoPadding.EncryptionInputs()
            ),
            KeyCipher.Options(
                AES.GcmNoPadding(AES.KeyLength.L256),
                AES.GcmNoPadding.EncryptionInputs()
            )
        )
    }
}
