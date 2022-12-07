package io.timewheel.crypto.cipher.password

import io.timewheel.crypto.NonceProvider
import io.timewheel.crypto.RandomNonceGenerator
import io.timewheel.crypto.StaticNonceProvider
import io.timewheel.crypto.cipher.password.PasswordKeyGenerator.Error
import io.timewheel.crypto.cipher.password.PasswordKeyGenerator.ResultData
import io.timewheel.crypto.getRandomNonce
import io.timewheel.util.Result
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*
import java.security.NoSuchAlgorithmException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

private typealias PasswordKeyGeneratorResult = Result<ResultData, Error>

class PasswordKeyGeneratorImplTest {

    private lateinit var secretKeyFactoryProviderFixture: SecretKeyFactoryProviderFixture

    private lateinit var subject: PasswordKeyGeneratorImpl

    @BeforeEach
    fun setUp() {
        secretKeyFactoryProviderFixture = SecretKeyFactoryProviderFixture()

        subject = PasswordKeyGeneratorImpl(secretKeyFactoryProviderFixture)
    }

    @Test
    fun onGenerateKey_withNegativeIterationCount_fails() {
        // Given
        val options = options(iterationCount = 1000)

        // When
        val result = subject.generateKey("", options)

        // Then
        assertEquals(
            failureWith(
                Error.InvalidArgument(
                    "iterationCount",
                    "${options.iterationCount}",
                    ">1000"
                )
            ),
            result
        )
    }

    @Test
    fun onGenerateKey_withNegativeKeyLength_fails() {
        // Given
        val options = options(keyLength = 0)

        // When
        val result = subject.generateKey("", options)

        // Then
        assertEquals(
            failureWith(
                Error.InvalidArgument(
                    "keyLength",
                    "${options.keyLength}",
                    "> 0 AND a multiple of 8"
                )
            ),
            result
        )
    }

    @Test
    fun onGenerateKey_withNonWholeBitCount_fails() {
        // Given
        val options = options(keyLength = 6)

        // When
        val result = subject.generateKey("", options)

        // Then
        assertEquals(
            failureWith(
                Error.InvalidArgument(
                    "keyLength",
                    "${options.keyLength}",
                    "> 0 AND a multiple of 8"
                )
            ),
            result
        )
    }

    @Test
    fun onGenerateKey_whenSecretKeyProviderThrows_fails() {
        // Given
        val algorithm = PasswordKeyGenerator.Algorithm.PBKDF2WithHmacSHA256
        secretKeyFactoryProviderFixture.mockThrow()

        // When
        val result = subject.generateKey(
            "",
            options(algorithm = algorithm)
        )

        // Then
        assertEquals(
            failureWith(Error.AlgorithmNotSupported(algorithm)),
            result
        )
    }

    @Test
    fun onGenerateKey_deliversResultWithKeyOfRequestedLength() {
        // Given
        val keyLength = 128
        val options = options(keyLength = keyLength)

        // When
        val data = subject.generateKey("abcABC_123", options)

        // Then
        assertEquals(keyLength, (data as Result.Success).result.key.data.size*8)
    }

    @Test
    fun onGenerateKey_deliversResultWithSaltAndKey() {
        // Given
        val password = "abcABC_123"
        val salt = getRandomNonce(12)
        val options = options(saltProvider = StaticNonceProvider(salt))
        val passwordKeySpec = PBEKeySpec(
            password.toCharArray(),
            salt,
            options.iterationCount,
            options.keyLength
        )
        val key = secretKeyFactoryProviderFixture.getSecretKeyFactory(options.algorithm)
            .generateSecret(passwordKeySpec)
            .encoded

        // When
        val data = subject.generateKey(password, options)

        // Then
        assertEquals(successFrom(key, salt), data)
    }

    private fun successFrom(key: ByteArray, salt: ByteArray): PasswordKeyGeneratorResult {
        return Result.Success(ResultData(key, salt))
    }

    private fun failureWith(error: Error): PasswordKeyGeneratorResult {
        return Result.Failure(error)
    }

    private fun options(
        saltProvider: NonceProvider = RandomNonceGenerator.ofNonceSize(16),
        algorithm: PasswordKeyGenerator.Algorithm = PasswordKeyGenerator.Algorithm.PBKDF2WithHmacSHA256,
        iterationCount: Int = 65536,
        keyLength: Int = 256
    ) = PasswordKeyGenerator.Options(saltProvider, algorithm, iterationCount, keyLength)

    class SecretKeyFactoryProviderFixture : SecretKeyFactoryProvider {
        private val mock = mock<SecretKeyFactoryProvider>()
        private val real = SecretKeyFactoryProviderImpl()

        init {
            mockRealResponse()
        }

        override fun provideSecretKeyFactory(algorithm: PasswordKeyGenerator.Algorithm): SecretKeyFactory {
            return mock.provideSecretKeyFactory(algorithm)
        }

        fun mockRealResponse() {
            whenever(mock.provideSecretKeyFactory(any())) doAnswer {
                real.provideSecretKeyFactory(it.getArgument(0))
            }
        }

        fun mockThrow() {
            whenever(mock.provideSecretKeyFactory(any())) doThrow NoSuchAlgorithmException::class
        }

        fun getSecretKeyFactory(algorithm: PasswordKeyGenerator.Algorithm): SecretKeyFactory {
            return real.provideSecretKeyFactory(algorithm)
        }
    }
}
