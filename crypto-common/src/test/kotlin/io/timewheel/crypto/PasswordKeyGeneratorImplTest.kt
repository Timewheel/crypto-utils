package io.timewheel.crypto

import io.timewheel.util.Result
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*
import java.security.NoSuchAlgorithmException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

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
        val options = PasswordKeyGenerator.Options(iterationCount = -1)

        // When
        val result = subject.generateKey("", options)

        // Then
        assertEquals(
            PasswordKeyGenerator.Error.InvalidArgument(
                "iterationCount",
                "${options.iterationCount}",
                ">=0"
            ),
            (result as Result.Fail).error
        )
    }

    @Test
    fun onGenerateKey_withNegativeKeyLength_fails() {
        // Given
        val options = PasswordKeyGenerator.Options(keyLength = 0)

        // When
        val result = subject.generateKey("", options)

        // Then
        assertEquals(
            PasswordKeyGenerator.Error.InvalidArgument(
                "keyLength",
                "${options.keyLength}",
                "> 0 AND a multiple of 8"
            ),
            (result as Result.Fail).error
        )
    }

    @Test
    fun onGenerateKey_withNonWholeBitCount_fails() {
        // Given
        val options = PasswordKeyGenerator.Options(keyLength = 6)

        // When
        val result = subject.generateKey("", options)

        // Then
        assertEquals(
            PasswordKeyGenerator.Error.InvalidArgument(
                "keyLength",
                "${options.keyLength}",
                "> 0 AND a multiple of 8"
            ),
            (result as Result.Fail).error
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
            PasswordKeyGenerator.Options(algorithm = algorithm)
        )

        // Then
        assertEquals(
            PasswordKeyGenerator.Error.AlgorithmNotSupported(algorithm),
            (result as Result.Fail).error
        )
    }

    @Test
    fun onGenerateKey_deliversSalt() {
        // Given
        secretKeyFactoryProviderFixture.useReal()
        val salt = getRandomNonce(12)
        val options = PasswordKeyGenerator.Options(saltProvider = StaticSaltProvider(salt))

        // When
        val data = subject.generateKey("abcABC_123", options)

        // Then
        assertArrayEquals(salt, (data as Result.Success).result.salt)
    }

    @Test
    fun onGenerateKey_deliversResultWithKeyOfRequestedLength() {
        // Given
        secretKeyFactoryProviderFixture.useReal()
        val keyLength = 128
        val options = PasswordKeyGenerator.Options(keyLength = keyLength)

        // When
        val data = subject.generateKey("abcABC_123", options)

        // Then
        assertEquals(keyLength, (data as Result.Success).result.key.size*8)
    }

    @Test
    fun onGenerateKey_deliversResultWithKey() {
        // Given
        secretKeyFactoryProviderFixture.useReal()
        val password = "abcABC_123"
        val salt = getRandomNonce(12)
        val options = PasswordKeyGenerator.Options(saltProvider = StaticSaltProvider(salt))
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
        assertArrayEquals(key, (data as Result.Success).result.key)
    }

    class SecretKeyFactoryProviderFixture : SecretKeyFactoryProvider {
        private val mock = mock<SecretKeyFactoryProvider>()
        private val real = SecretKeyFactoryProviderImpl()

        private var inUse = mock;

        override fun provideSecretKeyFactory(algorithm: PasswordKeyGenerator.Algorithm): SecretKeyFactory {
            return inUse.provideSecretKeyFactory(algorithm)
        }

        fun useReal() {
            inUse = real
        }

        private fun useMock() {
            inUse = mock
        }

        fun mockThrow() {
            useMock()
            whenever(mock.provideSecretKeyFactory(any())) doThrow NoSuchAlgorithmException::class
        }

        fun getSecretKeyFactory(algorithm: PasswordKeyGenerator.Algorithm): SecretKeyFactory {
            return real.provideSecretKeyFactory(algorithm)
        }
    }
}
