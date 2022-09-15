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
        // When
        val result = subject.generateKey(
            "",
            AES.default(),
            PasswordKeyGenerator.Options(iterationCount = -1)
        )

        // Then
        assertEquals(
            PasswordKeyGenerator.Error.InvalidArgument("iterationCount", "-1", ">=0"),
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
            AES.default(),
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
        val data = subject.generateKey("abcABC_123", AES.default(), options)

        // Then
        assertArrayEquals(salt, (data as Result.Success).result.salt)
    }

    @Test
    fun onGenerateKey_deliversKeySpecWithKey() {
        // Given
        secretKeyFactoryProviderFixture.useReal()
        val password = "abcABC_123"
        val encryptionAlgorithm = AES.default()
        val salt = getRandomNonce(12)
        val options = PasswordKeyGenerator.Options(saltProvider = StaticSaltProvider(salt))
        val passwordKeySpec = PBEKeySpec(
            password.toCharArray(),
            salt,
            options.iterationCount,
            encryptionAlgorithm.keyLength()
        )
        val key = secretKeyFactoryProviderFixture.getSecretKeyFactory(options.algorithm)
            .generateSecret(passwordKeySpec)
            .encoded

        // When
        val data = subject.generateKey(password, encryptionAlgorithm, options)

        // Then
        assertArrayEquals(key, (data as Result.Success).result.keySpec.encoded)
    }

    @Test
    fun onGenerateKey_deliversKeySpecWithRequestedEncryptionAlgorithm() {
        // Given
        secretKeyFactoryProviderFixture.useReal()
        val encryptionAlgorithm = AES.default()

        // When
        val data = subject.generateKey(
            "abcABC_123",
            encryptionAlgorithm,
            PasswordKeyGenerator.Options()
        )

        // Then
        assertEquals(encryptionAlgorithm.name, (data as Result.Success).result.keySpec.algorithm)
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

        fun useMock() {
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
