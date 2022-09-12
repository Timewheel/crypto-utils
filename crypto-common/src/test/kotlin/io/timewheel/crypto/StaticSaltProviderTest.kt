package io.timewheel.crypto

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.SecureRandom


class StaticSaltProviderTest {

    private lateinit var subject: StaticSaltProvider

    @BeforeEach
    fun setUp() {
        subject = StaticSaltProvider(SAMPLE_SALT)
    }

    @Test
    fun onProvideSalt_providesSalt() {
        // When
        val salt = subject.provideSalt()

        // Then
        assertTrue(salt.contentEquals(SAMPLE_SALT))
    }

    @Test
    fun onProvideSalt_providesSameSalt() {
        // When
        val salt1 = subject.provideSalt()
        val salt2 = subject.provideSalt()

        // Then
        assertTrue(salt1.contentEquals(salt2))
    }

    @Test
    fun onProvideSalt_providesNewInstance() {
        // When
        val salt = subject.provideSalt()

        // Then
        assertFalse(salt === SAMPLE_SALT)
    }

    @Test
    fun onProvideSalt_providesDifferentInstances() {
        // When
        val salt1 = subject.provideSalt()
        val salt2 = subject.provideSalt()

        // Then
        assertFalse(salt1 === salt2)
    }

    companion object {
        val SAMPLE_SALT = ByteArray(12).apply {
            SecureRandom().nextBytes(this)
        }
    }
}
