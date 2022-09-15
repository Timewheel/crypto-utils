package io.timewheel.crypto

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class StaticNonceProviderTest {

    private lateinit var subject: StaticNonceProvider

    @BeforeEach
    fun setUp() {
        subject = StaticNonceProvider(SAMPLE_NONCE)
    }

    @Test
    fun provideNonce_providesNonce() {
        // When
        val nonce = subject.provideNonce()

        // Then
        assertArrayEquals(SAMPLE_NONCE, nonce)
    }

    @Test
    fun provideNonce_providesSameNonce() {
        // When
        val nonce1 = subject.provideNonce()
        val nonce2 = subject.provideNonce()

        // Then
        assertArrayEquals(nonce1, nonce2)
    }

    @Test
    fun provideNonce_providesNewInstance() {
        // When
        val nonce = subject.provideNonce()

        // Then
        assertFalse(nonce === SAMPLE_NONCE)
    }

    @Test
    fun provideNonce_providesDifferentInstances() {
        // When
        val nonce1 = subject.provideNonce()
        val nonce2 = subject.provideNonce()

        // Then
        assertFalse(nonce1 === nonce2)
    }

    companion object {
        val SAMPLE_NONCE = ByteArray(12).apply {
            SecureRandom().nextBytes(this)
        }
    }
}
