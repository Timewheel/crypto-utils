package io.timewheel.crypto

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class RandomNonceGeneratorTest {

    private lateinit var subject: RandomNonceGenerator

    @BeforeEach
    fun setUp() {
        subject = RandomNonceGenerator.ofNonceSize(NONCE_SIZE)
    }

    @Test
    fun onNegativeNonceSize_throws() {
        assertThrows<IllegalArgumentException> {
            RandomNonceGenerator.ofNonceSize(-1)
        }
    }

    @Test
    fun provideNonce_generatesNonceOfCorrectSize() {
        // When
        val nonce = subject.provideNonce()

        // Then
        assertEquals(NONCE_SIZE, nonce.size)
    }

    @Test
    fun provideNonce_generatesDistinctNonces() {
        // When
        val nonce1 = subject.provideNonce()
        val nonce2 = subject.provideNonce()

        // Then
        assertFalse(nonce1.contentEquals(nonce2))
    }

    companion object {
        const val NONCE_SIZE: Int = 12
    }
}
