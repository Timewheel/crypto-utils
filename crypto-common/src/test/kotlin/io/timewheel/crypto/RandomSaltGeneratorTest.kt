package io.timewheel.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows


class RandomSaltGeneratorTest {

    private lateinit var subject: RandomSaltGenerator

    @BeforeEach
    fun setUp() {
        subject = RandomSaltGenerator.ofSaltLength(SALT_SIZE)
    }

    @Test
    fun onNegativeSaltLength_throws() {
        assertThrows<IllegalArgumentException> {
            RandomSaltGenerator.ofSaltLength(-1)
        }
    }

    @Test
    fun onProvideSalt_generatesSaltOfCorrectSize() {
        // When
        val salt = subject.provideSalt()

        // Then
        assertEquals(SALT_SIZE, salt.size)
    }

    @Test
    fun onProvideSalt_generatesDistinctSalts() {
        // When
        val salt1 = subject.provideSalt()
        val salt2 = subject.provideSalt()

        // Then
        assertNotEquals(salt1, salt2)
    }

    companion object {
        const val SALT_SIZE: Int = 12
    }
}
