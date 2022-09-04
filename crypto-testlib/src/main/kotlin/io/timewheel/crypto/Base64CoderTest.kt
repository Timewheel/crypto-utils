package io.timewheel.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

abstract class Base64CoderTest {

    abstract fun subject(): Base64Coder

    @Test
    fun encode_isSymmetric() {
        // Given
        val originalArray = randomByteArray(1024)

        // When
        val encodedString = subject().encode(originalArray)
        val decodedArray = subject().decode(encodedString)

        // Then
        assertArrayEquals(originalArray, decodedArray)
    }

    @Test
    fun decode_isSymmetric() {
        // Given
        val originalArray = randomByteArray(1024)
        val originalString = subject().encode(originalArray)

        // When
        val encodedArray = subject().decode(originalString)
        val decodedString = subject().encode(encodedArray)

        // Then
        assertEquals(originalString, decodedString)
    }
}
