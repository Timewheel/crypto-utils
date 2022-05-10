package io.timewheel.crypto

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer
import java.security.SecureRandom
import kotlin.text.Charsets.UTF_8

@RunWith(AndroidJUnit4::class)
class AesGcmCipherImplTest {
    private lateinit var subject: AesGcmCipherImpl

    @Before
    fun setUp() {
        subject = AesGcmCipher.Builder().build() as AesGcmCipherImpl
    }

    @Test
    fun shouldEncryptAndDecrypt() {
        // Given
        val input = randomString(128)
        val password = "abc123"

        // When
        val encryptionResult = subject.encrypt(input, password)
        val decryptionResult = subject.decrypt(encryptionResult, password)

        // Then
        assertEquals(input, (decryptionResult as DecryptionResult.Success).result)
    }

    @Test
    fun shouldEncryptAndDecryptMultipleStrings() {
        // Given
        val random = SecureRandom()
        val input = mutableListOf<String>()
        repeat(10) {
            input.add(randomString(random.nextInt(512)))
        }
        val password = "123abc"

        // When
        val encryptionResults = subject.encrypt(input, password)
        val decryptionResults = encryptionResults.map { subject.decrypt(it, password) }
            .map { it as DecryptionResult.Success }
            .map { it.result }

        // Then
        assertEquals(input, decryptionResults)
    }

    @Test
    fun decrypt_shouldErrorOutWhenFormatIsUnexpected() {
        // Given
        val input = ByteBuffer.allocate(4)
            .putInt(-1)
            .array()
        val base64Input = Base64.encodeToString(input, Base64.DEFAULT)

        // When
        val result = subject.decrypt(base64Input, "")

        // Then
        assertEquals(DecryptionResult.Failed(DecryptionError.BadFormat), result)
    }

    @Test
    fun decrypt_shouldErrorOutWithDifferentPasswords() {
        // Given
        val input = randomString(128)
        val encryptionResult = subject.encrypt(input, "abc123")

        // When
        val decryptionResult = subject.decrypt(encryptionResult, "123abc")

        // Then
        assertEquals(DecryptionResult.Failed(DecryptionError.WrongPassword), decryptionResult)
    }

    @Test
    fun encodeAndDecode_isSymmetric() {
        // Given
        val nonce = subject.getRandomNonce(16)

        // When
        val encodedNonce = Base64.encodeToString(nonce, Base64.DEFAULT)
        val decodedNonce = Base64.decode(encodedNonce.toByteArray(), Base64.DEFAULT)

        // Then
        assertEquals(hex(nonce), hex(decodedNonce))
    }

    @Test
    fun toByteArray_thenToString_withUTF8_isSymmetric() {
        // Given
        val string = randomString(16)

        // When
        val byteSalt = string.toByteArray(UTF_8)
        val decodedSalt = byteSalt.toString(UTF_8)

        // Then
        assertEquals(string, decodedSalt)
    }

    private fun randomString(length: Int): String {
        val bytes = ByteArray(length)
        SecureRandom().nextBytes(bytes)
        return bytes.toString(UTF_8)
    }

    private fun hex(bytes: ByteArray) = StringBuilder().apply {
        for (b in bytes) {
            append(String.format("%02x", b))
        }
    }.toString()
}
