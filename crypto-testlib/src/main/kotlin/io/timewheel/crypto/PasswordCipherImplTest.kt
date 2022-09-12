package io.timewheel.crypto

import io.timewheel.util.Result
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.*
import kotlin.text.Charsets.UTF_8

abstract class PasswordCipherImplTest {

    abstract fun subject(): PasswordCipher

    @Test
    fun shouldEncryptAndDecrypt() {
        // Given
        val input = randomString(128)
        val password = "abc123"

        // When
        val encryptionResult = subject().encrypt(
            input,
            password,
            PasswordCipher.Options(AES.default(), PasswordKeyGenerator.Options())
        )
        val decryptionResult = subject().decrypt((encryptionResult as Result.Success).result, password)

        // Then
        assertEquals(input, (decryptionResult as Result.Success).result)
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
        val encryptionResults = subject().encrypt(
            input,
            password,
            PasswordCipher.Options(AES.default(), PasswordKeyGenerator.Options())
        )
        val decryptionResults = encryptionResults.map { it as Result.Success }
            .map { subject().decrypt(it.result, password) }
            .map { it as Result.Success }
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
        val base64Input = Base64.getEncoder().encodeToString(input)

        // When
        val result = subject().decrypt(base64Input, "")

        // Then
        assertEquals(Result.Fail(DecryptionError.BadFormat), result)
    }

    @Test
    fun decrypt_shouldErrorOutWithDifferentPasswords() {
        // Given
        val input = randomString(128)
        val encryptionResult = subject().encrypt(
            input,
            "abc123",
            PasswordCipher.Options(AES.default(), PasswordKeyGenerator.Options())
        )

        // When
        val decryptionResult = subject().decrypt((encryptionResult as Result.Success).result, "123abc")

        // Then
        assertEquals(Result.Fail(DecryptionError.WrongPassword), decryptionResult)
    }

    @Test
    fun toByteArray_thenToString_withUTF8_isSymmetric() {
        // Given
        val string = randomString(256)

        // When
        val byteString = string.toByteArray(UTF_8)
        val decodedString = byteString.toString(UTF_8)

        // Then
        assertEquals(string, decodedString)
    }

    @Test
    fun toString_thenToByteArray_withUTF8_isSymmetric() {
        // Given
        val string = randomString(256)

        // When
        val byteString = string.toByteArray(UTF_8)
        val decodedString = byteString.toString(UTF_8)

        // Then
        assertEquals(string, decodedString)
    }

    // TODO this feels strange to me; investigate
    @Test
    fun corruption() {
        val buffer = ByteBuffer.allocate(3)
        buffer.put(-56)
        val array = buffer.array()

        val str = array.toString(UTF_8)
        val newArray = str.toByteArray(UTF_8)
        val newStr = newArray.toString(UTF_8)

        assertFalse(array.equals(newArray))
        assertEquals(str, newStr)
    }
}
