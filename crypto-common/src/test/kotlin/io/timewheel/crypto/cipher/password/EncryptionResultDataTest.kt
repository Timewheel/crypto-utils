package io.timewheel.crypto.cipher.password

import io.timewheel.crypto.cipher.Algorithm
import io.timewheel.crypto.encoding.ResultEncoder
import io.timewheel.util.ByteArrayWrapper
import io.timewheel.util.Result
import io.timewheel.util.wrap
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*

class EncryptionResultDataTest {
    private lateinit var mockResultEncoder: ResultEncoder

    @BeforeEach
    fun setUp() {
        mockResultEncoder = mock()
    }

    @Test
    fun encode_shouldCallResultEncoderEncode() {
        // Given
        val subject = createSubject()
        whenever(mockResultEncoder.encode(any(), any())) doReturn Result.Success("")

        // When
        subject.encode()

        // Then
        verify(mockResultEncoder).encode(any(), eq(subject))
    }

    @Test
    fun encodeWithFormat_shouldCallResultEncoderEncode() {
        // Given
        val format = "some%format"
        val subject = createSubject()
        whenever(mockResultEncoder.encode(any(), any())) doReturn Result.Success("")

        // When
        subject.encode(format)

        // Then
        verify(mockResultEncoder).encode(eq(format), eq(subject))
    }

    @Test
    fun encode_shouldGatherAlgorithmData() {
        // Given
        val mockAlgorithmData = mock<Algorithm.DecryptionInputs>()
        val subject = createSubject(algorithmData = mockAlgorithmData)

        whenever(mockResultEncoder.encode(any(), any())) doReturn Result.Success("")

        // When
        subject.getEncodingMapping()

        // Then
        verify(mockAlgorithmData).getEncodingMapping()
    }

    private fun createSubject(
        ciphertext: ByteArrayWrapper = byteArrayOf().wrap(),
        algorithmData: Algorithm.DecryptionInputs = mock(),
        passwordKeyGeneratorData: PasswordKeyGenerator.ResultData = PasswordKeyGenerator.ResultData(
            byteArrayOf(),
            byteArrayOf(),
            55
        )
    ) = PasswordCipher.EncryptionResultData(
        ciphertext,
        algorithmData,
        passwordKeyGeneratorData
    ).apply { setEncoder(mockResultEncoder) }
}
