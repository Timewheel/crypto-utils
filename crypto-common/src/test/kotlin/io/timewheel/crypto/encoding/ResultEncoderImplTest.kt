package io.timewheel.crypto.encoding

import io.timewheel.util.ByteArrayWrapper
import io.timewheel.util.Result
import io.timewheel.util.wrap
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.nio.ByteBuffer
import java.util.*

class ResultEncoderImplTest {

    private lateinit var mockBase64Coder: Base64Coder

    private lateinit var subject: ResultEncoderImpl

    @BeforeEach
    fun setUp() {
        mockBase64Coder = mock()

        subject = ResultEncoderImpl(mockBase64Coder)
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("encodeData")
    fun encode(description: String, data: EncodeData) {
        // Given
        data.byteArrayAndResult()?.let {
            whenever(mockBase64Coder.encode(it.first)) doReturn it.second
        }

        // When
        val result = subject.encode(data.format, data.encodable)

        // Then
        assertEquals(data.result, result)
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("decodeVersionData")
    fun decodeVersion(description: String, data: DecodeData) {
        // Given
        whenever(mockBase64Coder.decode(any())) doReturn data.byteArray.data

        // When
        val result = subject.decode("")

        // Then
        assertEquals(data.result, result)
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("decodeData")
    fun decode(description: String, data: DecodeData) {
        // Given
        whenever(mockBase64Coder.decode(any())) doReturn data.byteArray.data

        // When
        val result = subject.decode("")

        // Then
        assertEquals(data.result, result)
    }

    data class EncodeData(
        val encodable: Encodable,
        val format: String,
        val result: Result<String, BadFormatError>
    ) {
        fun byteArrayAndResult(): Pair<ByteArray, String>? = when (result) {
            is Result.Success -> Pair(byteArray(format, encodable), result.result)
            else -> null
        }
    }

    data class DecodeData(
        val byteArray: ByteArrayWrapper,
        val result: Result<Map<String, EncodableType>, BadFormatError>
    )

    companion object {
        @JvmStatic
        fun encodeData() = listOf(
            Arguments.of(
                "Format has a key that doesn't exist in the encodable",
                EncodeData(
                    encodable = encodableFrom(mapOf()),
                    format = "a",
                    result = Result.Failure(BadFormatError)
                )
            ),
            Arguments.of(
                "Encodable has a key that's not referenced in the format",
                EncodeData(
                    encodable = encodableFrom(
                        "a" to EncodableType.Int(6),
                        "b" to EncodableType.Int(12)
                    ),
                    format = "a",
                    result = Result.Failure(BadFormatError)
                )
            ),
            Arguments.of(
                "Success case",
                EncodeData(
                    encodable = encodableFrom(
                        "a" to EncodableType.Int(6),
                        "b" to EncodableType.Int(12)
                    ),
                    format = "a%b",
                    // Result gathered experimentally
                    result = Result.Success("Success")
                )
            )
        )

        @JvmStatic
        fun decodeVersionData(): List<Arguments> {
            val arguments = mutableListOf<Arguments>()
            val resultMap = mapOf("a" to EncodableType.String("test"))
            // All supported versions
            for (i in V1..CURRENT_VERSION) {
                arguments.add(
                    Arguments.of(
                        "V$i",
                        DecodeData(
                            byteArray = byteArray(i, "a", encodableFrom(resultMap)).wrap(),
                            result = Result.Success(resultMap)
                        )
                    )
                )
            }
            // Unsupported version
            arguments.add(
                Arguments.of(
                    "V${CURRENT_VERSION+1}",
                    DecodeData(
                        byteArray = byteArray(CURRENT_VERSION+1, "a", encodableFrom(resultMap)).wrap(),
                        result = Result.Failure(BadFormatError)
                    )
                )
            )
            return arguments
        }

        @JvmStatic
        fun decodeData() = listOf(
            Arguments.of(
                "Format is an unsupported type",
                DecodeData(
                    byteArray = ByteBuffer.allocate(6)
                        .putInt(1)
                        .putChar('z')
                        .array().wrap(),
                    result = Result.Failure(BadFormatError)
                )
            ),
            Arguments.of(
                "Format is a supported type but not a String",
                DecodeData(
                    byteArray = ByteBuffer.allocate(10)
                        .putInt(1)
                        .putEncodableType(EncodableType.Int(6))
                        .array().wrap(),
                    result = Result.Failure(BadFormatError)
                )
            ),
            Arguments.of(
                "Reading an EncodableType throws an error (trying to read more bytes than exist)",
                DecodeData(
                    byteArray = ByteBuffer.allocate(6)
                        .putInt(1)
                        .putChar('i')
                        .array().wrap(),
                    result = Result.Failure(BadFormatError)
                )
            ),
            Arguments.of(
                "After reading the whole array, there's still space in the buffer",
                DecodeData(
                    byteArray = ByteBuffer.allocate(100)
                        .putInt(1)
                        .putEncodableType(EncodableType.String("a"))
                        .putEncodableType(EncodableType.Int(6))
                        .array().wrap(),
                    result = Result.Failure(BadFormatError)
                )
            ),
            Arguments.of(
                "Success case; insert one of each encodable types and check they get read",
                DecodeData(
                    byteArray = ByteBuffer.allocate(4+15+3+4+6+7+8)
                        .putInt(1)
                        .putEncodableType(EncodableType.String("a%b%c%d%e"))
                        .putEncodableType(EncodableType.Byte(1))
                        .putEncodableType(EncodableType.Char('G'))
                        .putEncodableType(EncodableType.Int(6))
                        .putEncodableType(EncodableType.String("R"))
                        .putEncodableType(EncodableType.ByteArray(byteArrayOf(8, 9)))
                        .array().wrap(),
                    result = Result.Success(
                        mapOf(
                            "a" to EncodableType.Byte(1),
                            "b" to EncodableType.Char('G'),
                            "c" to EncodableType.Int(6),
                            "d" to EncodableType.String("R"),
                            "e" to EncodableType.ByteArray(byteArrayOf(8, 9))
                        )
                    )
                )
            )
        )

        private fun encodableFrom(vararg pairs: Pair<String, EncodableType>): Encodable {
            return encodableFrom(mapOf(*pairs))
        }

        private fun encodableFrom(mapping: Map<String, EncodableType>) = object : Encodable {
            override fun getEncodingMapping() = mapping
        }

        private fun byteArray(format: String, encodable: Encodable): ByteArray {
            return byteArray(CURRENT_VERSION, format, encodable)
        }

        private fun byteArray(version: Int, format: String, encodable: Encodable): ByteArray {
            val stringEncodable = EncodableType.String(format)
            val size = 4 + stringEncodable.size() + encodable.getEncodingMapping().size()
            val buffer = ByteBuffer.allocate(size)
            buffer.putInt(version).putEncodableType(stringEncodable)
            for (key in format.split("%")) {
                buffer.putEncodableType(encodable.getEncodingMapping()[key]!!)
            }
            return buffer.array()
        }
    }
}

private fun Map<String, EncodableType>.size(): Int {
    var value = 0
    for (item in values) {
        value += item.size()
    }
    return value
}
