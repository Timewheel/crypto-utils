package io.timewheel.crypto.encoding

import io.timewheel.util.ByteArrayWrapper
import io.timewheel.util.Result
import io.timewheel.util.wrap
import java.nio.ByteBuffer

/**
 * Interface for classes that can be encoded.
 */
interface Encodable {
    /**
     * @return a map of all properties that are relevant to the implementing class.
     */
    fun getEncodingMapping(): Map<String, EncodableType>
}

/**
 * List of types that can be encoded. Supports the following:
 *
 * - [kotlin.Byte]
 * - [kotlin.Char]
 * - [kotlin.Int]
 * - [kotlin.String]
 * - [kotlin.ByteArray]
 */
sealed class EncodableType(val type: kotlin.Char) {
    data class Byte(val value: kotlin.Byte) : EncodableType('b')
    data class Char(val value: kotlin.Char) : EncodableType('c')
    data class Int(val value: kotlin.Int) : EncodableType('i')
    data class String(val value: kotlin.String) : EncodableType('s')
    data class ByteArray(val value: ByteArrayWrapper) : EncodableType('a') { // a for array
        constructor(value: kotlin.ByteArray): this(value.wrap())
    }

    // Utility access functions
    fun byteOrNull() = this as? Byte
    fun charOrNull() = this as? Char
    fun intOrNull() = this as? Int
    fun stringOrNull() = this as? String
    fun byteArrayOrNull() = this as? ByteArray
}

/**
 * Tells the size of an encodable type in bytes.
 */
fun EncodableType.size() = when (this) {
    // All types record the type identifier as a char (1 byte)
    is EncodableType.Byte -> 2 + 1
    is EncodableType.Char -> 2 + 2
    is EncodableType.Int -> 2 + 4
    // Variable types record their size as an integer (4 bytes)
    is EncodableType.String -> 2 + 4 + value.toByteArray(Charsets.UTF_8).size
    is EncodableType.ByteArray -> 2 + 4 + value.data.size
}

/**
 * Puts an encodable type into the [buffer].
 */
fun EncodableType.putInto(buffer: ByteBuffer) {
    when (this) {
        is EncodableType.Byte -> buffer.put(value)
        is EncodableType.Char -> buffer.putChar(value)
        is EncodableType.Int -> buffer.putInt(value)
        is EncodableType.String -> {
            val bytes = value.toByteArray(Charsets.UTF_8)
            buffer.putInt(bytes.size).put(bytes)
        }
        is EncodableType.ByteArray -> buffer.putInt(value.data.size).put(value.data)
    }
}

/**
 * Puts the [encodableType] into the [ByteBuffer].
 */
fun ByteBuffer.putEncodableType(encodableType: EncodableType): ByteBuffer {
    putChar(encodableType.type)
    return when (encodableType) {
        is EncodableType.Byte -> put(encodableType.value)
        is EncodableType.Char -> putChar(encodableType.value)
        is EncodableType.Int -> putInt(encodableType.value)
        is EncodableType.String -> {
            val bytes = encodableType.value.toByteArray(Charsets.UTF_8)
            putInt(bytes.size).put(bytes)
        }
        is EncodableType.ByteArray -> putInt(encodableType.value.data.size).put(encodableType.value.data)
    }
}

fun ByteBuffer.getEncodableType(): Result<EncodableType, BadFormatError> {
    return try {
        when (char) {
            'b' -> Result.Success(EncodableType.Byte(get()))
            'c' -> Result.Success(EncodableType.Char(char))
            'i' -> Result.Success(EncodableType.Int(int))
            's' -> {
                val stringAsByteArray = ByteArray(int)
                get(stringAsByteArray)
                Result.Success(EncodableType.String(stringAsByteArray.toString(Charsets.UTF_8)))
            }
            'a' -> {
                val array = ByteArray(int)
                get(array)
                Result.Success(EncodableType.ByteArray(array.wrap()))
            }
            // Unsupported type
            else -> Result.Failure(BadFormatError)
        }
    } catch (x: Exception) {
        // If any of the ByteBuffer accesses throw an exception, catch and rethrow as bad format
        Result.Failure(BadFormatError)
    }
}

/**
 * Thrown when trying to read an [EncodableType] from a [ByteBuffer] but the format is bad
 */
internal class BadFormatException : Exception()

// Utility wrapping functions
fun Byte.encodableType() = EncodableType.Byte(this)
fun Int.encodableType() = EncodableType.Int(this)
fun String.encodableType() = EncodableType.String(this)
fun ByteArray.encodableType() = this.wrap().encodableType()
fun ByteArrayWrapper.encodableType() = EncodableType.ByteArray(this)
