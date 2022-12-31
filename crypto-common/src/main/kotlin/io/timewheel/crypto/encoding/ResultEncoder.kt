package io.timewheel.crypto.encoding

import java.util.LinkedList
import java.util.Queue
import io.timewheel.util.Result
import java.nio.ByteBuffer

internal const val V1 = 1
internal const val CURRENT_VERSION = V1
private const val FORMAT_DELIMITER = "%"

/**
 * Internal utility class. Encodes [Encodable]s, which provide a mapping of String to
 * [EncodableType], into Base64 strings and decodes Base64 encoded strings into the
 * original maps of String to [EncodableType] they were encoded from.
 */
interface ResultEncoder {
    /**
     * Encodes an [Encodable] in to a base 64 String with the provided format.
     */
    fun encode(format: String, data: Encodable): Result<String, BadFormatError>

    /**
     * Decodes a base 64 String into a map of String to [EncodableType].
     */
    fun decode(data: String): Result<Map<String, EncodableType>, BadFormatError>

    companion object {
        fun create(): ResultEncoder {
            return ResultEncoderImpl(Base64CoderProviderImpl().provideBase64Coder())
        }
    }
}

class ResultEncoderImpl(private val coder: Base64Coder) : ResultEncoder {
    override fun encode(format: String, data: Encodable): Result<String, BadFormatError> {
        val formatEncodable = EncodableType.String(format)
        val formatQueue = format.split(FORMAT_DELIMITER).toQueue()
        val encodingMapping = data.getEncodingMapping().toMutableMap()
        val orderedEncodables = mutableListOf<EncodableType>()

        // Calculate the size of the buffer and populate the items to encode in order
        // Version goes raw as an integer
        var size = 4 + formatEncodable.size()
        while (formatQueue.isNotEmpty()) {
            val encodable = encodingMapping.remove(formatQueue.remove()) ?: return Result.Failure(BadFormatError)
            orderedEncodables.add(encodable)
            size += encodable.size()
        }

        // If the mapping is not empty by the end of it something is not getting encoded
        if (encodingMapping.isNotEmpty()) {
            return Result.Failure(BadFormatError)
        }

        // Allocate the buffer
        val buffer = ByteBuffer.allocate(size)
        // Version
        buffer.putInt(CURRENT_VERSION)
        // Format
        buffer.putEncodableType(formatEncodable)
        // All other encodables in order
        for (item in orderedEncodables) {
            buffer.putEncodableType(item)
        }

        // Return the encoding
        return Result.Success(coder.encode(buffer.array()))
    }

    override fun decode(data: String): Result<Map<String, EncodableType>, BadFormatError> {
        val buffer = ByteBuffer.wrap(coder.decode(data))

        // Decode version
        return when (buffer.int) {
            V1 -> decodeV1(buffer)
            else -> Result.Failure(BadFormatError)
        }
    }

    private fun decodeV1(buffer: ByteBuffer): Result<Map<String, EncodableType>, BadFormatError> {
        return when (val formatResult = buffer.getEncodableType()) {
            is Result.Failure -> formatResult.map()
            is Result.Success -> formatResult.result.stringOrNull()?.let {
                return decodeV1(it.value, buffer)
            } ?: Result.Failure(BadFormatError)
        }
    }

    private fun decodeV1(format: String, buffer: ByteBuffer): Result<Map<String, EncodableType>, BadFormatError> {
        val formatList = format.split(FORMAT_DELIMITER)

        val mapping = mutableMapOf<String, EncodableType>()
        for (item in formatList) {
            when (val typeResult = buffer.getEncodableType()) {
                is Result.Failure -> return typeResult.map()
                is Result.Success -> {
                    mapping[item] = typeResult.result
                }
            }
        }

        if (buffer.hasRemaining()) {
            return Result.Failure(BadFormatError)
        }
        return Result.Success(mapping)
    }
}

private fun List<String>.toQueue(): Queue<String> {
    return LinkedList<String>().also {
        for (item in this) {
            it.offer(item)
        }
    }
}
