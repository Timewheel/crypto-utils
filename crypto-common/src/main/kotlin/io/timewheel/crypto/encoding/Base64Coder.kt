package io.timewheel.crypto.encoding

import java.util.ServiceLoader

/**
 * Turns [ByteArray]s into Base64 encoded [String]s and vice-versa. Implementations must satisfy
 * the following requirements:
 *
 * - Both [encode] and [decode] operations must be symmetric. If y = encode(x), then x = decode(y).
 * - Must be thread safe. Preferably stateless.
 */
interface Base64Coder {
    /**
     * Encodes the [source] [ByteArray] into a Base64 [String].
     */
    fun encode(source: ByteArray): String

    /**
     * Decodes the [source] Base64 [String] into a [ByteArray].
     */
    fun decode(source: String): ByteArray
}

internal interface Base64CoderProvider {
    fun provideBase64Coder(): Base64Coder
}

internal class Base64CoderProviderImpl : Base64CoderProvider {
    private val loader = ServiceLoader.load(Base64Coder::class.java)

    override fun provideBase64Coder(): Base64Coder = loader.first()
}
