package io.timewheel.crypto

import java.util.*

class AesGcmCipherBuilderImpl : AesGcmCipher.Builder() {
    override fun getBase64Coder(): Base64Coder = Base64CoderJvm()
}

/**
 * Pre Android API 26 implementation of [Base64Coder]. For API 26+ use the jvm implementation.
 */
internal class Base64CoderJvm : Base64Coder {
    override fun encode(source: ByteArray): String = Base64.getEncoder().encodeToString(source)
    override fun decode(source: String): ByteArray = Base64.getDecoder().decode(source)
}
