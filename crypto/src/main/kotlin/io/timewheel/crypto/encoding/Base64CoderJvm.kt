package io.timewheel.crypto.encoding

import java.util.Base64


/**
 * JVM implementation of [Base64Coder].
 */
internal class Base64CoderJvm : Base64Coder {
    override fun encode(source: ByteArray): String = Base64.getEncoder().encodeToString(source)
    override fun decode(source: String): ByteArray = Base64.getDecoder().decode(source)
}
