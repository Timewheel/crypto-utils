package io.timewheel.crypto

import java.util.*

/**
 * Creates a JVM [PasswordCipher] builder.
 */
fun PasswordCipher.Companion.build(block: PasswordCipher.Builder.() -> Unit) = build(Base64CoderJvm(), block)

/**
 * JVM implementation of [Base64Coder].
 */
internal class Base64CoderJvm : Base64Coder {
    override fun encode(source: ByteArray): String = Base64.getEncoder().encodeToString(source)
    override fun decode(source: String): ByteArray = Base64.getDecoder().decode(source)
}
