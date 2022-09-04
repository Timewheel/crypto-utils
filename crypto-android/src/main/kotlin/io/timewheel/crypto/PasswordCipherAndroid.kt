package io.timewheel.crypto

import android.util.Base64

/**
 * Creates a pre Android API 26 [PasswordCipher] builder.
 */
fun PasswordCipher.Companion.build(block: PasswordCipher.Builder.() -> Unit) = build(Base64CoderAndroid(), block)

/**
 * Pre Android API 26 implementation of [Base64Coder]. For API 26+ use the jvm implementation.
 */
internal class Base64CoderAndroid : Base64Coder {
    override fun encode(source: ByteArray): String = Base64.encodeToString(source, Base64.DEFAULT)
    override fun decode(source: String): ByteArray = Base64.decode(source, Base64.DEFAULT)
}
