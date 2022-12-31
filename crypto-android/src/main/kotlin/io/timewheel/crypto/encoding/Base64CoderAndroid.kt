package io.timewheel.crypto.encoding

import android.util.Base64

/**
 * Pre Android API 26 implementation of [Base64Coder]. For API 26+ use the jvm implementation.
 */
internal class Base64CoderAndroid : Base64Coder {
    override fun encode(source: ByteArray): String = Base64.encodeToString(source, Base64.DEFAULT)
    override fun decode(source: String): ByteArray = Base64.decode(source, Base64.DEFAULT)
}
