package io.timewheel.crypto

import android.util.Base64

/**
 * Cipher builder providing Android's implementation of the [Base64Coder].
 */
class AesGcmCipherBuilderImpl : AesGcmCipher.Builder() {
    override fun getBase64Coder(): Base64Coder = Base64CoderAndroid()
}

/**
 * Pre Android API 26 implementation of [Base64Coder]. For API 26+ use the jvm implementation.
 */
internal class Base64CoderAndroid : Base64Coder {
    override fun encode(source: ByteArray): String = Base64.encodeToString(source, Base64.DEFAULT)
    override fun decode(source: String): ByteArray = Base64.decode(source, Base64.DEFAULT)
}
