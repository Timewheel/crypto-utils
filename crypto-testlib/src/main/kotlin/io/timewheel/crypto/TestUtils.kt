package io.timewheel.crypto

import java.security.SecureRandom

fun randomByteArray(length: Int): ByteArray {
    val bytes = ByteArray(length)
    SecureRandom().nextBytes(bytes)
    return bytes
}

fun randomString(length: Int): String = randomByteArray(length).toString(Charsets.UTF_8)

fun hex(bytes: ByteArray) = StringBuilder().apply {
    for (b in bytes) {
        append(String.format("%02x", b))
    }
}.toString()
