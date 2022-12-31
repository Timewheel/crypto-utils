package io.timewheel.crypto

import java.security.SecureRandom

/**
 * Creates a random nonce of the specified [byteCount].
 */
fun getRandomNonce(byteCount: Int) = ByteArray(byteCount).also { byteArray ->
    SecureRandom().nextBytes(byteArray)
}

fun <K, V> Map<K, V>.toPairArray() = entries.map { Pair(it.key, it.value) }.toTypedArray()
