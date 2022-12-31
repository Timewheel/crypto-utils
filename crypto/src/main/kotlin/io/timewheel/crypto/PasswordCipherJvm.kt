package io.timewheel.crypto

import io.timewheel.crypto.encoding.Base64CoderJvm

/**
 * Creates a JVM [PasswordCipher] builder.
 */
fun PasswordCipher.Companion.build(block: PasswordCipher.Builder.() -> Unit) = build(Base64CoderJvm(), block)
