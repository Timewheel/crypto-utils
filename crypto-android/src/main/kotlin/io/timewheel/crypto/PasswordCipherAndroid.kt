package io.timewheel.crypto

import io.timewheel.crypto.encoding.Base64CoderAndroid

/**
 * Creates a pre Android API 26 [PasswordCipher] builder.
 */
fun PasswordCipher.Companion.build(block: PasswordCipher.Builder.() -> Unit) = build(Base64CoderAndroid(), block)
