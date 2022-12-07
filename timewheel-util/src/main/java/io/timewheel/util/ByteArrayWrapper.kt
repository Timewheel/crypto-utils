package io.timewheel.util

/**
 * Wrapper around [ByteArray] as a data class. Contains the backing [data]. Implements [equals] and
 * [hashCode]. It's purpose is to avoid littering the code with data classes that implements those
 * members.
 */
data class ByteArrayWrapper(
    val data: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ByteArrayWrapper

        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        return data.contentHashCode()
    }
}

/**
 * Utility function to wrap a [ByteArray] into a [ByteArrayWrapper]
 */
fun ByteArray.wrap() = ByteArrayWrapper(this)
