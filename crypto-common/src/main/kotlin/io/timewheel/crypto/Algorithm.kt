package io.timewheel.crypto

/**
 * Encryption algorithm.
 */
//sealed class Algorithm(internal val algorithmString: String) {
//    /**
//     * AES algorithms
//     */
//    sealed class AES(algorithmString: String) : Algorithm(algorithmString) {
//        /**
//         * AES, GCM with no padding.
//         */
//        object GCMNoPadding : AES("AES/GCM/NoPadding")
//    }
//
//    companion object {
//        private val allAlgorithms = listOf<Algorithm>(
//            AES.GCMNoPadding
//        )
//
//        internal fun fromString(algorithmString: String): Algorithm? {
//            for (algorithm in allAlgorithms) {
//                if (algorithm.algorithmString == algorithmString) {
//                    return algorithm
//                }
//            }
//            return null
//        }
//    }
//}
