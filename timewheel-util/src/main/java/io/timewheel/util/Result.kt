package io.timewheel.util

/**
 * The result of an operation. Can be one of the following:
 * - [Success]: the operation completed successfully. Provides the [Success.result].
 * - [Fail]: the operation finished with an error. Provides the [Fail.error].
 */
sealed class Result<in SuccessType, in ErrorType> {
    data class Success<SuccessType>(val result: SuccessType) : Result<SuccessType, Any>()
    data class Fail<ErrorType>(val error: ErrorType) : Result<Any, ErrorType>()
}
