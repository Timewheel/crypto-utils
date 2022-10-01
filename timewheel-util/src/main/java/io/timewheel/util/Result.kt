package io.timewheel.util

/**
 * The result of an operation. Can be one of the following:
 * - [Success]: the operation completed successfully. Provides the [Success.result].
 * - [Failure]: the operation finished with an error. Provides the [Failure.error].
 */
sealed class Result<ResultType, ErrorType> {
    data class Success<ResultType, ErrorType>(val result: ResultType) : Result<ResultType, ErrorType>()
    data class Failure<ResultType, ErrorType>(val error: ErrorType) : Result<ResultType, ErrorType>()

    /**
     * Executes the [block] if the [Result] is a [Success], providing the [Success.result].
     */
    fun doIfSuccess(block: (ResultType) -> Unit) : Result<ResultType, ErrorType> {
        if (this is Success) {
            block(this.result)
        }
        return this
    }

    /**
     * Executes the [block] if the [Result] is a [Failure], providing the [Failure.error].
     */
    fun doIfFailure(block: (ErrorType) -> Unit) : Result<ResultType, ErrorType> {
        if (this is Failure) {
            block(this.error)
        }
        return this
    }
}
