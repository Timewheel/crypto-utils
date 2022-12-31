package io.timewheel.util

/**
 * The result of an operation. Can be one of the following:
 * - [Success]: the operation completed successfully. Provides the [Success.result].
 * - [Failure]: the operation finished with an error. Provides the [Failure.error].
 */
sealed class Result<ResultType, ErrorType> {
    data class Success<ResultType, ErrorType>(val result: ResultType) : Result<ResultType, ErrorType>()
    data class Failure<ResultType, ErrorType>(val error: ErrorType) : Result<ResultType, ErrorType>() {
        fun <NewResultType> map(): Failure<NewResultType, ErrorType> = Failure(error)
    }

    /**
     * Executes the [block] if the [Result] is a [Success], providing the [Success.result].
     */
    inline fun doIfSuccess(block: (ResultType) -> Unit) : Result<ResultType, ErrorType> {
        if (this is Success) {
            block(result)
        }
        return this
    }

    /**
     * Executes the [block] if the [Result] is a [Failure], providing the [Failure.error].
     */
    inline fun doIfFailure(block: (ErrorType) -> Unit) : Result<ResultType, ErrorType> {
        if (this is Failure) {
            block(error)
        }
        return this
    }

    inline fun <NewResultType, NewErrorType> map(
        successBlock: (ResultType) -> NewResultType,
        failureBlock: (ErrorType) -> NewErrorType
    ): Result<NewResultType, NewErrorType> {
        return when (this) {
            is Success -> Success(successBlock(result))
            is Failure -> Failure(failureBlock(error))
        }
    }

    inline fun <NewResultType> mapSuccess(
        block: (ResultType) -> NewResultType
    ): Result<NewResultType, ErrorType> {
        return when (this) {
            is Success -> Success(block(result))
            is Failure -> Failure(error)
        }
    }

    inline fun <NewErrorType> mapFailure(
        block: (ErrorType) -> NewErrorType
    ): Result<ResultType, NewErrorType> {
        return when (this) {
            is Success -> Success(result)
            is Failure -> Failure(block(error))
        }
    }

    inline fun <NewResultType> flatMap(
        block: (ResultType) -> Result<NewResultType, ErrorType>
    ): Result<NewResultType, ErrorType> {
        return when (this) {
            is Success -> block(result)
            is Failure -> Failure(error)
        }
    }

    inline fun <NewResultType, NewErrorType> map(
        block: (Result<ResultType, ErrorType>) -> Result<NewResultType, NewErrorType>
    ): Result<NewResultType, NewErrorType> {
        return block(this)
    }

    inline fun <OtherResultType, CombinedResultType> combineWith(
        other: Result<OtherResultType, ErrorType>,
        block: (ResultType, OtherResultType) -> CombinedResultType
    ) : Result<CombinedResultType, ErrorType> {
        return when (this) {
            is Success -> when (other) {
                is Success -> Success(block(result, other.result))
                is Failure -> Failure(other.error)
            }
            is Failure -> Failure(error)
        }
    }

    /**
     * Runs the [block] providing the [Result.Failure.error] when the Result is a Failure with the
     * expectation that the client will exit the calling function before the end of the block. If
     * the client does not exit the calling function an [IllegalStateException] will be thrown.
     *
     * Otherwise, when the Result is a Success, returns the [Result.Success.result]
     */
    inline fun getResultOrDoAndReturnOnFailure(
        block: (ErrorType) -> Unit
    ): ResultType {
        if (this is Failure) {
            block(this.error)
        }
        @Suppress("UNREACHABLE_CODE") // Code is perfectly reachable
        return when (this) {
            is Failure -> throw IllegalStateException("Caller should have exited")
            is Success -> return this.result
        }
    }

    /**
     * Equals with a tighter bound for typing constraints.
     */
    @Suppress("CovariantEquals")
    fun equals(other: Result<ResultType, ErrorType>) = this == other as? Any
}
