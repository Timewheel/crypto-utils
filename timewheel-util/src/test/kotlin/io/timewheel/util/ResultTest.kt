package io.timewheel.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.fail

class ResultTest {
    @Test
    fun getResultOrDoAndReturnOnFailure_whenFailure_shouldThrowIfBlockDoesNotExit() {
        // Given
        val result: Result<String, Throwable> = Result.Failure(IllegalStateException())

        // Then
        assertThrows<IllegalStateException> {
            // When getResultOrDoAndReturnOnFailure doesn't return
            result.getResultOrDoAndReturnOnFailure {
                // Not returning here causes an exception to be thrown
            }
        }
    }

    @Test
    fun getResultOrDoAndReturnOnFailure_whenFailure_shouldExitScopeWhenReturning() {
        // Given
        val result: Result<String, Throwable> = Result.Failure(IllegalStateException())

        // When
        result.getResultOrDoAndReturnOnFailure {
            // Then
            return
        }

        // Returning within the inlined function block should exit the test function, not the block
        fail("Inlined function block return should have exited the test.")
    }

    @Test
    fun getResultOrDoAndReturnOnFailure_whenFailure_shouldPassErrorToBlock() {
        // Given
        val expectedError = IllegalStateException()
        val result: Result<String, Throwable> = Result.Failure(expectedError)

        // When
        result.getResultOrDoAndReturnOnFailure { error ->
            // Then
            assertEquals(expectedError, error)
            return
        }
    }

    @Test
    fun getResultOrDoAndReturnOnFailure_whenSuccess_shouldReturnValue() {
        // Given
        val expectedValue = "abc"
        val result: Result<String, Throwable> = Result.Success(expectedValue)

        // When
        val value = result.getResultOrDoAndReturnOnFailure {
            fail("Shouldn't call the block when the Result is a Success.")
        }

        // Then
        assertEquals(expectedValue, value)
    }
}
