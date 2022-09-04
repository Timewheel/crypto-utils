package io.timewheel.crypto

import org.junit.Before

class Base64CoderJvmTest : Base64CoderTest() {
    private lateinit var subject: Base64CoderJvm

    @Before
    fun setUp() {
        subject = Base64CoderJvm()
    }

    override fun subject(): Base64Coder = subject
}
