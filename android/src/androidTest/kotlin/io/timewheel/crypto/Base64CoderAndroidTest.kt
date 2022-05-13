package io.timewheel.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Base64CoderAndroidTest : Base64CoderTest(){
    private lateinit var subject: Base64CoderAndroid

    @Before
    fun setUp() {
        subject = Base64CoderAndroid()
    }

    override fun subject(): Base64Coder = subject
}
