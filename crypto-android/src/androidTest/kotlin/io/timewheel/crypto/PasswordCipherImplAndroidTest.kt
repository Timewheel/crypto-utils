package io.timewheel.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Before
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PasswordCipherImplAndroidTest : PasswordCipherImplTest() {
    private lateinit var subject: PasswordCipher

    @Before
    fun setUp() {
        subject = PasswordCipher.build { }
    }

    override fun subject() = subject
}
