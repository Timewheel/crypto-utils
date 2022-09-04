package io.timewheel.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Before
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AesGcmCipherImplAndroidTest : AesGcmCipherImplTest() {
    private lateinit var subject: AesGcmCipher

    @Before
    fun setUp() {
        subject = AesGcmCipher.build { }
    }

    override fun subject() = subject
}
