package io.timewheel.crypto

import org.junit.Before

class AesGcmCipherImplJvmTest : AesGcmCipherImplTest() {
    private lateinit var subject: AesGcmCipher

    @Before
    fun setUp() {
        subject = AesGcmCipher.build { }
    }

    override fun subject() = subject
}
