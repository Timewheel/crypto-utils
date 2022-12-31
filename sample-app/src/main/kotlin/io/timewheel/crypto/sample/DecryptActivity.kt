package io.timewheel.crypto.sample

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.appcompat.app.AppCompatActivity
import io.timewheel.crypto.cipher.password.PasswordCipher.DecryptionError
import io.timewheel.crypto.cipher.AES
import io.timewheel.crypto.cipher.password.PasswordCipher
import io.timewheel.crypto.cipher.password.PasswordKeyGenerator
import io.timewheel.crypto.sample.databinding.ActivityDecryptBinding
import io.timewheel.util.Result
import java.util.concurrent.atomic.AtomicReference

class DecryptActivity : AppCompatActivity() {

    private lateinit var binding: ActivityDecryptBinding
    private lateinit var cipher: AtomicReference<PasswordCipher>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDecryptBinding.inflate(layoutInflater)
        setContentView(binding.root)

        cipher = AtomicReference(PasswordCipher.create())

        binding.decryptInput.text = intent.getStringExtra(INPUT_KEY)
        binding.decryptDecrypt.setOnClickListener {
            decrypt()
        }
    }

    private fun decrypt() {
        val input = AtomicReference(binding.decryptInput.text.toString())
        val password = AtomicReference(binding.decryptPassword.text.toString())
        Thread {
            val result = AtomicReference(
                cipher.get().decrypt(
                    input.get(),
                    password.get(),
                    PasswordCipher.DecodingOptions(
                        AES.GcmNoPadding(AES.KeyLength.L256),
                        PasswordKeyGenerator.Algorithm.PBKDF2WithHmacSHA256
                    )
                )
            )
            Handler(Looper.getMainLooper()).post {
                result.get().let { result ->
                    when (result) {
                        is Result.Success -> {
                            binding.decryptOutput.text = "Decryption Success!\n" +
                                "Original text: ${result.result.data.toString(Charsets.UTF_8)}"
                        }
                        is Result.Failure -> {
                            val message = when (result.error) {
                                is DecryptionError.BadFormat -> "Bad input format"
                                is DecryptionError.AlgorithmNotSupported -> "Algorithm not supported"
                                is DecryptionError.WrongPassword -> "Wrong password"
                                is DecryptionError.KeyGenerationError -> "Key generation error"
                                is DecryptionError.Other -> {
                                    val unexpected = result.error as DecryptionError.Other
                                    "Unexpected error: ${unexpected.exception}"
                                }
                            }
                            binding.decryptOutput.text = "Decryption Failed...\nError: $message"
                        }
                    }
                }
            }
        }.start()
    }

    companion object {
        private const val INPUT_KEY = "decrypt_input"

        fun intent(context: Context, input: String): Intent {
            val intent = Intent(context, DecryptActivity::class.java)
            intent.putExtra(INPUT_KEY, input)
            return intent
        }
    }
}
