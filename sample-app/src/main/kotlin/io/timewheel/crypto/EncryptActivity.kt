package io.timewheel.crypto

import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import io.timewheel.crypto.databinding.ActivityEncryptBinding
import io.timewheel.crypto.databinding.ItemAddInputBinding
import io.timewheel.crypto.databinding.ItemInputBinding
import io.timewheel.crypto.databinding.ItemOutputBinding
import io.timewheel.util.Result
import java.util.concurrent.atomic.AtomicReference

class SampleActivity : AppCompatActivity() {

    private lateinit var binding: ActivityEncryptBinding

    private lateinit var inputAdapter: InputAdapter
    private lateinit var outputAdapter: OutputAdapter

    private lateinit var cipher: AtomicReference<PasswordCipher>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityEncryptBinding.inflate(layoutInflater)
        setContentView(binding.root)

        cipher = AtomicReference(PasswordCipher.build {
            // Change cipher parameters here
        })

        inputAdapter = InputAdapter(applicationContext)
        binding.encryptInput.adapter = inputAdapter
        binding.encryptInput.layoutManager = LinearLayoutManager(
            this,
            LinearLayoutManager.VERTICAL,
            false
        )

        outputAdapter = OutputAdapter(applicationContext) {
            startActivity(DecryptActivity.intent(this, it))
        }
        binding.encryptOutput.adapter = outputAdapter
        binding.encryptOutput.layoutManager = LinearLayoutManager(
            this,
            LinearLayoutManager.VERTICAL,
            false
        )

        binding.encryptEncrypt.setOnClickListener {
            encryptInput()
        }
    }

    private fun encryptInput() {
        val password = AtomicReference(binding.encryptPassword.editableText.toString())
        Thread {
            val output = AtomicReference(cipher.get().encrypt(
                inputAdapter.input,
                password.get(),
                PasswordCipher.Options(
                    AES.default(),
                    PasswordKeyGenerator.Options(
                        RandomNonceGenerator.ofNonceSize(12),
                        PasswordKeyGenerator.Algorithm.PBKDF2WithHmacSHA256,
                        65536,
                        256
                    )
                )
            ))
            Handler(Looper.getMainLooper()).post {
                outputAdapter.setOutput(output.get().map { (it as Result.Success).result })
                outputAdapter.notifyDataSetChanged()
            }
        }.start()
    }
}

class InputAdapter(private val context: Context) : RecyclerView.Adapter<EncryptionInputViewHolder>() {

    val input = mutableListOf("")

    override fun getItemCount() = input.count() + 1

    override fun getItemViewType(position: Int): Int {
        if (position == itemCount - 1) {
            return TYPE_ADD_INPUT
        }
        return TYPE_INPUT
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): EncryptionInputViewHolder {
        return when (viewType) {
            TYPE_INPUT -> InputViewHolder.create(context.layoutInflater(), parent)
            TYPE_ADD_INPUT -> AddInputViewHolder.create(context.layoutInflater(), parent)
            else -> throw RuntimeException()
        }
    }

    override fun onBindViewHolder(holder: EncryptionInputViewHolder, position: Int) {
        if (holder is InputViewHolder) {
            holder.bind(input[position], { editIndex, newText ->
                input[editIndex] = newText
            }) { deleteIndex ->
                input.removeAt(deleteIndex)
                notifyItemRemoved(position)
            }
        } else if (holder is AddInputViewHolder) {
            holder.bind {
                input.add("")
                notifyItemInserted(itemCount-1)
            }
        }
    }

    companion object {
        private const val TYPE_INPUT = 1
        private const val TYPE_ADD_INPUT = 2
    }
}

abstract class EncryptionInputViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView)

class InputViewHolder(private val binding: ItemInputBinding) : EncryptionInputViewHolder(binding.root) {

    fun bind(text: String, editListener: (Int, String) -> Unit, deleteListener: (Int) -> Unit) {
        binding.inputString.setText(text)
        binding.inputString.addTextChangedListener(object: TextWatcher {
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                editListener(adapterPosition, s.toString())
            }

            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) { }
            override fun afterTextChanged(s: Editable?) {}
        })
        binding.inputDelete.setOnClickListener {
            deleteListener(adapterPosition)
        }
    }

    companion object {
        fun create(inflater: LayoutInflater, parent: ViewGroup): InputViewHolder {
            return InputViewHolder(ItemInputBinding.inflate(inflater, parent, false))
        }
    }
}

class AddInputViewHolder(private val binding: ItemAddInputBinding) : EncryptionInputViewHolder(binding.root) {

    fun bind(addListener: () -> Unit) {
        binding.addInputAdd.setOnClickListener {
            addListener()
        }
    }

    companion object {
        fun create(inflater: LayoutInflater, parent: ViewGroup): AddInputViewHolder {
            return AddInputViewHolder(ItemAddInputBinding.inflate(inflater, parent, false))
        }
    }
}

class OutputAdapter(
    private val context: Context,
    private val itemClickListener: (String) -> Unit
) : RecyclerView.Adapter<OutputViewHolder>() {

    private var output = listOf<String>()

    override fun getItemCount() = output.size

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): OutputViewHolder {
        return OutputViewHolder.create(context.layoutInflater(), parent)
    }

    override fun onBindViewHolder(holder: OutputViewHolder, position: Int) {
        holder.bind(output[position]) {
            itemClickListener(it)
        }
    }

    fun setOutput(output: List<String>) {
        this.output = output
    }
}

class OutputViewHolder(private val binding: ItemOutputBinding) : RecyclerView.ViewHolder(binding.root) {

    fun bind(output: String, clickListener: (String) -> Unit) {
        binding.outputText.text = output
        binding.root.setOnClickListener {
            clickListener(output)
        }
    }

    companion object {
        fun create(inflater: LayoutInflater, parent: ViewGroup): OutputViewHolder {
            return OutputViewHolder(ItemOutputBinding.inflate(inflater, parent, false))
        }
    }
}

private fun Context.layoutInflater(): LayoutInflater = getSystemService(LayoutInflater::class.java)
