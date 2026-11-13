package network.conet.chat.nativekey

import android.content.Context
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors

/**
 * The native account-creation page (spec r3w §25.46). `nativeAccountCreateOpen` opens it in G0 only; the decision is
 * [NativeOpenRules.accountCreateOpen]. The shell sets [launcher] to show its page, and calls [NativeAccountCreate.confirm]
 * when the user confirms, and [pageClosed] when the page closes. Not registered is `not_supported`; registered but refused
 * is `not_available`. The page itself is the shell's. Nothing it shows or types passes through the bridge.
 */
object NativeAccountCreateHost {
    @Volatile
    var launcher: (() -> Boolean)? = null

    /** Set by the module, so results go out through the chat module event envelope. */
    @Volatile
    internal var events: ((JSONObject) -> Unit)? = null

    @Volatile
    private var pageReqId: Any? = null

    @Volatile
    private var resultSent = false

    /** `nativeAccountCreateOpen` (§25.46.2): `true` when the page is open. The `reqId` is kept for the result. */
    internal fun open(reqId: Any): Boolean {
        val show = launcher ?: return false
        pageReqId = reqId
        resultSent = false
        val opened = try {
            show()
        } catch (_: Exception) {
            false
        }
        if (!opened) {
            pageReqId = null
            return false
        }
        return true
    }

    /** The page was closed. Sends `cancelled` when no result was sent for this page (§25.46.6). */
    fun pageClosed() {
        val id = pageReqId ?: return
        if (!resultSent) emit(id, NativeAccountCreate.Code.CANCELLED, null)
        pageReqId = null
        resultSent = false
    }

    /** One result for the open page. `ok` ends the page; any other result keeps it open for a retry (§25.46.6). */
    internal fun finish(code: NativeAccountCreate.Code, eoa: String?) {
        val id = pageReqId ?: return
        emit(id, code, eoa)
        resultSent = true
        if (code == NativeAccountCreate.Code.OK) {
            pageReqId = null
            resultSent = false
        }
    }

    private fun emit(id: Any, code: NativeAccountCreate.Code, eoa: String?) {
        val payload = JSONObject()
            .put("type", "nativeAccountCreateResult")
            .put("reqId", id)
            .put("code", code.wire)
        if (code == NativeAccountCreate.Code.OK && eoa != null) payload.put("eoa", eoa)
        events?.invoke(payload)
    }
}

/**
 * Creation of the account key in native code (spec r3w §25.46.5). The phrase is generated, derived and dropped inside this
 * object. Only the code and the public address leave it. Nothing is stored, shown or logged except the key, which goes into
 * the vault through its write, readback and rollback.
 */
object NativeAccountCreate {
    enum class Code(val wire: String) {
        OK("ok"),
        CANCELLED("cancelled"),
        ALREADY_EXISTS("already_exists"),
        WRITE_FAILED("write_failed"),
        READBACK_FAILED("readback_failed"),
    }

    class Result(val code: Code, val eoa: String? = null)

    private val worker = Executors.newSingleThreadExecutor()

    /**
     * The user confirmed on the page (§25.46.5 step 1). Creates the key on a worker thread, reports the result to
     * [NativeAccountCreateHost], then calls [onResult]. The page stays open unless the code is `ok`.
     */
    fun confirm(context: Context, onResult: (Result) -> Unit = {}) {
        val app = context.applicationContext
        worker.execute {
            val result = try {
                create(NativeWallet.vault(app))
            } catch (_: Exception) {
                Result(Code.WRITE_FAILED)
            }
            NativeAccountCreateHost.finish(result.code, result.eoa)
            onResult(result)
        }
    }

    /**
     * Creates and stores a new account key (§25.46.5 steps 2 to 4). A record that already exists is never overwritten.
     * The caller's [entropy] is copied and zeroed; so are the derived key and the copy.
     */
    fun create(vault: NativeWalletVault, entropy: ByteArray = randomEntropy()): Result {
        val e = entropy.copyOf()
        try {
            if (vault.state() !is NativeWalletVault.State.NoKey) return Result(Code.ALREADY_EXISTS)
            val phrase = phraseOf(e)
            val key = MnemonicDerivation.deriveKey(phrase) ?: return Result(Code.WRITE_FAILED)
            try {
                val eoa = WalletAddress.fromPrivateKey(key) ?: return Result(Code.WRITE_FAILED)
                return when (vault.importKey(eoa, key, NativeWalletVault.SOURCE_NATIVE_CREATE)) {
                    NativeWalletVault.Import.OK -> Result(Code.OK, eoa)
                    NativeWalletVault.Import.ALREADY_PRESENT, NativeWalletVault.Import.RECORD_EXISTS ->
                        Result(Code.ALREADY_EXISTS)
                    NativeWalletVault.Import.READBACK_FAILED -> Result(Code.READBACK_FAILED)
                    // Store failures roll back inside the vault. A derived key that the vault refuses is treated the same:
                    // nothing was stored.
                    NativeWalletVault.Import.STORE_FAILED, NativeWalletVault.Import.BAD_KEY,
                    NativeWalletVault.Import.BAD_EOA, NativeWalletVault.Import.ADDRESS_MISMATCH,
                    -> Result(Code.WRITE_FAILED)
                }
            } finally {
                key.fill(0)
            }
        } finally {
            e.fill(0)
        }
    }

    /**
     * BIP-39 encoding of 16 bytes of entropy: 12 words, the last 4 bits being the first bits of SHA-256(entropy) (§25.26.1).
     * Only the phrase's derived key is used afterwards. The JVM string cannot be zeroed (same limit as MnemonicDerivation).
     */
    internal fun phraseOf(entropy: ByteArray): String {
        require(entropy.size == 16) { "entropy must be 16 bytes" }
        val checksum = MessageDigest.getInstance("SHA-256").digest(entropy)[0].toInt() and 0xff
        val bits = IntArray(132)
        for (i in 0 until 128) bits[i] = (entropy[i / 8].toInt() shr (7 - i % 8)) and 1
        for (i in 0 until 4) bits[128 + i] = (checksum shr (7 - i)) and 1
        return (0 until 12).joinToString(" ") { w ->
            var index = 0
            for (b in 0 until 11) index = (index shl 1) or bits[w * 11 + b]
            Bip39English.WORDS[index]
        }
    }

    private fun randomEntropy(): ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }
}
