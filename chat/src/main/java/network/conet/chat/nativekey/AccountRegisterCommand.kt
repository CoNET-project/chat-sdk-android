package network.conet.chat.nativekey

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

/**
 * The native side of `accountCreateRegister`: the page gives the BeamioTag and the user's password; this
 * checks the registry at one block, then signs and seals the `/api/addUser` payload ([AccountRegisterPayload]) and answers it for the page to forward.
 * The native layer never POSTs. The answer carries only `accountName`, `wallet`, `signMessage`, `recover[]` and `recoverCodeBase58` (once, no plaintext
 * copy is kept). The password is used for the sealing alone and zeroed before [run] returns; nothing in this file logs.
 *
 * Errors: bad_request, bad_tag, bad_password, tag_taken, already_registered, sign_failed, seal_failed,
 * not_ready, in_flight, not_available. `not_ready` carries the reason `passcode_not_provided` only when the passcode package is missing; an unreadable state has no reason.
 */
internal object AccountRegisterCommand {
    /** The request keys, exactly these four. */
    val REQUEST_KEYS: Set<String> = setOf("type", "reqId", "tag", "password")

    /** The keys of a success answer: anything else is `bad_response` on the page. */
    val RESULT_KEYS: Set<String> = setOf("accountName", "wallet", "signMessage", "recover", "recoverCodeBase58")

    sealed class Parsed {
        class Ok(val tag: String, val password: String) : Parsed()
        class Refused(val code: String) : Parsed()
    }

    /** The shape check, before any value is looked at: exactly the four keys, the two values strings; otherwise `bad_request`. */
    fun parse(body: JSONObject): Parsed {
        val keys = body.keys().asSequence().map { it.toString() }.toSet()
        if (keys != REQUEST_KEYS) return Parsed.Refused("bad_request")
        val tag = body.opt("tag") as? String ?: return Parsed.Refused("bad_request")
        val password = body.opt("password") as? String ?: return Parsed.Refused("bad_request")
        return Parsed.Ok(tag, password)
    }

    /** The account's material, read natively. [run] zeroes [key] and [phrase]. */
    class Material(val eoa: String, val key: ByteArray, val phrase: ByteArray?)

    sealed class MaterialRead {
        class Ready(val material: Material) : MaterialRead()

        /** The material is not available now: [passcodeMissing] when it is the passcode package, otherwise a storage state that cannot be read. */
        class NotReady(val passcodeMissing: Boolean) : MaterialRead()
    }

    /** The outcome: [error] is null for an answer; [reason] is only `passcode_not_provided`, only with `not_ready`. */
    class Outcome(val error: String?, val result: JSONObject?, val reason: String? = null) {
        val ok: Boolean get() = error == null
    }

    private fun err(code: String, reason: String? = null) = Outcome(code, null, reason)

    /** One registration payload at a time per account. */
    object Flight {
        private val inFlight: MutableSet<String> = ConcurrentHashMap.newKeySet()
        fun tryEnter(eoa: String): Boolean = inFlight.add(eoa.lowercase())
        fun exit(eoa: String) {
            inFlight.remove(eoa.lowercase())
        }
        internal fun resetForTests() = inFlight.clear()
    }

    /**
     * [material] reads the account; [registry] gives the owner of the tag (lower-case address or null), read at one block on both endpoints (a failure throws).
     * [password] is zeroed before this returns. Nothing is stored and nothing is sent.
     */
    fun run(
        tag: String,
        password: ByteArray,
        material: () -> MaterialRead,
        registry: (String) -> String?,
        build: (String, ByteArray, String, ByteArray, ByteArray) -> AccountRegisterPayload.Built = { n, p, e, k, ph -> AccountRegisterPayload.build(n, p, e, k, ph) },
        enter: (String) -> Boolean = Flight::tryEnter,
        exit: (String) -> Unit = Flight::exit,
    ): Outcome {
        var m: Material? = null
        var entered: String? = null
        try {
            val name = AccountRegisterPayload.normalizeName(tag) ?: return err("bad_tag")
            if (password.isEmpty()) return err("bad_password")
            m = when (val r = material()) {
                is MaterialRead.Ready -> r.material
                is MaterialRead.NotReady -> return err("not_ready", if (r.passcodeMissing) NoKeyGate.NOT_READY_PASSCODE_NOT_PROVIDED else null)
            }
            if (!enter(m.eoa)) return err("in_flight")
            entered = m.eoa
            val phrase = m.phrase ?: return err("seal_failed")
            return when (AccountRegisterPayload.decide(m.eoa) { registry(name) }) {
                // A read that fails is unknown: retryable, never tag_taken.
                is AccountRegisterPayload.Registry.Unreadable -> err("not_ready")
                is AccountRegisterPayload.Registry.Taken -> err("tag_taken")
                // The account already owns this tag (same-block read on both endpoints): nothing is generated (a second payload would overwrite the
                // recover the user was shown) and the page calls no addUser. This is an additional case beyond the base error table.
                is AccountRegisterPayload.Registry.AlreadyRegistered -> err("already_registered")
                is AccountRegisterPayload.Registry.Free -> when (val built = build(name, password, m.eoa, m.key, phrase)) {
                    // An address the phrase does not derive is sign_failed; a failed random or KDF, and a missing plain phrase, are seal_failed.
                    is AccountRegisterPayload.Built.Refused -> err(
                        when (built.code) {
                            "sign_failed", "phrase_mismatch" -> "sign_failed"
                            "bad_request" -> "bad_request"
                            else -> "seal_failed"
                        },
                    )
                    is AccountRegisterPayload.Built.Ok -> {
                        val recover = JSONArray()
                        built.recover.forEach { recover.put(JSONObject().put("hash", it.hash).put("encrypto", it.encrypto)) }
                        Outcome(
                            null,
                            JSONObject().put("accountName", built.accountName).put("wallet", built.wallet).put("signMessage", built.signMessage)
                                .put("recover", recover).put("recoverCodeBase58", built.recoverCode),
                        )
                    }
                }
            }
        } catch (_: Exception) {
            return err("not_ready")
        } finally {
            password.fill(0)
            m?.key?.fill(0)
            m?.phrase?.fill(0)
            entered?.let(exit)
        }
    }

    /**
     * The production material: a ready vault account with its stored phrase, else a plain store set. Never the vault's monitor on the caller's thread
     * for the state (the snapshot only; with none yet it asks for one and answers unknown).
     */
    fun productionMaterial(ctx: Context): MaterialRead {
        val vault = NativeWallet.vault(ctx)
        val snap = vault.snapshotState()
        if (snap == null) {
            VaultSnapshotRefresh.schedule(ctx)
            return MaterialRead.NotReady(false)
        }
        when {
            snap is NativeWalletVault.State.Ready -> {
                val key = vault.unlock() ?: return MaterialRead.NotReady(false)
                val phrase = (vault.mnemonicOf() as? NativeWalletVault.MnemonicRead.Stored)?.phrase?.toByteArray(Charsets.UTF_8)
                return MaterialRead.Ready(Material(snap.eoa, key, phrase))
            }
            snap is NativeWalletVault.State.Locked -> return MaterialRead.NotReady(snap.reason == NativeWalletVault.PASSCODE_REQUIRED)
            else -> Unit
        }
        return when (val r = StoreAwareAccount.resolveOnDevice(ctx)) {
            is StoreAwareAccount.Resolution.NotReady -> MaterialRead.NotReady(r.reason == NoKeyGate.NOT_READY_PASSCODE_REQUIRED)
            StoreAwareAccount.Resolution.NoKey -> MaterialRead.NotReady(false)
            is StoreAwareAccount.Resolution.Account -> {
                val current = StoreAwareAccount.storeCurrent(ctx)
                val found = current as? MnemonicSetStore.Current.Found
                if (found == null || found.kind != MnemonicSetStore.Kind.PLAIN) {
                    MaterialRead.NotReady(false)
                } else {
                    val key = StoreKeyAdapter.plainKey(current) ?: return MaterialRead.NotReady(false)
                    MaterialRead.Ready(Material(found.eoa, key, found.value.toByteArray(Charsets.UTF_8)))
                }
            }
        }
    }

    /** The production registry read: the owner of the tag, at one block on both endpoints. A failure throws (never "no owner"). */
    fun productionRegistry(name: String): String? =
        AccountRegistryRead.ownerAgreed(AccountRegistryRead.current, { ep -> AddressPgpRead.HttpRpc(ep.url, ep.timeoutMs) }, name)
}
