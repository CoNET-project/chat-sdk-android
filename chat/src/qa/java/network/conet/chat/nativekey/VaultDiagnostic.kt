package network.conet.chat.nativekey

import android.content.Context
import android.util.Log
import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import java.security.KeyStore

/**
 * QA-only diagnostic of an unreadable wallet record, as one reason code (no value, no key material). Compiled only with `-PchatQaHooks`; it is not
 * in the production AAR and is reachable only from the shell's native QA page.
 *
 * It never opens the record and never reads a key value. It reads the snapshot (no reconcile, no write), reads the record file's shape, and asks
 * the keystore whether the wrap alias exists. Every input is tri-state: a read or keystore enumeration that throws is unknown (null), and an
 * unknown input never produces a definite cause. Codes:
 * - `wrap_key_missing`: the record is unreadable, the keystore enumerates normally, and the wrap alias is absent. Only this case is a missing key.
 * - `aead_failed`: the record is unreadable, the alias is present, and the record's shape is valid (so the failure is in the open).
 * - `marker_mismatch`: the marker does not match the records.
 * - `none`: the record is readable, or there is no record.
 * - `read_failed`: the snapshot is unknown (not computed yet, or the last computation threw), or an input needed for the cause could not be read.
 * - `other`: any other lock reason, or an unreadable record whose shape is invalid.
 */
object VaultDiagnostic {
    private const val TAG = "BeamioNativeQa"

    /** The thread name of VaultSnapshotRefresh (the one that computes the snapshot in the background). */
    private const val REFRESH_THREAD = "conet-vault-snapshot"

    const val NONE = "none"
    const val WRAP_KEY_MISSING = "wrap_key_missing"
    const val AEAD_FAILED = "aead_failed"
    const val MARKER_MISMATCH = "marker_mismatch"
    const val READ_FAILED = "read_failed"
    const val OTHER = "other"

    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")

    /**
     * Pure classification. [state] is null when the snapshot is unknown. [aliasPresent] is null when the keystore could not be enumerated or
     * queried. [recordShapeOk] is null when the record file could not be read.
     */
    internal fun classify(state: NativeWalletVault.State?, aliasPresent: Boolean?, recordShapeOk: Boolean?): String = when (state) {
        null -> READ_FAILED
        is NativeWalletVault.State.Ready, NativeWalletVault.State.NoKey -> NONE
        is NativeWalletVault.State.Locked -> when (state.reason) {
            "marker_mismatch" -> MARKER_MISMATCH
            "unreadable" -> when (aliasPresent) {
                null -> READ_FAILED
                false -> WRAP_KEY_MISSING
                true -> when (recordShapeOk) {
                    null -> READ_FAILED
                    true -> AEAD_FAILED
                    false -> OTHER
                }
            }
            else -> OTHER
        }
    }

    /**
     * The record's shape as openRecord reads it, without the key: record version, canonical EOA, and hex `sealed`. Null when the record could not
     * be read; false when it is absent or malformed.
     */
    internal fun recordShapeOk(rec: ByteArray?): Boolean? {
        if (rec == null) return false
        return try {
            val o = JSONObject(String(rec, Charsets.UTF_8))
            o.optInt("record", 0) == NativeWalletVault.RECORD_VERSION &&
                EOA_RE.matches(o.optString("eoa", "")) &&
                ConetChatCryptoUtil.hexToBytes(o.optString("sealed", "")) != null
        } catch (_: Exception) {
            false
        }
    }

    /** The keystore load: `ok`, or `fail:<exception class>`. Load only; no key is read, created or deleted. */
    internal fun keystoreLoad(): String = try {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        "ok"
    } catch (e: Exception) {
        "fail:${e.javaClass.simpleName}"
    }

    /** The wrap alias: `present`, `absent`, or `fail:<exception class>` when the keystore cannot be queried. */
    internal fun aliasCategory(): String = try {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(AndroidKeyWrap.KEY_ALIAS)) "present" else "absent"
    } catch (e: Exception) {
        "fail:${e.javaClass.simpleName}"
    }

    /** Presence and readability of one vault file: `absent`, `present`, or `fail:<exception class>`. Contents are never returned. */
    internal fun fileCategory(files: VaultFiles, name: String): String = try {
        if (files.read(name) == null) "absent" else "present"
    } catch (e: Exception) {
        "fail:${e.javaClass.simpleName}"
    }

    /** The snapshot refresh thread(s): thread state and the top three frames as class and method names. No values, no line numbers. */
    internal fun refreshThreads(): String = try {
        val threads = Thread.getAllStackTraces().filterKeys { it.name == REFRESH_THREAD }
        if (threads.isEmpty()) {
            "none"
        } else {
            threads.entries.joinToString(";") { (t, frames) ->
                "state=${t.state}:top=" + frames.take(3).joinToString(">") { "${it.className}.${it.methodName}" }
            }
        }
    } catch (e: Exception) {
        "fail:${e.javaClass.simpleName}"
    }

    /**
     * The reason code of the vault now, and one logcat line with the sub-causes: the snapshot kind, the keystore load, the alias, the category of
     * each vault file, the count of PGP migration names, and the refresh thread. Categories and exception class names only; no value and no path content.
     * Reads only: nothing is deleted, sealed, created or written.
     */
    /** The reason of an SDK state as a code: no value, no EOA. */
    internal fun describe(state: NativeWalletVault.State): String = when (state) {
        is NativeWalletVault.State.Ready -> "ready"
        is NativeWalletVault.State.NoKey -> "nokey"
        is NativeWalletVault.State.Locked -> "locked:${state.reason}"
    }

    /**
     * Second probe (call it after the first walletStatus answer, from the QA page; it writes logcat only). Two parts:
     * - a sampler for 30 seconds (every 2 seconds): the snapshot kind and the refresh thread (state and top frames), so a refresh that never
     *   finishes shows up with its stack;
     * - the SDK's own state, only when the intent file is absent. Reconcile removes files only for an intent (NativeWalletVault.reconcile reads the
     *   intent first and returns true when it is absent), so with no intent nothing is deleted or written. Run in a worker with a 10-second bound.
     *   When an intent is present the state is not read, and the line says so.
     * Nothing is sealed, created or written.
     */
    fun probe(context: Context) {
        val app = context.applicationContext
        val files = NativeWallet.migrationFiles(app)
        Thread({
            for (i in 1..15) {
                try {
                    Thread.sleep(2_000)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                val snap = if (NativeWallet.vault(app).snapshotState() == null) "unknown" else "set"
                Log.i(TAG, "vaultDiagSample t=${i * 2}s snapshot=$snap refreshThreads=${refreshThreads()}")
            }
        }, "beamio-qa-diag-sampler").apply { isDaemon = true }.start()
        val intent = fileCategory(files, NativeWalletVault.INTENT)
        if (intent != "absent") {
            Log.i(TAG, "vaultDiagState skipped=intent_$intent")
            return
        }
        val result = arrayOfNulls<String>(1)
        val worker = Thread({
            result[0] = try {
                describe(NativeWallet.vault(app).state())
            } catch (e: Exception) {
                "fail:${e.javaClass.simpleName}"
            }
        }, "beamio-qa-diag-state").apply { isDaemon = true }
        worker.start()
        worker.join(10_000)
        Log.i(TAG, "vaultDiagState result=${result[0] ?: "timeout"} worker=${if (worker.isAlive) "alive" else "done"}")
    }

    fun code(context: Context): String {
        val app = context.applicationContext
        val state = NativeWallet.vault(app).snapshotState()
        val files = NativeWallet.migrationFiles(app)
        val recRead = runCatching { files.read(NativeWalletVault.REC) }
        val recCat = recRead.fold({ if (it == null) "absent" else "present" }, { "fail:${it.javaClass.simpleName}" })
        val alias = aliasCategory()
        val aliasBool = when (alias) {
            "present" -> true
            "absent" -> false
            else -> null
        }
        val recShape: Boolean? = if (recRead.isFailure) null else recordShapeOk(recRead.getOrNull())
        val code = if (recRead.isFailure) READ_FAILED else classify(state, aliasBool, recShape)
        val pgpNames = runCatching { NativeWallet.migrationNames(app).count { it.startsWith("pgp.v1.") } }
            .fold({ it.toString() }, { "fail:${it.javaClass.simpleName}" })
        val snap = when (state) {
            null -> "unknown"
            is NativeWalletVault.State.Ready -> "ready"
            is NativeWalletVault.State.NoKey -> "nokey"
            is NativeWalletVault.State.Locked -> "locked:${state.reason}"
        }
        Log.i(
            TAG,
            "vaultDiag code=$code snapshot=$snap ks=${keystoreLoad()} alias=$alias rec=$recCat" +
                " mark=${fileCategory(files, NativeWalletVault.MARK)} mnem=${fileCategory(files, NativeWalletVault.MNEM)}" +
                " commit=${fileCategory(files, NativeWalletVault.COMMIT)} intent=${fileCategory(files, NativeWalletVault.INTENT)}" +
                " pgpNames=$pgpNames refreshThreads=${refreshThreads()}",
        )
        return code
    }
}
