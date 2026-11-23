package network.conet.chat.nativekey

import org.json.JSONObject
import java.io.File
import java.io.IOException

/**
 * The two-state mnemonic store (2026-11-22, step (2)). One directory of the app's private
 * no-backup area; no device-protection key. Two kinds of record, decided by PWA:
 *  - `plain`: a validated phrase of a passcode-less account, in the set of its EOA. The same phrase again is idempotent; a different phrase for
 *    the same EOA is refused (a mnemonic of one EOA does not change).
 *  - `v3`: the v3 envelope of a passcode-protected account, kept as the original ciphertext (never decrypted here). A passcode change writes a new
 *    version beside the older ones; the same envelope again is idempotent.
 * Each set is a file per EOA and kind and version: `set.<eoa>.plain.<n>.v1`, `set.<eoa>.v3.<n>.v1`. The `current` pointer names the set in use:
 * `eoa|plain|n` or `eoa|v3|n`. Switching the kind of one EOA (plain → v3 → plain) writes the new version and moves the pointer; the older sets stay.
 *
 * A write is staged: a temp file is written and read back (stage); the pointer moves only at commit, after the caller has done its own write
 * (for the phrase path, the vault). An abort removes only the temp file. Old sets are never removed or rewritten.
 */
internal class MnemonicSetStore(private val dir: File) {

    companion object {
        /** The store's directory under the app's no-backup files area. */
        const val DIRECTORY = "mnemonic_sets_v1"

        /**
         * The identity_cleared marker of the store: written when an identity clear completes. It holds no
         * secret and deletes no set. While it is present the store answers as absent (no automatic re-adoption, no pointer write); it is removed only
         * by an explicit write of a new set (a restore, an import or a sync), after that write commits.
         */
        const val IDENTITY_CLEARED = "identity_cleared.v1"

        /** Writes [value] to a temp file beside [target], reads it back, and renames it over [target] (the pointer move). */
        internal fun writeVerified(target: File, value: String) {
            val tmp = File(target.parentFile, target.name + ".tmp")
            tmp.writeText(value, Charsets.UTF_8)
            if (tmp.readText(Charsets.UTF_8) != value) {
                tmp.delete()
                throw ReadbackMismatch("readback mismatch")
            }
            if (!tmp.renameTo(target)) {
                tmp.delete()
                throw IOException("rename failed")
            }
        }
    }

    /** A read-back that did not equal what was written: an unknown state (`internal_state`), as opposed to an ordinary write error (`storage_write`). */
    class ReadbackMismatch(message: String) : IOException(message)

    /** How a commit ended: it succeeded, an ordinary write error stopped it (`storage_write`), or a read-back mismatch did (`internal_state`). */
    enum class Commit { OK, WRITE_FAILED, READBACK_MISMATCH }

    enum class Kind(val tag: String) { PLAIN("plain"), V3("v3") }

    /** The current set: the EOA, the kind, the version, and the value (the phrase for PLAIN, the envelope JSON for V3). */
    sealed class Current {
        object Absent : Current()
        class Found(val eoa: String, val kind: Kind, val value: String, val version: Int = 0) : Current()
        class Unknown(val reason: String) : Current()
    }

    sealed class Write {
        class Stored(val eoa: String, val kind: Kind, val version: Int = 0) : Write()
        object Refused : Write()
        class Failed(val reason: String) : Write()
    }

    /** A staged write: the new version is written and read back, but the pointer has not moved. [commit] moves it; [abort] removes the temp file. */
    class Staged internal constructor(
        val eoa: String,
        val kind: Kind,
        val version: Int,
        private val tmp: File?,
        private val target: File,
        /** The pointer text this write moves `current` to: `<eoa>|<kind>|<n>`. */
        val pointerValue: String,
        private val pointer: File,
        /** What the set file must hold: the independent read-back after the file is in place compares it before the pointer moves. */
        private val expected: String,
    ) {
        /** True when this staged write adds a new file (a new phrase or a new envelope version); false when the same content already exists. */
        val isNew: Boolean get() = tmp != null

        /** Moves the file into place (when it is new) and then the pointer; false when either cannot be done (nothing else is changed). */
        fun commit(): Boolean = commitOutcome() == Commit.OK

        /** [commit] with the reason a failure is told by: an ordinary write error, or a read-back that did not match. */
        fun commitOutcome(): Commit {
            return try {
                if (tmp != null) {
                    if (target.exists()) return Commit.WRITE_FAILED
                    if (!tmp.renameTo(target)) return Commit.WRITE_FAILED
                }
                // Independent read-back of the set the pointer is about to name: only a set that reads back equal becomes current. A mismatch
                // moves nothing and deletes nothing (the older current and the older sets stay).
                if (target.readText(Charsets.UTF_8) != expected) return Commit.READBACK_MISMATCH
                writeVerified(pointer, pointerValue)
                // An explicit write of a new set releases the identity_cleared state (the explicit restore or import).
                runCatching { File(pointer.parentFile, IDENTITY_CLEARED).delete() }
                Commit.OK
            } catch (_: ReadbackMismatch) {
                Commit.READBACK_MISMATCH
            } catch (_: IOException) {
                Commit.WRITE_FAILED
            }
        }

        /** Removes the temp file of this staged write. The pointer and the older sets are not touched. */
        fun abort() {
            tmp?.delete()
        }
    }

    /** The result of staging: a staged write, a refusal (a different phrase for the same plain EOA), or a failure. */
    sealed class Stage {
        class Ready(val staged: Staged) : Stage()
        object Refused : Stage()
        /** The account has a saved v3 set: a plaintext write never replaces its protection, so nothing is staged (the answer is `unchanged`). */
        object V3Present : Stage()
        /**
         * An envelope that could not be verified (no passcode) differs from every v3 version the same account already has (a changed ct, or a legitimate
         * re-seal): it is not staged, so nothing is written, no version is added and current does not move (M6 v3.3).
         */
        object Unverifiable : Stage()
        class Failed(val reason: String) : Stage()
    }

    private fun plainFile(eoa: String, n: Int) = File(dir, "set.${eoa.lowercase()}.plain.$n.v1")
    private fun v3File(eoa: String, n: Int) = File(dir, "set.${eoa.lowercase()}.v3.$n.v1")
    private val currentFile get() = File(dir, "current.v1")

    /**
     * Whether any v3 set of [eoa] is saved, current or not. null when the directory cannot be read (unknown, never "no set"). A plaintext sync for an
     * account that has a v3 set must not replace its protection, so the caller asks this before it stages a plaintext set.
     */
    fun hasV3Set(eoa: String): Boolean? {
        if (!dir.exists()) return false
        val names = dir.list() ?: return null
        val prefix = "set.${eoa.lowercase()}.v3."
        return names.any { it.startsWith(prefix) && it.endsWith(".v1") }
    }

    /** The newest version of [eoa] for [kind] on disk, or 0. */
    private fun newest(eoa: String, kind: Kind): Int {
        val prefix = "set.${eoa.lowercase()}.${kind.tag}."
        return (dir.list() ?: return 0).mapNotNull { name ->
            if (!name.startsWith(prefix) || !name.endsWith(".v1")) return@mapNotNull null
            name.removePrefix(prefix).removeSuffix(".v1").toIntOrNull()
        }.maxOrNull() ?: 0
    }

    /** Stages a validated phrase for [eoa]. The derived address must equal [eoa]; the same phrase again is idempotent; a different one is refused. */
    fun stagePlain(eoa: String, phrase: String): Stage {
        val derived = MnemonicDerivation.deriveKey(phrase)?.let { WalletAddress.fromPrivateKey(it) }?.lowercase()
        if (derived == null || derived != eoa.lowercase()) return Stage.Refused
        return try {
            if (!dir.exists() && !dir.mkdirs()) return Stage.Failed("dir_unavailable")
            val e = eoa.lowercase()
            // Any v3 set of this account, current or not, keeps the plaintext out: the passcode protection changes only through the passcode commands.
            when (hasV3Set(e)) {
                true -> return Stage.V3Present
                null -> return Stage.Failed("write_failed")
                false -> Unit
            }
            val n = newest(e, Kind.PLAIN)
            if (n > 0) {
                if (plainFile(e, n).readText(Charsets.UTF_8) == phrase) {
                    return Stage.Ready(Staged(e, Kind.PLAIN, n, null, plainFile(e, n), "$e|plain|$n", currentFile, phrase))
                }
                return Stage.Refused
            }
            Stage.Ready(stageNew(e, Kind.PLAIN, 1, phrase) { plainFile(e, it) })
        } catch (_: ReadbackMismatch) {
            Stage.Failed("readback_mismatch")
        } catch (_: IOException) {
            Stage.Failed("write_failed")
        }
    }

    /**
     * Stages the v3 envelope [env]. An envelope byte-identical to a v3 version of the same EOA (current or older) adds nothing: idempotent, and only
     * the pointer moves when that account is not current. Otherwise it is written as a new version and the pointer moves to it at commit; older sets
     * are never removed. When [verified] is false (no passcode, so the envelope cannot be opened here) and the account already has a v3 version, an
     * envelope with different bytes is not staged ([Stage.Unverifiable]): unverifiable material never replaces what is saved. An account with no set
     * at all takes it as its first version. A verified envelope (the passcode opened it and the derived address matched) is added as a new version.
     */
    fun stageEnvelope(env: MnemonicCipherV3.Envelope, verified: Boolean = true): Stage {
        val json = JSONObject()
            .put("v", env.v).put("mode", env.mode).put("eoa", env.eoa.lowercase()).put("kdf", env.kdf)
            .put("salt", env.saltB64).put("iv", env.ivB64).put("alg", env.alg).put("ct", env.ctB64)
            .toString()
        val e = env.eoa.lowercase()
        return try {
            if (!dir.exists() && !dir.mkdirs()) return Stage.Failed("dir_unavailable")
            val cur = current()
            if (cur is Current.Found && cur.kind == Kind.V3 && cur.eoa == e && cur.value == json) {
                return Stage.Ready(Staged(e, Kind.V3, cur.version, null, v3File(e, cur.version), "$e|v3|${cur.version}", currentFile, json))
            }
            // Switching back to an account whose identical envelope is already saved (an older version): only the pointer moves, no set byte changes.
            val older = (dir.list() ?: emptyArray()).mapNotNull { name ->
                val prefix = "set.$e.v3."
                if (!name.startsWith(prefix) || !name.endsWith(".v1")) return@mapNotNull null
                name.removePrefix(prefix).removeSuffix(".v1").toIntOrNull()
            }.sorted().firstOrNull { v -> v3File(e, v).readText(Charsets.UTF_8) == json }
            if (older != null) {
                return Stage.Ready(Staged(e, Kind.V3, older, null, v3File(e, older), "$e|v3|$older", currentFile, json))
            }
            if (!verified) {
                when (hasV3Set(e)) {
                    true -> return Stage.Unverifiable
                    null -> return Stage.Failed("write_failed")
                    false -> Unit
                }
            }
            val n = newest(e, Kind.V3)
            Stage.Ready(stageNew(e, Kind.V3, n + 1, json) { v3File(e, it) })
        } catch (_: ReadbackMismatch) {
            Stage.Failed("readback_mismatch")
        } catch (_: IOException) {
            Stage.Failed("write_failed")
        }
    }

    private fun stageNew(eoa: String, kind: Kind, n: Int, value: String, file: (Int) -> File): Staged {
        val target = file(n)
        val tmp = File(target.parentFile, target.name + ".tmp")
        tmp.writeText(value, Charsets.UTF_8)
        if (tmp.readText(Charsets.UTF_8) != value) {
            tmp.delete()
            throw ReadbackMismatch("readback mismatch")
        }
        return Staged(eoa, kind, n, tmp, target, "$eoa|${kind.tag}|$n", currentFile, value)
    }

    /** Stages and commits a plain phrase in one step (no other write to order). */
    fun writePlain(eoa: String, phrase: String): Write = when (val s = stagePlain(eoa, phrase)) {
        is Stage.Refused -> Write.Refused
        is Stage.V3Present -> Write.Refused
        is Stage.Unverifiable -> Write.Refused
        is Stage.Failed -> Write.Failed(s.reason)
        is Stage.Ready -> if (s.staged.commit()) Write.Stored(s.staged.eoa, Kind.PLAIN, s.staged.version) else Write.Failed("write_failed")
    }

    /** Stages and commits a v3 envelope in one step. */
    fun writeEnvelope(env: MnemonicCipherV3.Envelope): Write = when (val s = stageEnvelope(env)) {
        is Stage.Refused -> Write.Refused
        is Stage.V3Present -> Write.Refused
        is Stage.Unverifiable -> Write.Refused
        is Stage.Failed -> Write.Failed(s.reason)
        is Stage.Ready -> if (s.staged.commit()) Write.Stored(s.staged.eoa, Kind.V3, s.staged.version) else Write.Failed("write_failed")
    }

    /** The current set, read back from the pointer and the set file. Any read failure is Unknown (never Absent). */
    /** Writes the identity_cleared marker (no secret, no set and no pointer changed). True when the marker is written. */
    fun markIdentityCleared(): Boolean = try {
        if (!dir.exists() && !dir.mkdirs()) false
        else {
            writeVerified(File(dir, IDENTITY_CLEARED), "cleared")
            true
        }
    } catch (_: IOException) {
        false
    }

    /** True while the identity_cleared marker is present. Unreadable counts as present (fail closed). */
    fun identityCleared(): Boolean = try {
        File(dir, IDENTITY_CLEARED).exists()
    } catch (_: Exception) {
        true
    }

    fun current(): Current {
        // after an identity clear the retained sets are not re-adopted automatically; the store answers as absent.
        if (identityCleared()) return Current.Absent
        val ptr = try {
            if (!currentFile.exists()) return Current.Absent
            currentFile.readText(Charsets.UTF_8).trim()
        } catch (_: IOException) {
            return Current.Unknown("pointer_unreadable")
        }
        val parts = ptr.split("|")
        if (parts.size != 3) return Current.Unknown("pointer_invalid")
        val eoa = parts[0]
        if (!Regex("^0x[0-9a-f]{40}$").matches(eoa)) return Current.Unknown("pointer_invalid")
        val kind = Kind.values().firstOrNull { it.tag == parts[1] } ?: return Current.Unknown("pointer_invalid")
        val n = parts[2].toIntOrNull()?.takeIf { it >= 1 } ?: return Current.Unknown("pointer_invalid")
        val f = if (kind == Kind.PLAIN) plainFile(eoa, n) else v3File(eoa, n)
        return try {
            if (!f.exists()) return Current.Unknown("set_missing")
            Current.Found(eoa, kind, f.readText(Charsets.UTF_8), n)
        } catch (_: IOException) {
            Current.Unknown("set_unreadable")
        }
    }

}
