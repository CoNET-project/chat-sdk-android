package network.conet.chat.nativekey

import android.content.Context
import network.conet.chat.BeamioChatPgpStore
import org.json.JSONObject
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Migration of the legacy PGP private key into the SDK's secure store (spec r3bg; earlier r3ay §25.52D, §25.52E, §25.52, §25.52A,
 * §25.52C, §25.52I; U5).
 *
 * The sources are the SDK's own account record L, read inside the SDK, and the page store P, which the shell reads natively and
 * hands in as bytes (§25.52D.3). The target is N, one sealed item per account. The success marker M is written last. Nothing here
 * takes a key, a passphrase or an old public key from the bridge, and nothing here generates a key. The migration never removes or
 * changes L. Results are codes only.
 */
internal object PgpMigrationPolicy {
    /**
     * Approval of the Android OpenPGP functions behind the migration (§25.52.10, §25.52E.8). The approval of 2026-11-14 covers
     * iOS only. The Android (BouncyCastle) functions are not approved, so the production path answers `verify_unavailable` and
     * writes nothing. The tests run the same pipeline with an approving [MigrationCrypto].
     */
    const val OPENPGP_APPROVED = false

    const val CHALLENGE_LABEL = "beamio.pgp.migrate.challenge.v1\n"
    const val PRECHECK_LABEL = "beamio.pgp.migrate.precheck.v1\n"
    const val PRECHECK_MESSAGE = "beamio pgp migrate precheck"
    const val SIG_TYPE = 0x01
    const val WORKSPACE = "default"
    const val SOURCE_LEGACY = "legacyPwa"
    const val NONCE_BYTES = 32

    /** The failure set of §25.52D.4: a last result in this set makes the state `failed`. */
    val FAILED_CODES: Set<String> = setOf(
        "fingerprint_mismatch",
        "legacy_unreadable",
        "account_mismatch",
        "chain_unavailable",
        "write_failed",
        "reread_failed",
        "challenge_failed",
        "verify_unavailable",
        "store_missing",
    )

    internal val EOA_RE = Regex("^0x[0-9a-f]{40}$")
    internal val WORKSPACE_RE = Regex("^[a-z0-9_-]{1,32}$")
}

/**
 * The result codes of §25.52.5, the unregister codes of §25.52I.8 and the states of §25.52D.4. [wire] is the code sent to the page.
 */
enum class MigrationCode(val wire: String) {
    OK("ok"),
    ALREADY_VERIFIED("already_verified"),
    NONE("none"),
    STORE_MISSING("store_missing"),
    LEGACY_UNREADABLE("legacy_unreadable"),
    ACCOUNT_MISMATCH("account_mismatch"),
    FINGERPRINT_MISMATCH("fingerprint_mismatch"),
    CHAIN_UNAVAILABLE("chain_unavailable"),
    WRITE_FAILED("write_failed"),
    REREAD_FAILED("reread_failed"),
    CHALLENGE_FAILED("challenge_failed"),
    VERIFY_UNAVAILABLE("verify_unavailable"),
    UNREGISTER_REFUSED("unregister_refused"),
    BAD_REQUEST("bad_request"),
    BUSY("busy"),
}

/** [fp] is the full lower-case fingerprint. The page only ever gets its first 16 characters. */
class MigrationResult internal constructor(val code: MigrationCode, val fp: String? = null)

/**
 * The page store's PGP fields (P), handed in by the shell in the same process (§25.52D.3, §25.52B.2). The shell reads them natively
 * from the WebView store and does not pass them through the WebView. The arrays are zero-filled after the run, whatever its result.
 * [keyId] is carried with the record (§25.52D.3); the check itself uses the key's own identifier.
 */
class LegacyPgpSource(
    val privateArmor: ByteArray,
    val publicArmor: ByteArray,
    val keyId: String,
) {
    /** Runs [block] with the record for [eoa], then zero-fills the arrays. */
    internal fun <T> useAs(eoa: String, block: (LegacyRecord) -> T): T = try {
        block(LegacyRecord(eoa, privateArmor, publicArmor))
    } finally {
        wipe()
    }

    /** Zero-fills both armor arrays. Called after use, and when the source is not used at all. */
    internal fun wipe() {
        privateArmor.fill(0)
        publicArmor.fill(0)
    }

    companion object {
        /** The size limit of each armor (§25.52D.3). A larger armor is `legacy_unreadable`. */
        const val MAX_BYTES = 64 * 1024
    }
}

/**
 * A run stopped by an interruption (process death, power loss, lock). It produces no result event (§25.52.12). The next call to the
 * same account resumes from the stored state. This is an [Error], so no handler in the pipeline swallows it. It is the
 * `CheckpointInterrupt` of §25.52C.4.
 */
internal class PgpMigrationInterrupted : Error("pgp migration interrupted")

/**
 * The checkpoints of §25.52C.4. A checkpoint closure is an internal parameter of [PgpMigrationEngine.run] and
 * [PgpMigrationEngine.unregister]. The public entries pass the default closure, which does nothing. A closure may throw
 * [PgpMigrationInterrupted] to stop the run without an event.
 */
internal enum class Stage {
    AFTER_STAGED_WRITE,
    AFTER_REREAD,
    AFTER_CHALLENGE,
    BEFORE_MARKER_WRITE,
    AFTER_MARKER_WRITE,
    AFTER_RECORD_INIT,
    AFTER_MARKER_DELETED,
}

/** A legacy record, from L or from P. The private and public armor are bytes, so they can be zero-filled. */
internal class LegacyRecord(val eoa: String, val privateArmor: ByteArray, val publicArmor: ByteArray) {
    fun privateText(): String = String(privateArmor, Charsets.UTF_8)

    fun publicText(): String = String(publicArmor, Charsets.UTF_8)
}

/** The target N: the account's private armor and the fingerprint it had when written. */
internal class StagedItem(val eoa: String, val fp: String, val privateArmor: String)

/** The success marker M. [fp] is the full fingerprint; the stored value is never a key. */
internal class MarkerItem(val fp: String, val source: String, val verifiedAt: Long)

/** The chain's view of the account's registered PGP fingerprint (AddressPGP, read only). */
internal sealed class ChainAnswer {
    class Found(val fp: String) : ChainAnswer()

    /** No record, or an empty, `0x`, or zero-only public key (§25.52I.7 case 2). */
    object Absent : ChainAnswer()

    /** A registered public key that does not parse (§25.52I.7 case 3). */
    object Unparseable : ChainAnswer()

    /** The read failed or the SDK is not configured (§25.52I.7 case 1). */
    object Unavailable : ChainAnswer()
}

internal interface MigrationLegacy {
    /** `null` when there is no record. Never writes. */
    fun read(): LegacyRecord?
}

internal interface MigrationStaged {
    /** `null` when absent. Throws [IOException] when present but unreadable. */
    fun read(): StagedItem?

    /** Writes the item in one step. On failure the earlier item is unchanged. Throws [IOException]. */
    fun write(item: StagedItem)

    fun delete()
}

internal interface MigrationMarker {
    /** `null` when absent. Throws [IOException] when present but unreadable. */
    fun read(): MarkerItem?

    /** Writes the marker in one step. Throws [IOException]. */
    fun write(item: MarkerItem)

    fun delete()
}

/** The last result of a complete run, non-secret (§25.52D.4). Written only when a run finishes, never on an interruption. */
internal interface MigrationLastCode {
    /** `null` when there is none. */
    fun read(): String?

    fun write(code: String)

    fun delete()
}

internal fun interface MigrationChain {
    fun registered(eoa: String): ChainAnswer
}

/**
 * The recovery sources of §25.52C.3. Unregister needs at least one: L (a separate source), P readable natively (§25.52B.2), or a
 * chain backup that is registered and restorable by P-IMP-PGP (§25.30).
 */
internal interface MigrationRecovery {
    /** Source P can be read natively. The shell's reader is not in this build, so production answers `false`. */
    fun pReadable(): Boolean

    /** The account's chain backup is registered and can be restored. Production answers `false` when unsure. */
    fun chainRegistered(): Boolean
}

/**
 * Serializes the runs and the unregister of one account (§25.52I.8, code `busy`). [tryRun] returns `null` without running [block]
 * when another run of the same account is in progress.
 */
internal interface MigrationLock {
    fun <T> tryRun(eoa: String, block: () -> T): T?
}

/** The process-wide lock: one account at a time, whichever command starts it. */
internal object ProcessMigrationLock : MigrationLock {
    private val running: MutableSet<String> = ConcurrentHashMap.newKeySet()

    override fun <T> tryRun(eoa: String, block: () -> T): T? {
        if (!running.add(eoa)) return null
        try {
            return block()
        } finally {
            running.remove(eoa)
        }
    }
}

/**
 * The OpenPGP functions the migration uses. Keys are passed as armor and never returned. A signature is returned as armor.
 * [approved] is the approval gate of §25.52.10; the pipeline checks it before any signing.
 */
internal interface MigrationCrypto {
    fun approved(): Boolean

    /** The lower-case fingerprint of a private armor, or `null` when it does not parse. */
    fun secretFingerprint(armor: String): String?

    /** The lower-case fingerprint of a public armor, or `null` when it does not parse or is a private block. */
    fun publicFingerprint(armor: String): String?

    /** The first subkey ID of a private armor, or `null`. */
    fun keyId(armor: String): String?

    /** A detached signature (armored) over [label] and [message], with an empty passphrase. `null` on failure. */
    fun sign(armor: String, label: String, message: ByteArray): String?

    fun verify(armor: String, label: String, message: ByteArray, signature: String): Boolean
}

/**
 * The page wallet copy of one account, as the unregister sees it (§25.52H.2 rule 5, §25.52J.3): the W fields (`profiles[*].privateKeyArmor`,
 * `mnemonic`, `walletVault.mnemonic`) are removed only by the unregister, after the recovery check. [present] is true when a W field is
 * there or the copy cannot be read. [remove] removes the W fields and keeps the rest of the copy.
 */
internal interface MigrationWallet {
    fun present(): Boolean

    /** Throws [IOException] when the copy cannot be written. */
    fun remove()
}

/** No page copy: nothing to remove. The engine's default, used by the vectors. */
internal object NoPageWallet : MigrationWallet {
    override fun present(): Boolean = false

    override fun remove() = Unit
}

/**
 * The migration pipeline for one account (§25.52.6, §25.52A.2, §25.52D.4, §25.52I) and the unregister (§25.52C.3, §25.52I.8). Each
 * call is one run; a run that is interrupted leaves the stored state as it was at that point, and the next call resumes from it. A
 * run returns exactly one [MigrationResult] or throws [PgpMigrationInterrupted].
 *
 * [primary] is the page store's record P, or `null` to use L (§25.52D.3). When both are present and both readable, their public
 * fingerprints must agree (SR-03).
 */
internal class PgpMigrationEngine(
    private val eoa: String,
    private val legacy: MigrationLegacy,
    private val primary: LegacyRecord?,
    private val staged: MigrationStaged,
    private val marker: MigrationMarker,
    private val lastCode: MigrationLastCode,
    private val chain: MigrationChain,
    private val crypto: MigrationCrypto,
    private val recovery: MigrationRecovery,
    private val lock: MigrationLock,
    private val wallet: MigrationWallet = NoPageWallet,
    private val random: SecureRandom = SecureRandom(),
    private val now: () -> Long = { System.currentTimeMillis() },
) {
    /** Stops the run with a code. Internal only; [run] turns it into a result. */
    private class Stop(val code: MigrationCode, val fp: String? = null) : RuntimeException()

    /**
     * `none`, `pending`, `failed` or `verified`, read only (§25.52D.4, §25.52I.6). `verified` needs M and N equal, and L equal to N
     * when L exists. M and N equal but L different is `failed` whatever the last code (fail closed).
     */
    fun state(): String {
        val m = try {
            marker.read()
        } catch (_: IOException) {
            return "pending"
        }
        val n = try {
            staged.read()
        } catch (_: IOException) {
            return "pending"
        }
        if (m != null && n != null && n.fp == m.fp) {
            val l = legacy.read() ?: return "verified"
            return if (crypto.publicFingerprint(l.publicText()) == n.fp) "verified" else "failed"
        }
        if (readLastCode()?.let { it in PgpMigrationPolicy.FAILED_CODES } == true) return "failed"
        if (n != null) return "pending"
        return "none"
    }

    /**
     * One run, under the account lock. Records the result as the last code when the run finishes. An interrupted run records nothing
     * (§25.52D.4). A run that finds the account busy returns `busy` and changes nothing.
     */
    fun run(checkpoint: (Stage) -> Unit = {}): MigrationResult = lock.tryRun(eoa) {
        val result = try {
            execute(checkpoint)
        } catch (stop: Stop) {
            MigrationResult(stop.code, stop.fp)
        }
        runCatching { lastCode.write(result.code.wire) }
        result
    } ?: MigrationResult(MigrationCode.BUSY)

    private fun execute(checkpoint: (Stage) -> Unit): MigrationResult {
        if (!PgpMigrationPolicy.EOA_RE.matches(eoa)) return MigrationResult(MigrationCode.ACCOUNT_MISMATCH)
        primary?.let { p ->
            val limit = LegacyPgpSource.MAX_BYTES
            if (p.privateArmor.size > limit || p.publicArmor.size > limit) return MigrationResult(MigrationCode.LEGACY_UNREADABLE)
        }
        val l = selectLegacy()
        val m = readMarker()
        val n = readStaged()

        // Step 1: a marker exists.
        if (m != null) {
            if (n != null) {
                if (n.fp != m.fp) return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
                if (l != null) {
                    val f0 = crypto.publicFingerprint(l.publicText())
                        ?: return MigrationResult(MigrationCode.LEGACY_UNREADABLE)
                    if (f0 != n.fp) return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
                }
                return MigrationResult(MigrationCode.ALREADY_VERIFIED, m.fp)
            }
            if (l == null) return MigrationResult(MigrationCode.STORE_MISSING)
            // The marker has no target and the legacy record is still there: the marker is stale (M-25).
            removeMarker()
        }

        // Step 2: no source record. The chain is the only reference for F0.
        if (l == null) {
            return if (n == null) MigrationResult(MigrationCode.NONE) else confirmStagedWithoutLegacy(n, checkpoint)
        }

        // Step 3: a source record is present.
        return migrateFromLegacy(l, n, checkpoint)
    }

    /**
     * The source selection of §25.52D.9 and SR-01 to SR-07. P has priority over L. When both are present and both readable, a different
     * public fingerprint is `fingerprint_mismatch` (thrown, so nothing is written). Returns the record used, or `null` when there is none.
     * The size limit of P is checked by the caller.
     */
    private fun selectLegacy(): LegacyRecord? {
        val p = primary ?: return legacy.read()
        val l = legacy.read()
        if (l != null) {
            val fpP = crypto.publicFingerprint(p.publicText())
            val fpL = crypto.publicFingerprint(l.publicText())
            if (fpP != null && fpL != null && fpP != fpL) throw Stop(MigrationCode.FINGERPRINT_MISMATCH)
        }
        return p
    }

    /**
     * The chain check of §25.52I.7 against the expected fingerprint. Returns `null` when the registered key matches, else the code.
     * An unreadable chain is `chain_unavailable`. Absent and unparseable are `fingerprint_mismatch`, with no automatic registration.
     */
    private fun chainCode(expected: String): MigrationCode? = when (val answer = chain.registered(eoa)) {
        is ChainAnswer.Unavailable -> MigrationCode.CHAIN_UNAVAILABLE
        is ChainAnswer.Absent, is ChainAnswer.Unparseable -> MigrationCode.FINGERPRINT_MISMATCH
        is ChainAnswer.Found -> if (answer.fp == expected) null else MigrationCode.FINGERPRINT_MISMATCH
    }

    private fun confirmStagedWithoutLegacy(n: StagedItem, checkpoint: (Stage) -> Unit): MigrationResult {
        chainCode(n.fp)?.let { return MigrationResult(it) }
        return verifyStaged(n.privateArmor, n.fp, wroteStaged = false, checkpoint = checkpoint)
    }

    private fun migrateFromLegacy(l: LegacyRecord, n: StagedItem?, checkpoint: (Stage) -> Unit): MigrationResult {
        val priv = l.privateText()
        // Pre-check (no write): both armors parse, the approval gate is open, and an empty passphrase signs.
        val f1 = crypto.secretFingerprint(priv) ?: return MigrationResult(MigrationCode.LEGACY_UNREADABLE)
        val f0 = crypto.publicFingerprint(l.publicText()) ?: return MigrationResult(MigrationCode.LEGACY_UNREADABLE)
        if (!crypto.approved()) return MigrationResult(MigrationCode.VERIFY_UNAVAILABLE)
        val probe = PgpMigrationPolicy.PRECHECK_MESSAGE.toByteArray(Charsets.UTF_8)
        if (crypto.sign(priv, PgpMigrationPolicy.PRECHECK_LABEL, probe) == null) {
            return MigrationResult(MigrationCode.LEGACY_UNREADABLE)
        }
        if (f1 != f0) return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
        if (!l.eoa.equals(eoa, ignoreCase = true)) return MigrationResult(MigrationCode.ACCOUNT_MISMATCH)

        chainCode(f0)?.let { return MigrationResult(it) }

        // Covering rule (§25.52A.2): no N writes; the same F0 is idempotent; a different F0 is never overwritten.
        if (n != null) {
            if (n.fp != f0) return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
            return verifyStaged(n.privateArmor, f0, wroteStaged = false, checkpoint = checkpoint)
        }
        try {
            staged.write(StagedItem(eoa, f0, priv))
        } catch (_: IOException) {
            throw Stop(MigrationCode.WRITE_FAILED)
        }
        checkpoint(Stage.AFTER_STAGED_WRITE)
        return verifyStaged(priv, f0, wroteStaged = true, checkpoint = checkpoint)
    }

    /**
     * Steps 4 to 6 (§25.52.6): reread N from the store, compare F1 with F0, challenge and verify, then write M. A failure in steps 4 and 5
     * deletes N only when this run wrote it (§25.52.6). A failure to write M keeps N.
     */
    private fun verifyStaged(armor: String, f0: String, wroteStaged: Boolean, checkpoint: (Stage) -> Unit): MigrationResult {
        fun reject(code: MigrationCode, fp: String? = null): Nothing {
            if (wroteStaged) runCatching { staged.delete() }
            throw Stop(code, fp)
        }

        val reread = try {
            staged.read()
        } catch (_: IOException) {
            null
        }
        if (reread == null || reread.privateArmor != armor) reject(MigrationCode.REREAD_FAILED)
        val f1 = crypto.secretFingerprint(reread.privateArmor) ?: reject(MigrationCode.REREAD_FAILED)
        if (f1 != f0) reject(MigrationCode.FINGERPRINT_MISMATCH)
        checkpoint(Stage.AFTER_REREAD)

        if (!crypto.approved()) reject(MigrationCode.VERIFY_UNAVAILABLE)
        val keyId = crypto.keyId(reread.privateArmor) ?: reject(MigrationCode.CHALLENGE_FAILED)
        val nonce = ByteArray(PgpMigrationPolicy.NONCE_BYTES).also { random.nextBytes(it) }
        val message = "$eoa|$keyId|${nonce.joinToString("") { "%02x".format(it) }}".toByteArray(Charsets.UTF_8)
        val signature = crypto.sign(reread.privateArmor, PgpMigrationPolicy.CHALLENGE_LABEL, message)
            ?: reject(MigrationCode.CHALLENGE_FAILED)
        val good = crypto.verify(reread.privateArmor, PgpMigrationPolicy.CHALLENGE_LABEL, message, signature)
        // Negative check (§25.52.8): a message changed by one bit must not verify.
        val tamperedVerifies = crypto.verify(reread.privateArmor, PgpMigrationPolicy.CHALLENGE_LABEL, flipOneBit(message), signature)
        if (!good || tamperedVerifies) reject(MigrationCode.CHALLENGE_FAILED)
        checkpoint(Stage.AFTER_CHALLENGE)

        checkpoint(Stage.BEFORE_MARKER_WRITE)
        try {
            marker.write(MarkerItem(f0, PgpMigrationPolicy.SOURCE_LEGACY, now()))
        } catch (_: IOException) {
            throw Stop(MigrationCode.WRITE_FAILED)
        }
        checkpoint(Stage.AFTER_MARKER_WRITE)
        return MigrationResult(MigrationCode.OK, f0)
    }

    /**
     * Unregister (§25.52C.3, §25.52I.8, §25.52I.9, §25.52H.2 rule 5): removes M, then N, then the last code, then the page copy's W fields.
     * L is never removed. An invalid account is
     * `bad_request`; a running operation on the account is `busy`; both remove nothing. The recovery source is checked before any
     * removal: L exists, or P is readable, or a chain backup is registered and restorable. Without one, and with N or M present, the
     * result is `unregister_refused`. Nothing present is `ok` (idempotent).
     */
    fun unregister(checkpoint: (Stage) -> Unit = {}): MigrationResult {
        if (!PgpMigrationPolicy.EOA_RE.matches(eoa)) return MigrationResult(MigrationCode.BAD_REQUEST)
        return lock.tryRun(eoa) {
            try {
                unregisterRun(checkpoint)
            } catch (stop: Stop) {
                MigrationResult(stop.code, stop.fp)
            }
        } ?: MigrationResult(MigrationCode.BUSY)
    }

    private fun unregisterRun(checkpoint: (Stage) -> Unit): MigrationResult {
        // A present-but-unreadable item is still present: it must be removed too, so it counts as present.
        val markerPresent = try {
            marker.read() != null
        } catch (_: IOException) {
            true
        }
        val stagedPresent = try {
            staged.read() != null
        } catch (_: IOException) {
            true
        }
        val walletPresent = wallet.present()
        if (!markerPresent && !stagedPresent && !walletPresent) {
            lastCode.delete()
            return MigrationResult(MigrationCode.OK)
        }
        // The recovery check comes before any removal, the W fields included (§25.52C.3, §25.52J.3).
        if (!hasRecoverySource()) return MigrationResult(MigrationCode.UNREGISTER_REFUSED)
        if (markerPresent) {
            marker.delete()
            checkpoint(Stage.AFTER_MARKER_DELETED)
        }
        if (stagedPresent) staged.delete()
        lastCode.delete()
        if (walletPresent) {
            try {
                wallet.remove()
            } catch (_: IOException) {
                throw Stop(MigrationCode.WRITE_FAILED)
            }
        }
        return MigrationResult(MigrationCode.OK)
    }

    /**
     * Check only, for the identity clear (§25.52PY.8 (1a), (1c); PY.12). Nothing is removed. Refused (`unregister_refused`) when N, M,
     * W or the native PGP record is present and no recovery source exists (L, P readable, or a chain backup). BUSY when the lock is held.
     */
    fun clearCheck(pgpRecordPresent: Boolean): MigrationResult = lock.tryRun(eoa) {
        val markerPresent = try {
            marker.read() != null
        } catch (_: IOException) {
            true
        }
        val stagedPresent = try {
            staged.read() != null
        } catch (_: IOException) {
            true
        }
        // W is not part of this check: its gate is recovery_backup_confirmed (PY.10), in IdentityClear (1b). L, P and the chain backup are
        // not W's recovery source, so a wallet with W only does not need one here.
        val needsSource = markerPresent || stagedPresent || pgpRecordPresent
        if (!needsSource || hasRecoverySource()) MigrationResult(MigrationCode.OK) else MigrationResult(MigrationCode.UNREGISTER_REFUSED)
    } ?: MigrationResult(MigrationCode.BUSY)

    /**
     * Removal for the identity clear, step (3) of §25.52PY.8, run only after clear_pending is set: N (staged), M (marker), the last code and
     * the page wallet fields of this account. True only when each is gone.
     */
    fun clearErase(): Boolean = lock.tryRun(eoa) {
        runCatching { marker.delete() }
        runCatching { staged.delete() }
        runCatching { lastCode.delete() }
        val walletRemoved = runCatching { wallet.remove() }.isSuccess
        val markerGone = runCatching { marker.read() == null }.getOrDefault(false)
        val stagedGone = runCatching { staged.read() == null }.getOrDefault(false)
        val walletGone = runCatching { !wallet.present() }.getOrDefault(false)
        walletRemoved && markerGone && stagedGone && walletGone
    } ?: false

    private fun hasRecoverySource(): Boolean =
        legacy.read() != null || recovery.pReadable() || recovery.chainRegistered()

    private fun readLastCode(): String? = try {
        lastCode.read()
    } catch (_: IOException) {
        null
    }

    private fun readStaged(): StagedItem? = try {
        staged.read()
    } catch (_: IOException) {
        throw Stop(MigrationCode.REREAD_FAILED)
    }

    private fun readMarker(): MarkerItem? = try {
        marker.read()
    } catch (_: IOException) {
        throw Stop(MigrationCode.REREAD_FAILED)
    }

    private fun removeMarker() {
        try {
            marker.delete()
        } catch (_: IOException) {
            throw Stop(MigrationCode.WRITE_FAILED)
        }
    }

    private fun flipOneBit(bytes: ByteArray): ByteArray = bytes.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
}

/**
 * The sealed target N for one account. One file, written in one step (tmp, fsync, rename, as the vault does). The AEAD tag binds the
 * account and the workspace, so a file moved between accounts does not open.
 */
internal class SealedStagedStore(
    private val wrap: KeyWrap,
    private val files: VaultFiles,
    eoa: String,
    workspace: String,
) : MigrationStaged {
    private val name = "pgp.v1.mig.${eoa.removePrefix("0x")}.$workspace.n"
    private val aad = "beamio.pgp.migrate.staged.v1|$eoa|$workspace".toByteArray(Charsets.UTF_8)

    override fun read(): StagedItem? {
        val sealed = files.read(name) ?: return null
        val plain = wrap.open(aad, sealed) ?: throw IOException("staged record does not open")
        return try {
            val o = JSONObject(String(plain, Charsets.UTF_8))
            StagedItem(o.getString("eoa"), o.getString("fp"), o.getString("priv"))
        } catch (_: Exception) {
            throw IOException("staged record is malformed")
        } finally {
            plain.fill(0)
        }
    }

    override fun write(item: StagedItem) {
        val plain = JSONObject()
            .put("v", 1)
            .put("eoa", item.eoa)
            .put("fp", item.fp)
            .put("priv", item.privateArmor)
            .toString()
            .toByteArray(Charsets.UTF_8)
        try {
            val sealed = try {
                wrap.seal(aad, plain)
            } catch (e: Exception) {
                throw IOException("staged record cannot be sealed", e)
            }
            files.write(name, sealed)
        } finally {
            plain.fill(0)
        }
    }

    override fun delete() {
        files.delete(name)
    }
}

/** The sealed success marker M for one account. Same file rules as [SealedStagedStore]. */
internal class SealedMarkerStore(
    private val wrap: KeyWrap,
    private val files: VaultFiles,
    eoa: String,
    workspace: String,
) : MigrationMarker {
    private val name = "pgp.v1.mig.${eoa.removePrefix("0x")}.$workspace.m"
    private val aad = "beamio.pgp.migrate.marker.v1|$eoa|$workspace".toByteArray(Charsets.UTF_8)

    override fun read(): MarkerItem? {
        val sealed = files.read(name) ?: return null
        val plain = wrap.open(aad, sealed) ?: throw IOException("marker does not open")
        return try {
            val o = JSONObject(String(plain, Charsets.UTF_8))
            MarkerItem(o.getString("fp"), o.getString("source"), o.getLong("verifiedAt"))
        } catch (_: Exception) {
            throw IOException("marker is malformed")
        }
    }

    override fun write(item: MarkerItem) {
        val plain = JSONObject()
            .put("v", 1)
            .put("fp", item.fp)
            .put("source", item.source)
            .put("verifiedAt", item.verifiedAt)
            .toString()
            .toByteArray(Charsets.UTF_8)
        try {
            val sealed = try {
                wrap.seal(aad, plain)
            } catch (e: Exception) {
                throw IOException("marker cannot be sealed", e)
            }
            files.write(name, sealed)
        } finally {
            plain.fill(0)
        }
    }

    override fun delete() {
        files.delete(name)
    }
}

/** The last result of an account's complete run (§25.52D.4). Plain JSON: it holds a code, never key material. */
internal class FileLastCodeStore(
    private val files: VaultFiles,
    eoa: String,
    workspace: String,
) : MigrationLastCode {
    private val name = "pgp.v1.mig.${eoa.removePrefix("0x")}.$workspace.last"

    override fun read(): String? {
        val bytes = files.read(name) ?: return null
        return try {
            JSONObject(String(bytes, Charsets.UTF_8)).getString("code")
        } catch (_: Exception) {
            null
        }
    }

    override fun write(code: String) {
        files.write(name, JSONObject().put("v", 1).put("code", code).toString().toByteArray(Charsets.UTF_8))
    }

    override fun delete() {
        files.delete(name)
    }
}

/** The production legacy source: the SDK's own account record, read only (§25.52.3). */
internal class BeamioChatPgpLegacy(private val context: Context) : MigrationLegacy {
    override fun read(): LegacyRecord? {
        val copy = BeamioChatPgpStore.legacyCopy(context) ?: return null
        return LegacyRecord(copy.eoa, copy.privateArmor.toByteArray(Charsets.UTF_8), copy.publicArmor.toByteArray(Charsets.UTF_8))
    }
}

/** The production chain source: the AddressPGP record of the account, read only (§25.52I.7). */
internal class AddressPgpMigrationChain : MigrationChain {
    override fun registered(eoa: String): ChainAnswer {
        val chain = AddressPgpChain.read(eoa) { ep -> AddressPgpRead.HttpRpc(ep.url, ep.timeoutMs) }
        if (!chain.chainReadable()) return if (chain.recordKnown()) ChainAnswer.Unparseable else ChainAnswer.Unavailable
        val identity = chain.identity() ?: return ChainAnswer.Absent
        return ChainAnswer.Found(identity.fingerprint.lowercase())
    }
}

/**
 * The production recovery sources (§25.52C.3). P is not readable in this build: the shell's reader is not wired to unregister. A chain
 * backup counts when the record exists, the backup decrypts with the vault key of this account, and the result parses as a private
 * key. An unreadable chain, a locked vault or another account counts as not registered: unregister then refuses.
 */
internal class ProductionRecovery(private val context: Context, private val eoa: String) : MigrationRecovery {
    override fun pReadable(): Boolean = false

    override fun chainRegistered(): Boolean {
        val chain = AddressPgpChain.read(eoa) { ep -> AddressPgpRead.HttpRpc(ep.url, ep.timeoutMs) }
        if (!chain.chainReadable() || chain.identity() == null) return false
        val backup = chain.backupText()
        if (backup.isEmpty()) return false
        val vault = NativeWallet.vault(context)
        if ((vault.state() as? NativeWalletVault.State.Ready)?.eoa != eoa) return false
        val key = vault.unlock() ?: return false
        try {
            val armor = NativePgpBackup.decryptArmor(NativePgpBackup.passwordString(key), backup) ?: return false
            return NativePgp.parseSecret(String(armor, Charsets.UTF_8)) != null
        } finally {
            key.fill(0)
        }
    }
}

/** The production OpenPGP functions, on the same library as [NativePgp]. Keys stay inside this class. */
internal class NativeMigrationCrypto(
    private val approvedFlag: Boolean = PgpMigrationPolicy.OPENPGP_APPROVED,
) : MigrationCrypto {
    override fun approved(): Boolean = approvedFlag

    override fun secretFingerprint(armor: String): String? = NativePgp.parseSecret(armor)?.fingerprint

    override fun publicFingerprint(armor: String): String? {
        if (armor.isBlank() || armor.contains("PRIVATE KEY BLOCK")) return null
        return PgpPublicIdentity.parse(armor)?.fingerprint?.lowercase()
    }

    override fun keyId(armor: String): String? = NativePgp.parseSecret(armor)?.let { NativePgpBackup.subkeyKeyId(it) }

    override fun sign(armor: String, label: String, message: ByteArray): String? {
        val secret = NativePgp.parseSecret(armor) ?: return null
        val out = NativePgp.signDocument(secret, "", label, message, PgpMigrationPolicy.SIG_TYPE)
        return if (out.ok) out.value else null
    }

    override fun verify(armor: String, label: String, message: ByteArray, signature: String): Boolean {
        val secret = NativePgp.parseSecret(armor) ?: return false
        return NativePgp.verifyDocument(secret, label, message, signature)
    }
}

/**
 * The public entry of the native layer (§25.52D.3, §25.52C.2, §25.52K.7). Takes an account, a workspace and an optional page source P,
 * and nothing secret. The checkpoint parameter is internal to the engine, so it is not part of this API (§25.52C.4). Calls block: run them
 * off the main thread.
 */
object BeamioPgpMigrationImport {
    /**
     * One run for [eoa]. With [source] nil the run reads L; otherwise it uses P (§25.52D.9). The source arrays are zero-filled after the
     * run, whatever its result.
     */
    fun run(
        context: Context,
        eoa: String,
        workspace: String = PgpMigrationPolicy.WORKSPACE,
        source: LegacyPgpSource? = null,
    ): MigrationResult {
        if (source == null) return engine(context, eoa, workspace, null)?.run() ?: refused()
        return source.useAs(eoa.lowercase()) { record ->
            engine(context, eoa, workspace, record)?.run() ?: refused()
        }
    }

    /** `none`, `pending`, `failed` or `verified`. Read only. */
    fun state(context: Context, eoa: String, workspace: String = PgpMigrationPolicy.WORKSPACE): String =
        engine(context, eoa, workspace, null)?.state() ?: "none"

    /**
     * Unregister (§25.52C.3, §25.52I.8): removes M, N and the last code after the recovery check. L is never removed. Returns `ok`,
     * `unregister_refused`, `bad_request` (an invalid account or a workspace other than `default`) or `busy`.
     */
    fun unregister(context: Context, eoa: String, workspace: String = PgpMigrationPolicy.WORKSPACE): MigrationResult {
        if (workspace != PgpMigrationPolicy.WORKSPACE) return MigrationResult(MigrationCode.BAD_REQUEST)
        return engine(context, eoa, workspace, null)?.unregister() ?: MigrationResult(MigrationCode.BAD_REQUEST)
    }

    /** Identity clear, (1a) and (1c): the check only (see [PgpMigrationEngine.clearCheck]). */
    fun clearCheck(context: Context, eoa: String, pgpRecordPresent: Boolean): MigrationResult =
        engine(context, eoa, PgpMigrationPolicy.WORKSPACE, null)?.clearCheck(pgpRecordPresent) ?: MigrationResult(MigrationCode.BAD_REQUEST)

    /** Identity clear, step (3): the removal for [eoa] (see [PgpMigrationEngine.clearErase]). */
    fun clearErase(context: Context, eoa: String): Boolean =
        engine(context, eoa, PgpMigrationPolicy.WORKSPACE, null)?.clearErase() == true

    /**
     * The first-run import (§25.52K.7): the legacy wallet record becomes the page wallet copy (rev 0 to 1, W fields encrypted, PGP fields
     * removed), after the address check. The PGP part of the same first start goes to the migration (§25.52.6). Never creates a new wallet.
     * [walletRecord] and [pgpSource] are zero-filled after use.
     */
    fun importFirstRun(
        context: Context,
        eoa: String,
        walletRecord: LegacyWalletRecord,
        pgpSource: LegacyPgpSource? = null,
    ): ShellImportCode = markingMigration(ShellRecordState.migrationPending) {
        // §25.52L.3: the entry itself marks the page's reads and writes as migrating while it runs.
        BeamioShellRecordImport.runFirstImport(context, eoa.lowercase(), walletRecord, pgpSource)
    }

    private fun refused(): MigrationResult = MigrationResult(MigrationCode.ACCOUNT_MISMATCH)

    /** The engine for a canonical account and a safe workspace name. Null for anything else, so no file name is built from it. */
    internal fun engine(context: Context, eoa: String, workspace: String, primary: LegacyRecord?): PgpMigrationEngine? {
        val account = eoa.lowercase()
        if (!PgpMigrationPolicy.EOA_RE.matches(account)) return null
        if (!PgpMigrationPolicy.WORKSPACE_RE.matches(workspace)) return null
        val app = context.applicationContext
        val wrap = AndroidKeyWrap()
        val files = NativeWallet.migrationFiles(app)
        return PgpMigrationEngine(
            eoa = account,
            legacy = BeamioChatPgpLegacy(app),
            primary = primary?.let { LegacyRecord(account, it.privateArmor, it.publicArmor) },
            staged = SealedStagedStore(wrap, files, account, workspace),
            marker = SealedMarkerStore(wrap, files, account, workspace),
            lastCode = FileLastCodeStore(files, account, workspace),
            chain = AddressPgpMigrationChain(),
            crypto = NativeMigrationCrypto(),
            recovery = ProductionRecovery(app, account),
            lock = ProcessMigrationLock,
            wallet = PageWalletRemoval(BeamioShellRecordImport.storeFor(app, account)),
        )
    }
}
