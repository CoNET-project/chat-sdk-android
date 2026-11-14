package network.conet.chat.nativekey

import android.content.Context
import network.conet.chat.BeamioChatPgpStore
import org.json.JSONObject
import java.io.IOException
import java.security.SecureRandom

/**
 * Migration of the legacy PGP private key into the SDK's secure store (spec r3at §25.52, §25.52A, §25.52C; U5).
 *
 * The source is the SDK's own account record L, read only, inside the SDK. The target is N, one sealed item per account. The
 * success marker M is written last. Nothing here takes a key, a passphrase or an old public key from the bridge, and nothing
 * here generates a key. L is never changed or removed by the migration. Results are codes only.
 */
internal object PgpMigrationPolicy {
    /**
     * Approval of the OpenPGP functions behind the migration (§25.52.10: sign, verify, primary fingerprint and first subkey ID).
     * They are not approved yet, so the production path answers `verify_unavailable` and writes nothing (§25.52A.3, §25.52C.1).
     * The tests run the same pipeline with an approving [MigrationCrypto].
     */
    const val OPENPGP_APPROVED = false

    const val CHALLENGE_LABEL = "beamio.pgp.migrate.challenge.v1\n"
    const val PRECHECK_LABEL = "beamio.pgp.migrate.precheck.v1\n"
    const val PRECHECK_MESSAGE = "beamio pgp migrate precheck"
    const val SIG_TYPE = 0x01
    const val WORKSPACE = "default"
    const val SOURCE_LEGACY = "legacyPwa"
    const val NONCE_BYTES = 32

    internal val EOA_RE = Regex("^0x[0-9a-f]{40}$")
    internal val WORKSPACE_RE = Regex("^[a-z0-9_-]{1,32}$")
}

/**
 * The result codes of §25.52.5 and the unregister codes of §25.52C.3. [wire] is the code sent to the page.
 */
internal enum class MigrationCode(val wire: String) {
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
}

/** [fp] is the full lower-case fingerprint. The page only ever gets its first 16 characters. */
internal class MigrationResult(val code: MigrationCode, val fp: String? = null)

/**
 * A run stopped by an interruption (process death, power loss, lock). It produces no result event (§25.52.12). The next call to
 * the same account resumes from the stored state. This is an [Error], so no handler in the pipeline swallows it. It is the
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

/** The legacy record L as read. Read only. */
internal class LegacyRecord(val eoa: String, val privateArmor: String, val publicArmor: String)

/** The target N: the account's private armor and the fingerprint it had when written. */
internal class StagedItem(val eoa: String, val fp: String, val privateArmor: String)

/** The success marker M. [fp] is the full fingerprint; the stored value is never a key. */
internal class MarkerItem(val fp: String, val source: String, val verifiedAt: Long)

/** The chain's view of the account's registered PGP fingerprint (AddressPGP, read only). */
internal sealed class ChainAnswer {
    class Found(val fp: String) : ChainAnswer()
    object Absent : ChainAnswer()
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

internal fun interface MigrationChain {
    fun registered(eoa: String): ChainAnswer
}

/**
 * The recovery sources of §25.52C.3. Unregister needs at least one: L (a separate source), P readable natively (§25.52B.2), or
 * a chain backup that is registered and restorable by P-IMP-PGP (§25.30).
 */
internal interface MigrationRecovery {
    /** Source P can be read natively. No reader is in this build yet (r3aw), so production answers `false`. */
    fun pReadable(): Boolean

    /** The account's chain backup is registered and can be restored. Production answers `false` when unsure. */
    fun chainRegistered(): Boolean
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
 * The migration pipeline for one account (§25.52.6, §25.52A.2) and the unregister (§25.52C.3). Each call is one run; a run that
 * is interrupted leaves the stored state as it was at that point, and the next call resumes from it. A run returns exactly one
 * [MigrationResult] or throws [PgpMigrationInterrupted].
 */
internal class PgpMigrationEngine(
    private val eoa: String,
    private val legacy: MigrationLegacy,
    private val staged: MigrationStaged,
    private val marker: MigrationMarker,
    private val chain: MigrationChain,
    private val crypto: MigrationCrypto,
    private val recovery: MigrationRecovery,
    private val random: SecureRandom = SecureRandom(),
    private val now: () -> Long = { System.currentTimeMillis() },
) {
    /** Stops the run with a code. Internal only; [run] turns it into a result. */
    private class Stop(val code: MigrationCode, val fp: String? = null) : RuntimeException()

    /** `none`, `pending` or `verified`, read only (§25.52.4). */
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
        if (m == null && n == null) return "none"
        if (m == null || n == null || n.fp != m.fp) return "pending"
        val l = legacy.read()
        if (l != null && crypto.publicFingerprint(l.publicArmor) != n.fp) return "pending"
        return "verified"
    }

    fun run(checkpoint: (Stage) -> Unit = {}): MigrationResult = try {
        execute(checkpoint)
    } catch (stop: Stop) {
        MigrationResult(stop.code, stop.fp)
    }

    private fun execute(checkpoint: (Stage) -> Unit): MigrationResult {
        if (!PgpMigrationPolicy.EOA_RE.matches(eoa)) return MigrationResult(MigrationCode.ACCOUNT_MISMATCH)
        val m = readMarker()
        val n = readStaged()
        val l = legacy.read()

        // Step 1: a marker exists.
        if (m != null) {
            if (n != null) {
                if (n.fp != m.fp) return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
                if (l != null) {
                    val f0 = crypto.publicFingerprint(l.publicArmor) ?: return MigrationResult(MigrationCode.LEGACY_UNREADABLE)
                    if (f0 != n.fp) return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
                }
                return MigrationResult(MigrationCode.ALREADY_VERIFIED, m.fp)
            }
            if (l == null) return MigrationResult(MigrationCode.STORE_MISSING)
            // The marker has no target and the legacy record is still there: the marker is stale (M-25).
            removeMarker()
        }

        // Step 2: no legacy record. The chain is the only reference for F0.
        if (l == null) {
            return if (n == null) MigrationResult(MigrationCode.NONE) else confirmStagedWithoutLegacy(n, checkpoint)
        }

        // Step 3: the legacy record is present.
        return migrateFromLegacy(l, n, checkpoint)
    }

    private fun confirmStagedWithoutLegacy(n: StagedItem, checkpoint: (Stage) -> Unit): MigrationResult {
        when (val answer = chain.registered(eoa)) {
            is ChainAnswer.Unavailable -> return MigrationResult(MigrationCode.CHAIN_UNAVAILABLE)
            is ChainAnswer.Absent -> return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
            is ChainAnswer.Found -> if (answer.fp != n.fp) return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
        }
        return verifyStaged(n.privateArmor, n.fp, wroteStaged = false, checkpoint = checkpoint)
    }

    private fun migrateFromLegacy(l: LegacyRecord, n: StagedItem?, checkpoint: (Stage) -> Unit): MigrationResult {
        // Pre-check (no write): both armors parse, the approval gate is open, and an empty passphrase signs.
        val f1 = crypto.secretFingerprint(l.privateArmor) ?: return MigrationResult(MigrationCode.LEGACY_UNREADABLE)
        val f0 = crypto.publicFingerprint(l.publicArmor) ?: return MigrationResult(MigrationCode.LEGACY_UNREADABLE)
        if (!crypto.approved()) return MigrationResult(MigrationCode.VERIFY_UNAVAILABLE)
        val probe = PgpMigrationPolicy.PRECHECK_MESSAGE.toByteArray(Charsets.UTF_8)
        if (crypto.sign(l.privateArmor, PgpMigrationPolicy.PRECHECK_LABEL, probe) == null) {
            return MigrationResult(MigrationCode.LEGACY_UNREADABLE)
        }
        if (f1 != f0) return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
        if (!l.eoa.equals(eoa, ignoreCase = true)) return MigrationResult(MigrationCode.ACCOUNT_MISMATCH)

        when (val answer = chain.registered(eoa)) {
            is ChainAnswer.Unavailable -> return MigrationResult(MigrationCode.CHAIN_UNAVAILABLE)
            is ChainAnswer.Absent -> return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
            is ChainAnswer.Found -> if (answer.fp != f0) return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
        }

        // Covering rule (§25.52A.2): no N writes; the same F0 is idempotent; a different F0 is never overwritten.
        if (n != null) {
            if (n.fp != f0) return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
            return verifyStaged(n.privateArmor, f0, wroteStaged = false, checkpoint = checkpoint)
        }
        try {
            staged.write(StagedItem(eoa, f0, l.privateArmor))
        } catch (_: IOException) {
            throw Stop(MigrationCode.WRITE_FAILED)
        }
        checkpoint(Stage.AFTER_STAGED_WRITE)
        return verifyStaged(l.privateArmor, f0, wroteStaged = true, checkpoint = checkpoint)
    }

    /**
     * Steps 4 to 6 (§25.52.6): reread N from the store, compare F1 with F0, challenge and verify, then write M. A failure in
     * steps 4 and 5 deletes N only when this run wrote it (§25.52.6). A failure to write M keeps N.
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
     * Unregister (§25.52C.3): removes M, then N. L is never removed. The recovery source is checked before any removal: L
     * exists, or P is readable, or a chain backup is registered and restorable. Without one, and with N or M present, the
     * result is `unregister_refused` and nothing is removed. Nothing present is `ok` (idempotent).
     */
    fun unregister(checkpoint: (Stage) -> Unit = {}): MigrationResult = try {
        unregisterRun(checkpoint)
    } catch (stop: Stop) {
        MigrationResult(stop.code, stop.fp)
    }

    private fun unregisterRun(checkpoint: (Stage) -> Unit): MigrationResult {
        if (!PgpMigrationPolicy.EOA_RE.matches(eoa)) return MigrationResult(MigrationCode.ACCOUNT_MISMATCH)
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
        if (!markerPresent && !stagedPresent) return MigrationResult(MigrationCode.OK)
        if (!hasRecoverySource()) return MigrationResult(MigrationCode.UNREGISTER_REFUSED)
        if (markerPresent) {
            marker.delete()
            checkpoint(Stage.AFTER_MARKER_DELETED)
        }
        if (stagedPresent) staged.delete()
        return MigrationResult(MigrationCode.OK)
    }

    private fun hasRecoverySource(): Boolean =
        legacy.read() != null || recovery.pReadable() || recovery.chainRegistered()

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
 * The sealed target N for one account. One file, written in one step (tmp, fsync, rename, as the vault does). The AEAD tag
 * binds the account and the workspace, so a file moved between accounts does not open.
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

/** The production legacy source: the SDK's own account record, read only (§25.52.3). */
internal class BeamioChatPgpLegacy(private val context: Context) : MigrationLegacy {
    override fun read(): LegacyRecord? {
        val copy = BeamioChatPgpStore.legacyCopy(context) ?: return null
        return LegacyRecord(copy.eoa, copy.privateArmor, copy.publicArmor)
    }
}

/** The production chain source: the AddressPGP record of the account, read only (§25.52.6 step 3). */
internal class AddressPgpMigrationChain : MigrationChain {
    override fun registered(eoa: String): ChainAnswer {
        val chain = AddressPgpChain.read(eoa) { ep -> AddressPgpRead.HttpRpc(ep.url, ep.timeoutMs) }
        if (!chain.chainReadable()) return ChainAnswer.Unavailable
        val identity = chain.identity() ?: return ChainAnswer.Absent
        return ChainAnswer.Found(identity.fingerprint.lowercase())
    }
}

/**
 * The production recovery sources (§25.52C.3). P is not readable in this build (r3aw defines the native reader). A chain
 * backup counts when the record exists, the backup decrypts with the vault key of this account, and the result parses as a
 * private key. An unreadable chain, a locked vault or another account counts as not registered: unregister then refuses.
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
 * The public entry of the native layer (§25.52.4, §25.52C.2; class name per §25.52C.2). Takes an account and a workspace, and
 * nothing secret. The checkpoint parameter is internal to the engine, so it is not part of this API (§25.52C.4).
 */
internal object BeamioPgpMigrationImport {
    /** One run for [eoa]. Blocking; call it off the main thread. */
    fun run(context: Context, eoa: String, workspace: String = PgpMigrationPolicy.WORKSPACE): MigrationResult =
        engine(context, eoa, workspace)?.run() ?: MigrationResult(MigrationCode.ACCOUNT_MISMATCH)

    /** `none`, `pending` or `verified`. Read only. */
    fun state(context: Context, eoa: String, workspace: String = PgpMigrationPolicy.WORKSPACE): String =
        engine(context, eoa, workspace)?.state() ?: "none"

    /** Unregister (§25.52C.3): removes M and N after the recovery check. L is never removed. Blocking. */
    fun unregister(context: Context, eoa: String, workspace: String = PgpMigrationPolicy.WORKSPACE): MigrationResult =
        engine(context, eoa, workspace)?.unregister() ?: MigrationResult(MigrationCode.ACCOUNT_MISMATCH)

    /** The engine for a canonical account and a safe workspace name. Null for anything else, so no file name is built from it. */
    private fun engine(context: Context, eoa: String, workspace: String): PgpMigrationEngine? {
        val account = eoa.lowercase()
        if (!PgpMigrationPolicy.EOA_RE.matches(account)) return null
        if (!PgpMigrationPolicy.WORKSPACE_RE.matches(workspace)) return null
        val app = context.applicationContext
        val wrap = AndroidKeyWrap()
        val files = NativeWallet.migrationFiles(app)
        return PgpMigrationEngine(
            eoa = account,
            legacy = BeamioChatPgpLegacy(app),
            staged = SealedStagedStore(wrap, files, account, workspace),
            marker = SealedMarkerStore(wrap, files, account, workspace),
            chain = AddressPgpMigrationChain(),
            crypto = NativeMigrationCrypto(),
            recovery = ProductionRecovery(app, account),
        )
    }
}
