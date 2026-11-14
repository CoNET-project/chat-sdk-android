package network.conet.chat.nativekey

import android.content.Context
import network.conet.chat.BeamioChatPgpStore
import org.json.JSONObject
import java.io.IOException
import java.security.SecureRandom

/**
 * Migration of the legacy PGP private key into the SDK's secure store (spec r3at §25.52, §25.52A; U5).
 *
 * The source is the SDK's own account record L, read only, inside the SDK. The target is N, one sealed item per account. The
 * success marker M is written last. Nothing here takes a key, a passphrase or an old public key from the bridge, and nothing
 * here generates a key. L is never changed or removed. Results are codes only.
 */
internal object PgpMigrationPolicy {
    /**
     * Approval of the OpenPGP functions behind the migration (§25.52.10: sign, verify, primary fingerprint and first subkey ID).
     * They are not approved yet, so the production path answers `verify_unavailable` and writes nothing (§25.52A.3). The tests
     * run the same pipeline with an approving [MigrationCrypto].
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
}

/** The result codes of §25.52.5. [wire] is the code sent to the page. */
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
}

/** [fp] is the full lower-case fingerprint. The page only ever gets its first 16 characters. */
internal class MigrationResult(val code: MigrationCode, val fp: String? = null)

/**
 * A run stopped by an interruption (process death, power loss, lock). It produces no result event (§25.52.12). The next call to
 * the same account resumes from the stored state. This is an [Error], so no handler in the pipeline swallows it.
 */
internal class PgpMigrationInterrupted : Error("pgp migration interrupted")

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
 * The migration pipeline for one account (§25.52.6, §25.52A.2). Each call is one run; a run that is interrupted leaves the
 * stored state as it was at that point, and the next call resumes from it. A run returns exactly one [MigrationResult] or
 * throws [PgpMigrationInterrupted].
 */
internal class PgpMigrationEngine(
    private val eoa: String,
    private val legacy: MigrationLegacy,
    private val staged: MigrationStaged,
    private val marker: MigrationMarker,
    private val chain: MigrationChain,
    private val crypto: MigrationCrypto,
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

    fun run(): MigrationResult = try {
        execute()
    } catch (stop: Stop) {
        MigrationResult(stop.code, stop.fp)
    }

    private fun execute(): MigrationResult {
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
            return if (n == null) MigrationResult(MigrationCode.NONE) else confirmStagedWithoutLegacy(n)
        }

        // Step 3: the legacy record is present.
        return migrateFromLegacy(l, n)
    }

    private fun confirmStagedWithoutLegacy(n: StagedItem): MigrationResult {
        when (val answer = chain.registered(eoa)) {
            is ChainAnswer.Unavailable -> return MigrationResult(MigrationCode.CHAIN_UNAVAILABLE)
            is ChainAnswer.Absent -> return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
            is ChainAnswer.Found -> if (answer.fp != n.fp) return MigrationResult(MigrationCode.FINGERPRINT_MISMATCH)
        }
        return verifyStaged(n.privateArmor, n.fp, wroteStaged = false)
    }

    private fun migrateFromLegacy(l: LegacyRecord, n: StagedItem?): MigrationResult {
        // Pre-check (no write): both armors parse, the approval gate is open, and an empty passphrase signs.
        val f1 = crypto.secretFingerprint(l.privateArmor) ?: return MigrationResult(MigrationCode.LEGACY_UNREADABLE)
        val f0 = crypto.publicFingerprint(l.publicArmor) ?: return MigrationResult(MigrationCode.LEGACY_UNREADABLE)
        if (!crypto.approved()) return MigrationResult(MigrationCode.VERIFY_UNAVAILABLE)
        if (crypto.sign(l.privateArmor, PgpMigrationPolicy.PRECHECK_LABEL, PgpMigrationPolicy.PRECHECK_MESSAGE.toByteArray(Charsets.UTF_8)) == null) {
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
            return verifyStaged(n.privateArmor, f0, wroteStaged = false)
        }
        try {
            staged.write(StagedItem(eoa, f0, l.privateArmor))
        } catch (_: IOException) {
            throw Stop(MigrationCode.WRITE_FAILED)
        }
        return verifyStaged(l.privateArmor, f0, wroteStaged = true)
    }

    /**
     * Steps 4 to 6 (§25.52.6): reread N from the store, compare F1 with F0, challenge and verify, then write M. A failure in
     * steps 4 and 5 deletes N only when this run wrote it (§25.52.6). A failure to write M keeps N.
     */
    private fun verifyStaged(armor: String, f0: String, wroteStaged: Boolean): MigrationResult {
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

        try {
            marker.write(MarkerItem(f0, PgpMigrationPolicy.SOURCE_LEGACY, now()))
        } catch (_: IOException) {
            throw Stop(MigrationCode.WRITE_FAILED)
        }
        return MigrationResult(MigrationCode.OK, f0)
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

/** The public entry for the native layer (§25.52.4). Takes an account and nothing secret. */
internal object BeamioPgpMigration {
    /** One run for [eoa] in the default workspace. Blocking; call it off the main thread. */
    fun run(context: Context, eoa: String): MigrationResult = engine(context, eoa).run()

    /** `none`, `pending` or `verified`. Read only. */
    fun state(context: Context, eoa: String): String = engine(context, eoa).state()

    private fun engine(context: Context, eoa: String): PgpMigrationEngine {
        val app = context.applicationContext
        val account = eoa.lowercase()
        val workspace = PgpMigrationPolicy.WORKSPACE
        val wrap = AndroidKeyWrap()
        val files = NativeWallet.migrationFiles(app)
        return PgpMigrationEngine(
            eoa = account,
            legacy = BeamioChatPgpLegacy(app),
            staged = SealedStagedStore(wrap, files, account, workspace),
            marker = SealedMarkerStore(wrap, files, account, workspace),
            chain = AddressPgpMigrationChain(),
            crypto = NativeMigrationCrypto(),
        )
    }
}
