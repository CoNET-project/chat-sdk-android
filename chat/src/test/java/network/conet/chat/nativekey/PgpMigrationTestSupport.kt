package network.conet.chat.nativekey

import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.security.SecureRandom

/** Shared fixtures for the PGP migration tests. Only synthetic keys from `spec/` and one generated key are used. */
internal object PgpMigrationKeys {
    internal class Key(val priv: String, val pub: String, val fp: String)

    /** Account the migration serves (canonical lower-case). */
    const val ACCOUNT = "0x2222222222222222222222222222222222222222"

    /** A different account, for the account-mismatch case. */
    const val OTHER = "0x1111111111111111111111111111111111111111"
    const val WORKSPACE = "default"

    private val nativeVectors: JSONObject =
        JSONObject(File("../spec/pgp-native-vectors.v1.json").readText(Charsets.UTF_8))
    private val keys: JSONObject = nativeVectors.getJSONObject("keys")

    /** `A`: the synthetic no-passphrase key of `pgp-native-vectors.v1.json`. */
    val a: Key = Key(
        keys.getJSONObject("ecc-nopass").getString("privateArmored"),
        keys.getJSONObject("ecc-nopass").getString("publicArmored"),
        keys.getJSONObject("ecc-nopass").getString("fingerprint").lowercase(),
    )

    /** `B`: a second no-passphrase key, generated once for these tests. */
    val b: Key = NativePgpKeyGen.generate("pgp-migration-test-b", SecureRandom()).let {
        Key(it.privateArmor, it.publicArmor, it.fingerprint.lowercase())
    }

    /** A private key with a passphrase: signing with an empty passphrase must fail on it. */
    val encrypted: String = keys.getJSONObject("ecc-pass").getString("privateArmored")

    fun byLabel(label: String): Key = when (label) {
        "A" -> a
        "B" -> b
        else -> throw IllegalArgumentException("unknown fingerprint label $label")
    }

    fun labelOf(fp: String?): String? = when (fp) {
        null -> null
        a.fp -> "A"
        b.fp -> "B"
        else -> "?$fp"
    }

    /** The first 16 characters, as the page sees it. */
    fun prefix16(fp: String): String = fp.take(16)
}

/** Faults for one step of a vector or one test. Each is applied only to the call it names. */
internal data class MigrationFaults(
    val writeN: Boolean = false,
    val rereadN: Boolean = false,
    val challenge: Boolean = false,
    val writeM: Boolean = false,
    val interruptAfterN: Boolean = false,
    val interruptAfterM: Boolean = false,
    val chainMode: String? = null,
    val approved: Boolean = true,
)

/** A staged store that fails, interrupts or rereads differently, as the faults say. Delegates everything else. */
internal class FaultyStaged(private val inner: MigrationStaged, private val faults: MigrationFaults) : MigrationStaged {
    private var wroteThisRun = false

    override fun read(): StagedItem? {
        if (faults.rereadN && wroteThisRun) return null
        return inner.read()
    }

    override fun write(item: StagedItem) {
        if (faults.writeN) throw IOException("injected write failure for N")
        inner.write(item)
        wroteThisRun = true
        if (faults.interruptAfterN) throw PgpMigrationInterrupted()
    }

    override fun delete() = inner.delete()
}

/** A marker store with the same fault rules for M. */
internal class FaultyMarker(private val inner: MigrationMarker, private val faults: MigrationFaults) : MigrationMarker {
    override fun read(): MarkerItem? = inner.read()

    override fun write(item: MarkerItem) {
        if (faults.writeM) throw IOException("injected write failure for M")
        inner.write(item)
        if (faults.interruptAfterM) throw PgpMigrationInterrupted()
    }

    override fun delete() = inner.delete()
}

/** The OpenPGP functions with the challenge fault applied: the verify step fails when asked. */
internal class FaultyCrypto(private val inner: MigrationCrypto, private val faults: MigrationFaults) : MigrationCrypto {
    override fun approved(): Boolean = inner.approved()

    override fun secretFingerprint(armor: String): String? = inner.secretFingerprint(armor)

    override fun publicFingerprint(armor: String): String? = inner.publicFingerprint(armor)

    override fun keyId(armor: String): String? = inner.keyId(armor)

    override fun sign(armor: String, label: String, message: ByteArray): String? = inner.sign(armor, label, message)

    override fun verify(armor: String, label: String, message: ByteArray, signature: String): Boolean {
        if (faults.challenge) return false
        return inner.verify(armor, label, message, signature)
    }
}

/** A legacy source that returns a fixed record, or nothing. Stands in for the SDK's pre-upgrade copy. */
internal class FixedLegacy(private val record: LegacyRecord?) : MigrationLegacy {
    override fun read(): LegacyRecord? = record
}

/** A chain source that answers as the mode says: a fixed registered fingerprint, a mismatch, or unreadable. */
internal class FixedChain(private val answer: ChainAnswer) : MigrationChain {
    override fun registered(eoa: String): ChainAnswer = answer
}

/** Builds the engine for one account over the given stores, with the given faults applied. */
internal fun migrationEngine(
    files: VaultFiles,
    wrap: KeyWrap,
    legacy: LegacyRecord?,
    chain: ChainAnswer,
    faults: MigrationFaults = MigrationFaults(),
    eoa: String = PgpMigrationKeys.ACCOUNT,
): PgpMigrationEngine = PgpMigrationEngine(
    eoa = eoa,
    legacy = FixedLegacy(legacy),
    staged = FaultyStaged(SealedStagedStore(wrap, files, eoa, PgpMigrationKeys.WORKSPACE), faults),
    marker = FaultyMarker(SealedMarkerStore(wrap, files, eoa, PgpMigrationKeys.WORKSPACE), faults),
    chain = FixedChain(chain),
    crypto = FaultyCrypto(NativeMigrationCrypto(approvedFlag = faults.approved), faults),
    random = SecureRandom(),
    now = { 1L },
)

/** The file names the migration uses for an account (for byte-level checks in tests). */
internal fun stagedFileName(eoa: String = PgpMigrationKeys.ACCOUNT): String =
    "pgp.v1.mig.${eoa.removePrefix("0x")}.${PgpMigrationKeys.WORKSPACE}.n"

internal fun markerFileName(eoa: String = PgpMigrationKeys.ACCOUNT): String =
    "pgp.v1.mig.${eoa.removePrefix("0x")}.${PgpMigrationKeys.WORKSPACE}.m"
