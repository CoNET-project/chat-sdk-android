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
}

/** A legacy record from text armor, as the tests build it. */
internal fun legacyRecord(eoa: String, priv: String, pub: String): LegacyRecord =
    LegacyRecord(eoa, priv.toByteArray(Charsets.UTF_8), pub.toByteArray(Charsets.UTF_8))

/**
 * Store, crypto and chain faults for one step of a vector or one test. Each is applied only to the call it names. Interruptions
 * are not here: they go through the checkpoint closure ([checkpointFor]), as §25.52C.4 requires.
 */
internal data class MigrationFaults(
    val writeN: Boolean = false,
    val rereadN: Boolean = false,
    val challenge: Boolean = false,
    val writeM: Boolean = false,
    val chainMode: String? = null,
    val approved: Boolean = true,
    val interrupt: String? = null,
)

/** The checkpoint closure for a fault set: throws [PgpMigrationInterrupted] at the named stage, and does nothing else. */
internal fun checkpointFor(faults: MigrationFaults): (Stage) -> Unit = { stage ->
    val stop = when (stage) {
        Stage.AFTER_STAGED_WRITE -> faults.interrupt == "afterN"
        Stage.AFTER_MARKER_WRITE -> faults.interrupt == "afterM"
        Stage.AFTER_MARKER_DELETED -> faults.interrupt == "afterMarkerDeleted"
        else -> false
    }
    if (stop) throw PgpMigrationInterrupted()
}

/** A staged store that fails or rereads differently, as the faults say. Delegates everything else. */
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
    }

    override fun delete() = inner.delete()
}

/** A marker store with the same fault rules for M. */
internal class FaultyMarker(private val inner: MigrationMarker, private val faults: MigrationFaults) : MigrationMarker {
    override fun read(): MarkerItem? = inner.read()

    override fun write(item: MarkerItem) {
        if (faults.writeM) throw IOException("injected write failure for M")
        inner.write(item)
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

/** A chain source that answers with a fixed answer. */
internal class FixedChain(private val answer: ChainAnswer) : MigrationChain {
    override fun registered(eoa: String): ChainAnswer = answer
}

/** Recovery sources with fixed answers (§25.52C.3). */
internal class FixedRecovery(private val p: Boolean, private val chain: Boolean) : MigrationRecovery {
    override fun pReadable(): Boolean = p

    override fun chainRegistered(): Boolean = chain
}

/** An account lock that is either free, or held by another operation (`busy`, §25.52I.8). */
internal class FixedLock(private val busy: Boolean) : MigrationLock {
    override fun <T> tryRun(eoa: String, block: () -> T): T? = if (busy) null else block()
}

/** Builds the engine for one account over the given stores, with the given faults applied. */
internal fun migrationEngine(
    files: VaultFiles,
    wrap: KeyWrap,
    legacy: LegacyRecord?,
    chain: ChainAnswer,
    faults: MigrationFaults = MigrationFaults(),
    recovery: MigrationRecovery = FixedRecovery(p = false, chain = false),
    primary: LegacyRecord? = null,
    eoa: String = PgpMigrationKeys.ACCOUNT,
    busy: Boolean = false,
): PgpMigrationEngine = PgpMigrationEngine(
    eoa = eoa,
    legacy = FixedLegacy(legacy),
    primary = primary,
    staged = FaultyStaged(SealedStagedStore(wrap, files, eoa, PgpMigrationKeys.WORKSPACE), faults),
    marker = FaultyMarker(SealedMarkerStore(wrap, files, eoa, PgpMigrationKeys.WORKSPACE), faults),
    lastCode = FileLastCodeStore(files, eoa, PgpMigrationKeys.WORKSPACE),
    chain = FixedChain(chain),
    crypto = FaultyCrypto(NativeMigrationCrypto(approvedFlag = faults.approved), faults),
    recovery = recovery,
    lock = FixedLock(busy),
    random = SecureRandom(),
    now = { 1L },
)

/** The file names the migration uses for an account (for byte-level checks in tests). */
internal fun stagedFileName(eoa: String = PgpMigrationKeys.ACCOUNT): String =
    "pgp.v1.mig.${eoa.removePrefix("0x")}.${PgpMigrationKeys.WORKSPACE}.n"

internal fun markerFileName(eoa: String = PgpMigrationKeys.ACCOUNT): String =
    "pgp.v1.mig.${eoa.removePrefix("0x")}.${PgpMigrationKeys.WORKSPACE}.m"

internal fun lastCodeFileName(eoa: String = PgpMigrationKeys.ACCOUNT): String =
    "pgp.v1.mig.${eoa.removePrefix("0x")}.${PgpMigrationKeys.WORKSPACE}.last"
