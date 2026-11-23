package network.conet.chat.nativekey

import android.content.Context
import android.os.Build
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import network.conet.chat.BeamioChatPgpStore
import network.conet.chat.BeamioChatWalletKeyStore
import network.conet.chat.ConetChatCryptoUtil
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AndroidKeyStore AES-256-GCM wrapping key (spec 25.17.5, alias `beamio.wallet.wrap.v1`). StrongBox is
 * tried first and the TEE used when it is not available. Not verified on a device in this build: the
 * behaviour of the real Keystore is a device-acceptance item.
 */
class AndroidKeyWrap(
    private val alias: String = KEY_ALIAS,
    /** True when sealed records exist in the vault directory (25.52Y.124 第 2 項 (a)). It throws when that cannot be told (unknown). */
    private val sealedRecordsExist: () -> Boolean = { false },
) : KeyWrap {
    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun existingKey(): SecretKey? = keyStore().getKey(alias, null) as? SecretKey

    private fun createKey(): SecretKey =
        try {
            generate(strongBox = true)
        } catch (e: Exception) {
            generate(strongBox = false)
        }

    private fun generate(strongBox: Boolean): SecretKey {
        if (strongBox && Build.VERSION.SDK_INT < 28) throw IllegalStateException("StrongBox needs API 28")
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
        if (strongBox && Build.VERSION.SDK_INT >= 28) spec.setIsStrongBoxBacked(true)
        gen.init(spec.build())
        return gen.generateKey()
    }

    /**
     * The alias state, from the enumeration only. It throws when the keystore cannot be enumerated: that is unknown, never absent
     * (25.52Y.122 第 1 項).
     */
    private fun aliasPresence(): WrapKeyPresence {
        val names = java.util.Collections.list(keyStore().aliases())
        return if (names.contains(alias)) WrapKeyPresence.PRESENT else WrapKeyPresence.CONFIRMED_ABSENT
    }

    /**
     * The key for a seal (25.52Y.124). A present alias is used, and an unusable one throws; it is never replaced. An alias confirmed absent fails
     * closed with [WrapKeyMissingException] when sealed records exist, and a first use with none creates the key. An enumeration failure throws
     * before any key is generated.
     */
    private fun sealKey(): SecretKey = resolveSealKey(
        presence = ::aliasPresence,
        sealedRecordsExist = sealedRecordsExist,
        existing = { existingKey() },
        create = { createKey() },
    )

    override fun presence(): WrapKeyPresence = try {
        aliasPresence()
    } catch (_: Exception) {
        WrapKeyPresence.UNKNOWN
    }

    override fun seal(aad: ByteArray, plain: ByteArray): ByteArray {
        val key = sealKey()
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key)
        c.updateAAD(aad)
        return c.iv + c.doFinal(plain)
    }

    /**
     *  (transient vs deterministic): a malformed input and an authentication failure (AEADBadTagException) are null (deterministic).
     * A keystore that cannot be read or used throws (transient, unknown): it is never folded into null.
     */
    override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? {
        if (sealed.size < 13) return null
        val key = try {
            keyStore().getKey(alias, null) as? SecretKey
        } catch (e: Exception) {
            throw java.io.IOException("keystore unavailable: ${e.javaClass.simpleName}")
        } ?: return null
        val c = try {
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed.copyOfRange(0, 12))); updateAAD(aad) }
        } catch (e: Exception) {
            throw java.io.IOException("keystore unusable: ${e.javaClass.simpleName}")
        }
        return try {
            c.doFinal(sealed.copyOfRange(12, sealed.size))
        } catch (_: javax.crypto.AEADBadTagException) {
            null
        } catch (e: Exception) {
            // Any other failure of the keystore operation is transient (unknown), never a deterministic corrupt record (X5).
            throw java.io.IOException("keystore operation failed: ${e.javaClass.simpleName}", e)
        }
    }

    override fun deleteKey(): Boolean = try {
        keyStore().deleteEntry(alias)
        !keyStore().containsAlias(alias)
    } catch (_: Exception) {
        false
    }

    companion object {
        const val KEY_ALIAS = "beamio.wallet.wrap.v1"

        /** The wrap of a vault directory: a seal fails closed when the alias is gone and sealed records remain in [dir] (25.52Y.124). */
        fun forDir(dir: java.io.File): AndroidKeyWrap = AndroidKeyWrap(KEY_ALIAS) { sealedRecordsIn(dir) }
    }
}

/** The seal plan of 25.52Y.124: (a) sealed records exist and the alias is gone: fail closed; (b) the alias is present: use it; (c) neither: first use. */
internal enum class SealKeyPlan { USE_EXISTING, WRAP_KEY_MISSING, CREATE_FIRST_USE }

/**
 * The seal decision (25.52Y.124) over its three probes, without a keystore: [presence] must answer PRESENT or CONFIRMED_ABSENT, and a probe that
 * cannot answer throws out unchanged (unknown). A key is created only on a confirmed-absent alias with no sealed record ([create]).
 */
internal fun <K : Any> resolveSealKey(
    presence: () -> WrapKeyPresence,
    sealedRecordsExist: () -> Boolean,
    existing: () -> K?,
    create: () -> K,
): K {
    val p = presence()
    check(p != WrapKeyPresence.UNKNOWN) { "an unknown wrap presence is never absent" }
    val records = sealedRecordsExist()
    return when (sealKeyPlan(p == WrapKeyPresence.PRESENT, records)) {
        SealKeyPlan.USE_EXISTING -> existing() ?: throw IllegalStateException("wrap key unavailable")
        SealKeyPlan.WRAP_KEY_MISSING -> throw WrapKeyMissingException()
        SealKeyPlan.CREATE_FIRST_USE -> create()
    }
}

/** Pure form of the seal decision. [aliasPresent] comes from a successful enumeration; an unknown enumeration never reaches this function. */
internal fun sealKeyPlan(aliasPresent: Boolean, sealedRecordsExist: Boolean): SealKeyPlan = when {
    aliasPresent -> SealKeyPlan.USE_EXISTING
    sealedRecordsExist -> SealKeyPlan.WRAP_KEY_MISSING
    else -> SealKeyPlan.CREATE_FIRST_USE
}

/**
 * Whether sealed records exist in [dir] (25.52Y.124 第 2 項 (a)). An isolated file (25.52Y.128) and the audit are kept for the record of the loss and
 * do not count: a new key may be created after the isolation (第 2 項 (b)). A listing that fails throws (unknown).
 */
internal fun sealedRecordsIn(dir: File): Boolean {
    if (!dir.exists()) return false
    val names = dir.list() ?: throw IOException("vault directory cannot be listed")
    return names.any { isSealedRecordName(it) }
}

internal fun isSealedRecordName(name: String): Boolean =
    !name.contains(".isolated.") && name != NativeWalletVault.AUDIT && name != NativeWalletVault.PENDING &&
        name != NativeWalletVault.RETAINED

/** Files under the app's private directory. Writes go to a temp file, are synced, then renamed. */
class AndroidVaultFiles(private val dir: File) : VaultFiles {
    /**
     * The bytes of [name], or null only when the name is absent from a readable directory. A name present but not a regular file, or a directory
     * that exists but cannot be listed, is a read failure (throws): it is never taken for "no record", which would answer no_key (25.52Y.84).
     */
    override fun read(name: String): ByteArray? {
        val f = File(dir, name)
        // Absent is only NoSuchFileException from the stat. Any other failure (permission, I/O, a parent that is not a directory) is a read
        // failure: unknown, never "no record" (Y.104 第 3 条, Y.105 第 2 条).
        val attributes = try {
            java.nio.file.Files.readAttributes(f.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java)
        } catch (_: java.nio.file.NoSuchFileException) {
            if (dir.exists() && dir.list() == null) throw IOException("vault directory cannot be listed")
            return null
        } catch (e: IOException) {
            throw IOException("vault entry cannot be read", e)
        }
        if (!attributes.isRegularFile) throw IOException("vault entry is not a regular file")
        return f.readBytes()
    }

    override fun write(name: String, bytes: ByteArray) {
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("vault directory unavailable")
        val tmp = File(dir, "$name.tmp")
        FileOutputStream(tmp).use { out ->
            out.write(bytes)
            out.flush()
            out.fd.sync()
        }
        if (!tmp.renameTo(File(dir, name))) {
            tmp.delete()
            throw IOException("vault rename failed")
        }
    }

    override fun exists(name: String): Boolean = File(dir, name).exists()

    /** One move, never a replacement (25.52Y.128 第 3 项 (a)): the source is a regular file and the target is absent. The write path only. */
    override fun rename(from: String, to: String) {
        val src = File(dir, from)
        val dst = File(dir, to)
        if (!src.isFile) throw IOException("vault rename source is not a file")
        if (dst.exists()) throw IOException("vault rename target exists")
        java.nio.file.Files.move(src.toPath(), dst.toPath())
    }

    /**
     * Removes the file and its temp leftover. A removal that does not take effect throws (the file is still there), so no caller can take a
     * failed removal for a done one (spec 25.25.5, 25.52Y.42 第 4 项 (e)).
     */
    override fun delete(name: String) {
        for (f in listOf(File(dir, name), File(dir, "$name.tmp"))) {
            if (f.exists() && !f.delete() && f.exists()) throw IOException("vault delete failed")
        }
    }

    /**
     * The file names in the vault directory (25.52Y.136 第 8 項 uses them for the isolation of every sealed record, and the page-copy discovery
     * (§25.52AD.2) reads them too). Empty when the directory does not exist; a directory that cannot be listed throws (unknown).
     */
    override fun names(): List<String> = if (!dir.exists()) emptyList() else dir.list()?.toList() ?: throw IOException("vault directory cannot be listed")
}

/** The app's single native wallet vault, and the one-time adoption of the pre-upgrade key. */
object NativeWallet {
    private const val DIR = "native_wallet_v1"

    @Volatile
    private var instance: NativeWalletVault? = null

    /** The directory the vault and the PGP migration store their sealed files in (same wrap key). */
    internal fun migrationFiles(context: Context): VaultFiles =
        AndroidVaultFiles(File(context.applicationContext.filesDir, DIR))

    /** The wrap of the vault directory (25.52Y.124). Used by the PGP migration engine, which seals in the same directory. */
    internal fun keyWrap(context: Context): AndroidKeyWrap = AndroidKeyWrap.forDir(File(context.applicationContext.filesDir, DIR))

    /** The file names in the vault directory (for the identity clear, which must find PGP records without an account). */
    internal fun migrationNames(context: Context): List<String> =
        (migrationFiles(context) as? AndroidVaultFiles)?.names().orEmpty()

    /** The single background thread of the startup hook (one per process). */
    private val startupExecutor: java.util.concurrent.ExecutorService = java.util.concurrent.Executors.newSingleThreadExecutor()

    /**
     * Test seam (bridge state drive, 2026-11-20): installs [vault] as the process vault, or restores the Keystore-backed factory with null.
     * The vault is built from the test doubles, so no Keystore is read. Production never calls it.
     */
    internal fun installVaultForTest(vault: NativeWalletVault?) {
        synchronized(this) { instance = vault }
    }

    fun vault(context: Context): NativeWalletVault =
        instance ?: synchronized(this) {
            instance ?: NativeWalletVault(
                AndroidKeyWrap.forDir(File(context.applicationContext.filesDir, DIR)),
                AndroidVaultFiles(File(context.applicationContext.filesDir, DIR)),
            ).also {
                // The startup hook of the narrow discard (review) can read the keystore, and the factory is called from command paths that may run
                // on the main thread. It runs once per process on a background executor. Until it finishes, a pending intent makes the state
                // Locked(discard_pending) (unknown), and a second start is decided by the hook itself; nothing is returned as a confirmed state.
                instance = it
                startupExecutor.execute { it.completeDiscardAtStartup() }
            }
        }

    /**
     * Upgrade path: when the vault is empty and the pre-upgrade store (`BeamioChatWalletKeyStore`) holds a
     * wallet key that decrypts, the key is imported into the vault. The old copy is removed only after the
     * vault has confirmed it. Returns `true` when a key was adopted.
     *
     * S25 ANR (2026-11-19): never open AndroidKeyStore on the main / WebView bridge thread. When called on the
     * main looper, schedules a once-per-process adoption on [startupExecutor] and returns `false` immediately.
     */
    @Synchronized
    fun migrateLegacy(context: Context): Boolean {
        val app = context.applicationContext
        if (legacyGate.isResolved()) return false
        if (isMainThread()) {
            scheduleLegacyAdoptionOffMain(app)
            return false
        }
        // F1 (2026-11-20): refresh only when this attempt adopted; an unsettled gate must not clear the snapshot on every command.
        return legacyGate.run { migrateLegacyOutcome(app) }.also { if (it) refreshVaultSnapshotAfterLegacy(app) }
    }

    /** Set by the module before any adoption (2026-11-20): the start-up legacy report reader. Null means the report is unknown. */
    @Volatile
    internal var legacyReportReader: ((Context) -> LegacyReportState)? = null

    /** True when the once-per-process wallet legacy gate has a definitive result (adopted or nothing). */
    fun isLegacyWalletAdoptionSettled(): Boolean = legacyGate.isResolved()

    /** True while a background legacy wallet/PGP adoption kick is queued or running. */
    fun isLegacyWalletAdoptionInFlight(): Boolean = legacyAdoptionKick.get()

    /** Once per process (hotfix): a definitive result is remembered; a read fault or an unfinished write is retried after a delay (see [MigrationGate]). */
    private val legacyGate = MigrationGate(now = { System.currentTimeMillis() })
    private val legacyPgpGate = MigrationGate(now = { System.currentTimeMillis() })
    private val legacyAdoptionKick = AtomicBoolean(false)

    private fun isMainThread(): Boolean = Looper.myLooper() == Looper.getMainLooper()

    /**
     * Schedules wallet + PGP legacy adoption on [startupExecutor]. Idempotent while a kick is in flight.
     * Must not call [migrateLegacy] / [migrateLegacyPgp] from the worker (those re-check the main thread).
     */
    private fun scheduleLegacyAdoptionOffMain(app: Context) {
        if (legacyGate.isResolved() && legacyPgpGate.isResolved()) return
        if (!legacyAdoptionKick.compareAndSet(false, true)) return
        startupExecutor.execute {
            try {
                // F1 (2026-11-20): the snapshot is refreshed only when an adoption wrote something.
                val walletAdopted = legacyGate.run { migrateLegacyOutcome(app) }
                val pgpAdopted = legacyPgpGate.run { migrateLegacyPgpOutcome(app) }
                if (walletAdopted || pgpAdopted) refreshVaultSnapshotAfterLegacy(app)
            } finally {
                legacyAdoptionKick.set(false)
            }
        }
    }

    private fun refreshVaultSnapshotAfterLegacy(app: Context) {
        try {
            vault(app).invalidateSnapshot()
        } catch (_: Exception) {
            // Vault may still be constructing; snapshot refresh below still helps.
        }
        VaultSnapshotRefresh.schedule(app)
    }

    /**
     * Stopped (2026-11-22, the same as the iOS walletKey stop). The pre-upgrade wallet key
     * (`BeamioChatWalletKeyStore`) is shipped data: it is never read here, never imported into the vault and never removed.
     * It is not a basis for deciding the account. The gate resolves to nothing, so the vault stays as it is.
     */
    @Suppress("UNUSED_PARAMETER")
    private fun migrateLegacyOutcome(app: Context): MigrationGate.Outcome = MigrationGate.Outcome.RESOLVED_NOTHING

    /**
     * The PGP vault of the wallet's active account. Without a wallet key it serves no record ([NativePgpVault.NO_ACCOUNT]).
     * Each account has its own PGP record in the same directory and wrap key; the wallet record is not touched.
     */
    internal fun pgp(context: Context): NativePgpVault {
        val app = context.applicationContext
        val eoa = (vault(app).state() as? NativeWalletVault.State.Ready)?.eoa ?: NativePgpVault.NO_ACCOUNT
        return pgpFor(app, eoa)
    }

    /**
     * Inbound PGP decryption (2026-11-22): the shipped PGP store decides when its private armor exists (read only, LegacyPgpReader);
     * otherwise the native PGP vault decrypts. Nothing is written by either path.
     */
    internal fun decryptInbound(context: Context, armored: String): NativePgp.Outcome {
        val app = context.applicationContext
        val shipped = LegacyPgpReader.shippedArmor(app)
        return if (shipped != null) LegacyPgpReader.decryptWith(shipped, armored) else pgp(app).decryptInbound(armored)
    }

    /** The literal form of [decryptInbound] (same precedence). */
    internal fun decryptInboundLiteral(context: Context, armored: String): NativePgp.LiteralResult {
        val app = context.applicationContext
        val shipped = LegacyPgpReader.shippedArmor(app)
        return if (shipped != null) LegacyPgpReader.decryptLiteralWith(shipped, armored) else pgp(app).decryptInboundLiteral(armored)
    }

    /** The active PGP record of [eoa]. A value that is not a canonical address serves no record. */
    internal fun pgpFor(context: Context, eoa: String): NativePgpVault =
        NativePgpVault(
            AndroidKeyWrap.forDir(File(context.applicationContext.filesDir, DIR)),
            AndroidVaultFiles(File(context.applicationContext.filesDir, DIR)),
            accountOrNone(eoa),
        )

    /**
     * The restore device for [eoa] (P-IMP-PGP): the same wrap and files as [pgpFor], so a restored record is the one that
     * [pgpFor] reads afterwards.
     */
    internal fun pgpRestoreDevice(context: Context, eoa: String, id: String): PgpRestoreDevice =
        PgpRestoreDevice(
            id,
            accountOrNone(eoa),
            AndroidKeyWrap.forDir(File(context.applicationContext.filesDir, DIR)),
            AndroidVaultFiles(File(context.applicationContext.filesDir, DIR)),
        )

    /** The pending slot of [eoa]: a generated key awaiting its registration. It is never the active identity. */
    internal fun pendingPgpFor(context: Context, eoa: String): NativePgpVault =
        NativePgpVault(
            AndroidKeyWrap.forDir(File(context.applicationContext.filesDir, DIR)),
            AndroidVaultFiles(File(context.applicationContext.filesDir, DIR)),
            accountOrNone(eoa),
            NativePgpVault.Slot.PENDING,
        )

    private fun accountOrNone(eoa: String): String {
        val lower = eoa.lowercase()
        return if (Regex("^0x[0-9a-f]{40}$").matches(lower)) lower else NativePgpVault.NO_ACCOUNT
    }

    /**
     * Upgrade path for the PGP key. When the EOA record is present and the PGP record is not, and the pre-upgrade PGP
     * store holds a private key for the same account, the key is copied into the vault. The legacy copy is kept: this
     * version never clears L (r3as §25.52.3, PGP migration U5), and the migration reads it. The legacy store never held a
     * passphrase; the passphrase arrives with `init`. Returns `true` when a key was adopted.
     */
    @Synchronized
    fun migrateLegacyPgp(context: Context): Boolean {
        val app = context.applicationContext
        if (legacyPgpGate.isResolved()) return false
        if (isMainThread()) {
            scheduleLegacyAdoptionOffMain(app)
            return false
        }
        // F1 (2026-11-20): refresh only when this attempt adopted (see migrateLegacy).
        return legacyPgpGate.run { migrateLegacyPgpOutcome(app) }.also { if (it) refreshVaultSnapshotAfterLegacy(app) }
    }

    private fun migrateLegacyPgpOutcome(app: Context): MigrationGate.Outcome {
        // F2 (2026-11-20): no legacy PGP armor means nothing to adopt, whatever the wallet state, so the gate settles
        // (a fresh install has no wallet and no armor). A read failure of the armor throws and is unknown (MigrationGate.run).
        // With armor present and no wallet the result stays unknown (pending).
        // F2 (2026-11-20): the armor read is strict. A store that cannot be read is unknown, never "no armor".
        // F3: an orphan armor with a confirmed no-wallet state settles and the armor stays as it is.
        val armorRead = BeamioChatPgpStore.legacyPrivateArmorStrict(app)
        legacyPgpPrecheck(armorRead, noWalletConfirmed = {
            noWalletConfirmedBy(MnemonicPreread.vaultAnswerOrUnknown(vault(app)) {
                // The reader is injected by the module before any adoption (G-LR-2). Without it the report is unknown (fail closed).
                legacyReportReader?.invoke(app) ?: throw IllegalStateException("legacy report reader not set")
            })
        })?.let { return it }
        // 2026-11-22: the native PGP vault is an unpublished format and is not written here (no adoption, no vault record). The shipped
        // armor is read in place for inbound decryption (LegacyPgpReader); the stored armor is never changed.
        if (armorRead == null) return MigrationGate.Outcome.UNKNOWN
        return MigrationGate.Outcome.RESOLVED_NOTHING
    }
}

/**
 * The precheck of the legacy PGP adoption (2026-11-20, F2 and F3). `null` continues to the adoption. An armor read that failed is unknown
 * (never "no armor"); no armor is nothing; an armor with a confirmed no-wallet state is nothing, and the armor is not touched. A wallet read
 * that throws propagates (MigrationGate.run takes it as unknown).
 */
internal fun legacyPgpPrecheck(armor: String?, noWalletConfirmed: () -> Boolean): MigrationGate.Outcome? = when {
    armor == null -> MigrationGate.Outcome.UNKNOWN
    !armor.contains("BEGIN PGP PRIVATE KEY") -> MigrationGate.Outcome.RESOLVED_NOTHING
    noWalletConfirmed() -> MigrationGate.Outcome.RESOLVED_NOTHING
    else -> null
}

/**
 * F3 (2026-11-20): the no-wallet settle needs the pre-read to answer Absent: the current phrase, the isolated copies and the
 * legacy report all say no phrase. A read fault of any of them is unknown (MnemonicPreread.vaultAnswerOrUnknown). A REC or MARK fault alone
 * does not change this answer (E9.1-3); the phrase source decides.
 */
internal fun noWalletConfirmedBy(answer: MnemonicPreread.Answer): Boolean = answer is MnemonicPreread.Answer.Absent

/**
 * Owner of the stored legacy PGP record: `""` when none is stored, the normalised EOA otherwise, and `null` when the stored
 * value cannot be read. `null` is unknown: the caller adopts nothing and writes nothing.
 */
internal fun readLegacyOwnerEoa(read: () -> String?): String? =
    try {
        read()?.trim()?.lowercase().orEmpty()
    } catch (_: IOException) {
        null
    }

/**
 * The wallet EOA a legacy PGP key may be adopted into, or null. The wallet is read first; the PGP state is read only when the
 * wallet is known. A read that throws [IOException] is unknown and refuses the adoption.
 */
internal fun legacyAdoptionEoa(readWalletEoa: () -> String?, readPgpIsNoKey: (String) -> Boolean): String? {
    val eoa: String = (try { readWalletEoa() } catch (_: IOException) { null }) ?: return null
    val noKey = try {
        readPgpIsNoKey(eoa)
    } catch (_: IOException) {
        return null
    }
    return if (noKey) eoa else null
}
