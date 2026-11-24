package network.conet.chat.nativekey

import android.content.Context
import network.conet.chat.BeamioChatPgpStore

/**
 * The runtime upgrade of K_pgp for an account that has W but no K_pgp .
 *
 *  - K_pgp already there: kept.
 *  - The native PGP vault holds a record (L, ready): K_pgp is written from it, and L is never deleted (the original path, unchanged).
 *  - The vault slot is empty: [AutoRecovery]: the registered public key is read, a candidate (the old key in the SDK store, then the chain
 *    backup) signs a fresh challenge that the registered key verifies, and only then is the vault written, then K_pgp mirrored.
 *  - Anything else, or a source that does not verify: pgp_migration_retry, never a silent new key. A new key is generated only on the user's
 *    explicit click; this function does not generate it.
 */
internal object KpgpUpgrade {
    /** The native PGP record of the account: its private armor and its subkey keyId, as the vault reports them. */
    internal class LRecord(val privateArmor: String, val subkeyKeyId: String)

    /** The action codes of the first-identity run (the module settles on [FIRST_IDENTITY_REGISTERED]; anything else is released with a delay). */
    const val FIRST_IDENTITY_REGISTERED = "first_identity_registered"
    const val FIRST_IDENTITY_RETRY = "first_identity_retry"

    /** The production first-identity run for [eoa]. [storeAccount] is the store account of a vault with no record (its key signs the registration). */
    private fun firstIdentity(
        app: Context,
        eoa: String,
        store: AccountPgpK,
        storeAccount: StoreAwareAccount.Resolution.Account?,
        nowSec: Long,
        mode: FirstIdentityCoordinator.Mode,
    ): FirstIdentityCoordinator.Result {
        val dev = NativeWallet.pgpRestoreDevice(app, eoa, "first")
        val vault = NativeWallet.vault(app)
        val t = DiagTiming.now()
        val routeOnce: () -> RouteChoice = run {
            var chosen: RouteChoice? = null
            val pick: () -> RouteChoice = {
                chosen ?: run {
                    val candidates = try {
                        BeamioChatPgpStore.loadSiNodes(app)
                            .filter { it.domain.isNotBlank() && it.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY") }
                            .map { it.domain }.shuffled()
                    } catch (_: Exception) {
                        null
                    }
                    val result = if (candidates == null) {
                        RouteChoice.Unreadable
                    } else {
                        val rpc = RouteRecorded.failover(AddressPgpConfig.default.endpoints.map { ep -> AddressPgpRead.HttpRpc(ep.url, ep.timeoutMs) })
                        RouteRecorded.pick(candidates, { id -> RouteRecorded.isRecorded(id, rpc) })
                    }
                    // An unreadable check is not remembered: the next ask (a retry) checks again.
                    if (result !is RouteChoice.Unreadable) chosen = result
                    result
                }
            }
            pick
        }
        val coordinator = FirstIdentityCoordinator(
            eoa = eoa,
            dev = dev,
            k = store,
            readKey = { readAgreedTimed(eoa).registeredKey() },
            readIdentity = { ProductionIdentityRead.read(eoa) },
            legacyKeyPresent = {
                try {
                    LegacyArmorRestore.candidate(eoa, BeamioChatPgpStore.legacyCopy(app)) is LegacyArmorRestore.Candidate.Present
                } catch (_: Exception) {
                    null
                }
            },
            // One route for the whole run: the stored roster in random order, the first node that AddressPGP and GuardianNodesInfoV6 both record
            // (the PWA's pickRecordedMailbox rule); a failed read picks nothing. Memoized, so the decision and the submission use the same node.
            chooseRoute = routeOnce,
            eoaKey = { if (storeAccount == null) vault.unlock() else StoreAwareAccount.keyOf(app, storeAccount) },
            bases = FIRST_IDENTITY_BASES,
            poster = ChatRouteSubmit.HttpPoster,
            nowMs = { nowSec * 1000L },
            log = { code -> DiagTiming.log("firstIdentity", t, code) },
            emit = { status -> FirstIdentityEvents.emit(eoa, status) },
            lockState = { lockStateOf(app, eoa, storeAccount) },
            mode = mode,
        )
        return coordinator.run()
    }

    /**
     * Whether the material the account's key needs is available now (the SDK keeps no application-level or UI lock and never reads
     * one). Only two things block: (a) the passcode package is not provided (a store v3 set the session has no key for), answered
     * `passcode_not_provided`; (b) the storage state cannot be read, answered unknown with no reason. Nothing else, and no UI or app lock state, is read.
     * A vault Locked state is a storage state (a marker, a record, a pending write), never the passcode: it is unknown, not locked.
     */
    internal fun lockStateOf(app: Context, eoa: String, storeAccount: StoreAwareAccount.Resolution.Account?): LockState = try {
        if (storeAccount != null) {
            lockStateOfStore(StoreAwareAccount.resolveOnDevice(app), eoa)
        } else {
            // The snapshot only: this is asked at several points of a run on the module thread, and the vault's monitor may be held for a long time by a
            // cold compute. No snapshot yet is unknown (never unlocked), so the run waits and asks again.
            lockStateOfVault(NativeWallet.vault(app).snapshotState(), eoa)
        }
    } catch (_: Exception) {
        LockState.UNKNOWN
    }

    /**
     * A vault account: unlocked when its vault is Ready for [eoa]; locked only when the vault is Locked for the passcode package
     * ([NativeWalletVault.PASSCODE_REQUIRED], answered `passcode_not_provided`); every other state (a marker, a record, a pending write, a discard) is a
     * storage state that cannot be read: unknown, no reason.
     */
    internal fun lockStateOfVault(state: NativeWalletVault.State?, eoa: String): LockState = when {
        state is NativeWalletVault.State.Ready -> if (state.eoa.equals(eoa, ignoreCase = true)) LockState.UNLOCKED else LockState.UNKNOWN
        state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.PASSCODE_REQUIRED -> LockState.LOCKED
        else -> LockState.UNKNOWN
    }

    /** A store account: the store resolves it for this session (unlocked), needs the passcode package (locked), or cannot say (unknown). */
    internal fun lockStateOfStore(resolution: StoreAwareAccount.Resolution, eoa: String): LockState = when (resolution) {
        is StoreAwareAccount.Resolution.Account -> if (resolution.eoa.equals(eoa, ignoreCase = true)) LockState.UNLOCKED else LockState.UNKNOWN
        is StoreAwareAccount.Resolution.NotReady -> if (resolution.reason == NoKeyGate.NOT_READY_PASSCODE_REQUIRED) LockState.LOCKED else LockState.UNKNOWN
        StoreAwareAccount.Resolution.NoKey -> LockState.UNKNOWN
    }

    /** The registration endpoint bases (the same as the page's `chatRouteRegister`). */
    internal val FIRST_IDENTITY_BASES: List<String> = listOf("https://beamio.ca")

    /** The two-endpoint read, with its duration and the sub-reason of a failure logged as a code (the SDK log only). */
    private fun readAgreedTimed(eoa: String): AddressPgpChain {
        val t = DiagTiming.now()
        val chain = AddressPgpChain.readAgreed(eoa) { ep -> AddressPgpRead.HttpRpc(ep.url, ep.timeoutMs) }
        DiagTiming.log("autorecovery.chainread", t, chain.registeredKeyFailure() ?: "ok")
        return chain
    }

    /** The decision for [eoa], writing K_pgp from a valid L record. [record] null means no native record. */
    fun upgrade(
        k: AccountPgpK,
        eoa: String,
        record: LRecord?,
        userClick: Boolean,
        nowSec: Long,
        nativeConfirm: Boolean = false,
        /** The registered public armor (the bytes the chain holds, decoded); when given, K gets it instead of the armor derived from the private key. */
        registeredPublicArmor: String? = null,
    ): KpgpPolicy.Expect {
        val existing = try {
            k.read(eoa, PgpMigrationPolicy.WORKSPACE) != null
        } catch (_: Exception) {
            // An unreadable K is not an absent one: the upgrade does not run (fail closed).
            return KpgpPolicy.Expect("pgp_migration_retry", emptyList(), emptyList(), "pgp_migration_retry", rollback = true)
        }
        if (existing) return KpgpPolicy.decide(KpgpPolicy.Input(kind = "upgrade", kPgpExists = true))
        val publicArmor = record?.let { NativePgpKeyGen.publicArmorOf(it.privateArmor) }
        val keyIdOfRecord = record?.let { r -> NativePgp.parseSecret(r.privateArmor)?.let { NativePgpBackup.subkeyKeyId(it) } }
        val lValid = record != null && publicArmor != null && keyIdOfRecord != null && keyIdOfRecord == record.subkeyKeyId
        // keyID consistency log (rc2.2-qa item 4): match, mismatch or unknown. The local key and the local keyID are never logged.
        val lCheck = when {
            record == null || keyIdOfRecord == null -> "unknown"
            keyIdOfRecord == record.subkeyKeyId -> "match"
            else -> "mismatch"
        }
        DiagTiming.log("kpgp.keyid", DiagTiming.now(), "L=$lCheck")
        var writeOk = false
        if (lValid && record != null && publicArmor != null && keyIdOfRecord != null) {
            val tW = DiagTiming.now()
            writeOk = k.writeIfAbsent(eoa, PgpMigrationPolicy.WORKSPACE, keyIdOfRecord, registeredPublicArmor ?: publicArmor, record.privateArmor, nowSec) ==
                AccountPgpKWrite.WRITTEN
            // origin log (25.52Y.84 request): the label, the time and the code only. No key, no keyID.
            DiagTiming.log("kpgp.write:upgradeL", tW, if (writeOk) "ok" else "fail")
        }
        return KpgpPolicy.decide(
            KpgpPolicy.Input(
                kind = "upgrade",
                kPgpExists = false,
                writeOk = writeOk,
                readbackOk = writeOk,
                lPresent = record != null,
                lValid = lValid,
                userClick = userClick,
                nativeConfirm = nativeConfirm,
            ),
        )
    }

    /**
     * The device wrapper. K_pgp present: kept. A ready vault record: the original path. An empty vault slot: [AutoRecovery] with the account's key
     * (a Ready wallet vault, or [storeAccount] of a vault with no record) used only in native code to open the chain backup. A locked slot is left
     * alone. [DiagTiming] gets reason codes only.
     */
    fun fromDevice(
        app: Context,
        eoa: String,
        userClick: Boolean,
        nowSec: Long,
        nativeConfirm: Boolean = false,
        storeAccount: StoreAwareAccount.Resolution.Account? = null,
    ): KpgpPolicy.Expect {
        val store = AccountPgpK.forDevice(app)
        return orchestrate(
            firstIdentityEnabled = network.conet.chat.BuildConfig.IDENTITY_STATE_EVENTS_QA,
            vaultNow = { vaultStateNow(app, eoa) },
            runFirst = { mode -> firstIdentity(app, eoa, store, storeAccount, nowSec, mode) },
            base = { fromDeviceBase(app, eoa, userClick, nowSec, nativeConfirm, storeAccount, store) },
        )
    }

    /**
     * The vault state of [eoa]'s active slot, from the public snapshot when it has a valid entry (no Keystore), else one read ([NativePgpVault.readOnce])
     * that also fills the snapshot. Only the kind matters to the caller: Ready, NoKey, or anything else (null or Locked).
     */
    private fun vaultStateNow(app: Context, eoa: String): NativePgpVault.State? = try {
        val pgp = NativeWallet.pgpFor(app, eoa)
        when (val l = PublicIdentitySnapshot.lookup(pgp.account, pgp.fileSignature())) {
            is PublicIdentitySnapshot.Lookup.Hit -> when (l.facts.kind) {
                PublicIdentitySnapshot.Kind.READY -> NativePgpVault.State.Ready(l.facts.fingerprint ?: "")
                PublicIdentitySnapshot.Kind.NO_KEY -> NativePgpVault.State.NoKey
                PublicIdentitySnapshot.Kind.UNKNOWN -> NativePgpVault.State.Locked("unknown")
            }
            PublicIdentitySnapshot.Lookup.Miss -> pgp.readOnce(wantArmor = false).also { PublicIdentitySnapshot.store(pgp.account, it) }.state
        }
    } catch (_: Exception) {
        null
    }

    /**
     * The order of [fromDevice], with the steps as seams so it can be tested without a device.
     *
     * The first-identity machine (generate a key, register it, discard a K-only key, resume a pending one, activate) runs ONLY when
     * [firstIdentityEnabled] (a QA build; production builds enable it only after acceptance).
     * In the default build it is never started for an account with no vault key: that account takes the recovery ([base]) as before.
     *
     * Not part of that switch, and run in every build: the recovery and the reconciliation of an ACTIVE key's registration with the same key
     * ([FirstIdentityCoordinator.Mode.RECONCILE_ONLY]: no generation, no pending key, no K-only discard).
     */
    internal fun orchestrate(
        firstIdentityEnabled: Boolean,
        vaultNow: () -> NativePgpVault.State?,
        runFirst: (FirstIdentityCoordinator.Mode) -> FirstIdentityCoordinator.Result,
        base: () -> KpgpPolicy.Expect,
    ): KpgpPolicy.Expect {
        val state = vaultNow()
        // An account with no vault key goes through the first-identity coordinator first (a pending key resumes, a
        // confirmed no-record chain generates and registers; a registered chain is the recovery below).
        if (firstIdentityEnabled && state is NativePgpVault.State.NoKey) {
            when (val first = runFirst(FirstIdentityCoordinator.Mode.FULL)) {
                is FirstIdentityCoordinator.Result.Registered ->
                    return KpgpPolicy.Expect(FIRST_IDENTITY_REGISTERED, emptyList(), emptyList(), FIRST_IDENTITY_REGISTERED)
                is FirstIdentityCoordinator.Result.RetryLater, is FirstIdentityCoordinator.Result.Failed, is FirstIdentityCoordinator.Result.Conflict ->
                    return KpgpPolicy.Expect(FIRST_IDENTITY_RETRY, emptyList(), emptyList(), FIRST_IDENTITY_RETRY, rollback = true)
                else -> Unit
            }
        }
        val result = base()
        // An active key (restored or older): its registration is reconciled with the same key, once per process (the trigger settles on the base
        // answer). A missing route or no record submits that key; another key on the chain is a conflict and is left alone (no retry loop). Every build.
        if (state is NativePgpVault.State.Ready && result.action in SETTLED_ACTIONS) {
            val mode = if (firstIdentityEnabled) FirstIdentityCoordinator.Mode.FULL else FirstIdentityCoordinator.Mode.RECONCILE_ONLY
            val rec = runFirst(mode)
            if (rec is FirstIdentityCoordinator.Result.RetryLater || rec is FirstIdentityCoordinator.Result.Failed) {
                return KpgpPolicy.Expect(FIRST_IDENTITY_RETRY, emptyList(), emptyList(), FIRST_IDENTITY_RETRY, rollback = true)
            }
        }
        return result
    }

    private val SETTLED_ACTIONS = setOf("keep_existing", "upgraded_from_L", "upgraded_from_chain")

    private fun fromDeviceBase(
        app: Context,
        eoa: String,
        userClick: Boolean,
        nowSec: Long,
        nativeConfirm: Boolean,
        storeAccount: StoreAwareAccount.Resolution.Account?,
        store: AccountPgpK,
    ): KpgpPolicy.Expect {
        // An unreadable K is not an absent one: upgrade() answers retry for it.
        val kAbsent = try {
            store.read(eoa, PgpMigrationPolicy.WORKSPACE) == null
        } catch (_: Exception) {
            return upgrade(store, eoa, null, userClick, nowSec, nativeConfirm)
        }
        if (!kAbsent) return upgrade(store, eoa, null, userClick, nowSec, nativeConfirm)
        val pgp = NativeWallet.pgpFor(app, eoa)
        // The state, the identity and the armor from ONE decrypt (it was three, each seconds long on the S25's StrongBox). The same read
        // fills the public identity snapshot, so identityPublic needs no read of its own afterwards.
        val read = pgp.readOnce(wantArmor = true)
        PublicIdentitySnapshot.store(pgp.account, read)
        when (read.state) {
            is NativePgpVault.State.Ready -> {
                val record = try {
                    val identity = read.identity
                    // LRecord still takes a String (its lifetime is a listed pending item); the byte copy is zeroed here.
                    val priv = read.armor?.let { b -> try { String(b, Charsets.UTF_8) } finally { b.fill(0) } }
                    if (identity != null && priv != null) LRecord(priv, identity.subkeyKeyId) else null
                } catch (_: Exception) {
                    null
                }
                // Hardening: the vault key is held to the same challenge before it is mirrored into K_pgp (K_pgp was absent, so this is the
                // one chain read of an account that has none). A refusal mirrors nothing; the vault key itself is not touched.
                if (record == null) return upgrade(store, eoa, null, userClick, nowSec, nativeConfirm)
                val chainRead = readAgreedTimed(eoa)
                val t = DiagTiming.now()
                val outcome = AutoRecovery.mirrorVault(eoa, record, store, chainRead, nowSec, lock = { lockStateOf(app, eoa, storeAccount) })
                DiagTiming.log("autorecovery", t, outcome.logCode)
                return outcome.expect
            }
            is NativePgpVault.State.Locked -> {
                DiagTiming.log("autorecovery", DiagTiming.now(), "vault_locked")
                return upgrade(store, eoa, null, userClick = false, nowSec = nowSec, nativeConfirm = false)
            }
            is NativePgpVault.State.NoKey -> Unit
        }
        // One chain read (both endpoints at one block) gives the registered key and the backup of the same snapshot.
        val chainRead = readAgreedTimed(eoa)
        val vault = NativeWallet.vault(app)
        val forms: () -> List<String>? = {
            val key = if (storeAccount == null) vault.unlock() else StoreAwareAccount.keyOf(app, storeAccount)
            try {
                key?.let { NativePgpBackup.passwordForms(it) }
            } finally {
                key?.fill(0)
            }
        }
        val legacy = try {
            BeamioChatPgpStore.legacyCopy(app)
        } catch (_: Exception) {
            // The shipped store cannot be read: no candidate from it (the chain backup is still tried); nothing is written from an unread store.
            null
        }
        val t0 = DiagTiming.now()
        val outcome = AutoRecovery.recover(eoa, pgp, store, chainRead, legacy, forms, nowSec, lock = { lockStateOf(app, eoa, storeAccount) })
        DiagTiming.log("autorecovery", t0, outcome.logCode)
        if (outcome.expect.action == "pgp_migration_retry" && userClick && nativeConfirm) {
            return upgrade(store, eoa, null, userClick, nowSec, nativeConfirm)
        }
        return outcome.expect
    }
}
