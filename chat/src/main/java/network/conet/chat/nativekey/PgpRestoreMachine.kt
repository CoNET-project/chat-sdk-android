package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The P-IMP-PGP option A state machine (spec §25.30, r3o; P-IMP-REPLACE per r3n). Native only; nothing here returns key
 * material.
 *
 * Read-only evaluation ([restore]); the user-confirmed path ([tapEntry], [keygen], [commit], [cancelOrTimeout]) with a native
 * confirmation, compare-and-set on the chain version the user saw, and an idempotency key; a direct registration
 * ([registerDirect]); and reconciliation after a restart ([resume]). The chain is reached only through [PgpRestoreChain].
 * Each device has its own local vaults.
 *
 * The machine mirrors the reference simulator `gen-pgp-restore-acceptance-vectors.mjs` (the registered r3o copy). The
 * acceptance vectors check every step result and the final state against it.
 */
/**
 * Clears a registering marker by absence (review 2): true when the chain shows no identity at every endpoint the rule uses, at a block
 * later than [markBlock]. The adapter decides the endpoints and the depth; the rule is configured, not hard-coded (the 第 5 版 answer pending).
 */
internal fun interface RegisteringAbsenceRule {
    fun confirmedAbsentAfter(markBlock: Long): Boolean
}

/** The production default until the confirmation rule exists: absence is never confirmed, so a marker is only cleared by its own identity. */
internal val NO_ABSENCE_CONFIRMATION = RegisteringAbsenceRule { false }

/**
 * The registering marker as read (draft 5B, format v2): `v2` is false when the marker is the old format or does not parse; `writeBlock` is the chain
 * block of the write, or null when it was unknown. The identity is the pending key's, not the marker's.
 */
internal data class RegisteringMark(val v2: Boolean, val writeBlock: Long?)

internal data class PgpIdentity(val fingerprint: String, val subkeyKeyId: String) {
    fun sameAs(other: PgpIdentity?): Boolean = other != null && fingerprint == other.fingerprint && subkeyKeyId == other.subkeyKeyId
}

/**
 * G1 (review): the identity read is three-state. A record that exists but whose public key cannot be parsed is Unknown, not Absent; only a
 * readable absence is Absent. Unknown is never taken for "no record" (25.52Y.84, 25.30.2).
 */
internal sealed class IdentityRead {
    class Present(val identity: PgpIdentity) : IdentityRead()
    object Absent : IdentityRead()
    object Unknown : IdentityRead()
}

/** The on-chain record, read through a read-only adapter. A write happens only through [write]. */
internal interface PgpRestoreChain {
    /** `false` when the chain read failed (RPC, timeout, parsing). That is not "no record". */
    fun chainReadable(): Boolean

    /** `false` when the backup read failed. That is not "no backup". */
    fun backupReadable(): Boolean

    /** The record's version. It starts at 0 and rises by one on every successful write. */
    fun version(): Long

    /** The registered identity, or `null` when the chain holds no record. */
    fun identity(): PgpIdentity?

    /**
     * B-B (review): a fresh read of the chain for the pre-write re-read and the post-write read-back. The default returns this adapter, which is
     * right only for a chain that is itself live; an adapter with a snapshot overrides it with a new read.
     */
    fun reread(): PgpRestoreChain = this

    /** The three-state identity read (G1). The default is the two-state answer; an adapter that can tell unreadable from absent overrides it. */
    fun identityRead(): IdentityRead = identity()?.let { IdentityRead.Present(it) } ?: IdentityRead.Absent

    /** The stored backup text. `""` when the record holds no backup. */
    fun backupText(): String

    /** The chain's head block at the read, or `null` when unknown. A registering marker written with an unknown block is never cleared by absence. */
    fun headBlock(): Long? = null

    /** Writes the identity and its backup and advances the version by one. The caller has checked the version (CAS). */
    fun write(identity: PgpIdentity, backupText: String)
}

/** The account's wallet, as the machine needs it. The wallet is never written by this machine. */
internal interface PgpRestoreWallet {
    fun ready(): Boolean

    /** The account's private-key string ("0x" + 64 lower-case hex) for the backup password, or `null` without a key. */
    fun passwordString(): String?
}

/** A new key for one device. Generated natively in production; the acceptance harness supplies the vector keys. */
internal class PgpNewKey(val privateArmor: ByteArray, val identity: PgpIdentity) {
    /** Test and harness seam: a String armor is copied to bytes here. The String is the caller's, and is not kept. */
    constructor(privateArmor: String, identity: PgpIdentity) : this(privateArmor.toByteArray(Charsets.UTF_8), identity)

    /** A text view for the one call that takes a String. Not kept by the caller. */
    fun armorText(): String = String(privateArmor, Charsets.UTF_8)
}

internal interface PgpRestoreKeys {
    fun newKey(deviceId: String): PgpNewKey
}

/**
 * The UI state the PWA shows (§25.30.3, §25.30.7). [code] is the reason, [observedVersion] is the chain version the user saw,
 * and [origin] ("first" or "replace") is set while the confirmation is awaited. [uiKey] is the copy key; the copy is in the PWA.
 */
internal data class PgpRestoreUi(
    val state: String = "not_evaluated",
    val failureClass: String? = null,
    val offerEntry: Boolean = false,
    val observedVersion: Long? = null,
    val code: String? = null,
    val origin: String? = null,
) {
    fun uiKey(): String? = when (state) {
        "failed" -> "chat.restore_failed.body"
        "undetermined" -> "chat.restore_retry.body"
        "awaiting_confirm" -> if (origin == "first") "chat.first_identity.confirm.body" else "chat.new_identity.confirm.body"
        "first_identity" -> "chat.first_identity.body"
        "retry_write" -> "chat.new_identity.retry.body"
        "blocked" -> "wallet.not_ready"
        else -> null
    }
}

/** A failed erase of a pending key: retry_write. The pending key is kept and the discard is not reported. */
internal const val RETRY_WRITE = "retry_write"

/** The pending key's metadata: the idempotency key, the chain version the user saw, and the kind ("first" or "replace"). */
internal data class PendingMeta(val idemKey: String, val observedVersion: Long, val kind: String)

/** One device: its own files and wrapping key, its vaults for the account, and its in-memory UI and crash flag. */
internal class PgpRestoreDevice(val id: String, val account: String, wrap: KeyWrap, val files: VaultFiles) {
    val active = NativePgpVault(wrap, files, account)
    val pending = NativePgpVault(wrap, files, account, NativePgpVault.Slot.PENDING)
    val old = NativePgpVault(wrap, files, account, NativePgpVault.Slot.OLD)
    var ui: PgpRestoreUi = PgpRestoreUi()
    var crashed: Boolean = false

    fun pendingMeta(): PendingMeta? {
        val bytes = files.read(NativePgpVault.pendingMetaName(account)) ?: return null
        return try {
            val o = JSONObject(String(bytes, Charsets.UTF_8))
            PendingMeta(o.getString("idemKey"), o.getLong("observedVersion"), o.getString("kind"))
        } catch (e: Exception) {
            // Present but unreadable is unknown, not "no pending": a new key is never generated on an unknown state (25.52Y.84).
            throw java.io.IOException("pending metadata unreadable", e)
        }
    }

    fun writePendingMeta(meta: PendingMeta) {
        val o = JSONObject()
            .put("idemKey", meta.idemKey)
            .put("observedVersion", meta.observedVersion)
            .put("kind", meta.kind)
        files.write(NativePgpVault.pendingMetaName(account), o.toString().toByteArray(Charsets.UTF_8))
    }

    /**
     * Removes the pending key and its metadata. The active identity, the old wrap and the completed key are not touched.
     * The metadata is erased first: if that fails, the pending key is untouched and kept for a retry. Returns false when either erase fails; the
     * caller answers [RETRY_WRITE] (retry_write) and counts no discard. If the metadata is gone and the key
     * erase fails, the key is kept without its metadata; the commit path treats it as no pending key and erases it on the next attempt.
     */
    fun clearPending(): Boolean {
        val ok = eraseChecked(files, NativePgpVault.pendingMetaName(account)) && pending.forget()
        // A failed erase disables the pending key: it is never used again (no recovery, resume, signing or decryption) until a later erase succeeds.
        // The flag holds no key material.
        if (ok) runCatching { files.delete(disabledName()) } else runCatching { files.write(disabledName(), byteArrayOf(1)) }
        return ok
    }

    /** True when an erase of this device's pending key failed and the key is disabled (a flag only; no key material). */
    fun pendingDisabled(): Boolean = runCatching { files.read(disabledName()) != null }.getOrDefault(true)

    private fun disabledName(): String = "pgp.v1.disabled.${account.lowercase().removePrefix("0x")}.pending"

    /**
     * The registering state (review, adopted): written before the chain write, removed only after the chain write and the local write are both
     * done. A marker that is still present means a write may have reached the chain without the local record: the state is unknown until
     * resolved. The name is the PGP restore's own (not the wallet.discard.intent state machine).
     */
    private fun registeringName(): String = "pgp.restore.registering.${account}"

    /** The v2 marker (draft 5B): `{"format":"v2","writeBlock":<n or null>}`. Written before the chain write; overwritten by each retry. */
    fun markRegistering(writeBlock: Long?) {
        val json = JSONObject().put("format", "v2").put("writeBlock", writeBlock ?: JSONObject.NULL)
        files.write(registeringName(), json.toString().toByteArray(Charsets.UTF_8))
    }

    fun registeringMarked(): Boolean = files.read(registeringName()) != null

    /** The marker, or `null` when there is none. Anything that is not a v2 JSON marker is `v2 = false` (unknown format). */
    fun registeringMark(): RegisteringMark? {
        val raw = files.read(registeringName()) ?: return null
        return try {
            val o = JSONObject(String(raw, Charsets.UTF_8))
            if (o.optString("format") != "v2") {
                RegisteringMark(v2 = false, writeBlock = null)
            } else {
                RegisteringMark(v2 = true, writeBlock = if (o.isNull("writeBlock")) null else o.optLong("writeBlock", -1L).takeIf { it >= 0L })
            }
        } catch (_: Exception) {
            RegisteringMark(v2 = false, writeBlock = null)
        }
    }

    /** Audit (draft 5B, registering_superseded): the local active fingerprint ("none" when empty) and the chain's identity (the supersedor). */
    fun recordSuperseded(activeFingerprint: String, by: PgpIdentity): Boolean =
        appendAudit("pgp.restore.superseded.$account", "active=$activeFingerprint|chain=${by.fingerprint}|${by.subkeyKeyId}")

    /** Appends one line to an audit name (draft 5B: every clearing of a marker writes its audit). False when the write fails. */
    fun appendAudit(name: String, line: String): Boolean = runCatching {
        val prev = files.read(name)?.let { String(it, Charsets.UTF_8) } ?: ""
        files.write(name, (prev + line + "\n").toByteArray(Charsets.UTF_8))
    }.isSuccess

    fun clearRegistering() {
        runCatching { files.delete(registeringName()) }
    }

    /** The idempotency key of the last completed replacement or first identity, or `null`. */
    fun completedIdem(): String? = files.read(NativePgpVault.completedName(account))?.let { String(it, Charsets.UTF_8) }

    fun setCompletedIdem(idemKey: String) {
        files.write(NativePgpVault.completedName(account), idemKey.toByteArray(Charsets.UTF_8))
    }
}

internal class PgpRestoreMachine(
    private val chain: PgpRestoreChain,
    private val wallet: PgpRestoreWallet,
    private val keys: PgpRestoreKeys,
    /** The IV of a new backup. Random in production; the acceptance harness supplies a fixed one per identity. */
    private val ivFor: (PgpIdentity) -> ByteArray,
    val devices: Map<String, PgpRestoreDevice>,
    /** Clears a registering marker by absence (review 2). The default never confirms absence. */
    private val absence: RegisteringAbsenceRule = NO_ABSENCE_CONFIRMATION,
) {
    /**
     * G3 (review): one in-flight operation for the whole machine. Every entry point holds this monitor, so two calls (a double tap, two threads, a
     * bridge retry) run one after the other: the second sees the first's result, never a half-done state. The PGP restore keeps its own files
     * (pgp.v1 names, the pending metadata, the completed marker); it does not share the wallet.discard.intent state machine.
     */
    /**
     * The one in-flight domain of the restore, for the whole process (review of fix/pgp-g123, G3): every PgpRestoreMachine instance, including the
     * production machine built for each call, takes this same monitor, so instances do not run side by side.
     */
    private companion object {
        private val IN_FLIGHT = Any()
    }

    class Counters {
        var keygen = 0
        var onchainWrites = 0
        var backupWrites = 0
        var registrations = 0
        var replacements = 0
        var localWrites = 0
        var pendingDiscarded = 0
        var externalWrites = 0
        var walletWrites = 0
    }

    /**
     * One step's answer: [result], and optionally a [code], the state after a re-evaluation ([reevaluated]), or the
     * idempotency key of a discarded pending key ([idemKey]).
     */
    class Step(
        val result: String,
        val code: String? = null,
        val reevaluated: String? = null,
        val idemKey: String? = null,
    )

    val counters = Counters()

    private fun rejected(code: String) = Step("rejected", code = code)

    private fun crash(dev: PgpRestoreDevice) {
        dev.crashed = true
        dev.ui = PgpRestoreUi()
    }

    private fun identityOf(dev: PgpRestoreDevice): PgpIdentity? = dev.active.identity()

    /** The pending key of [dev] as a new key. Null when there is none. */
    private fun pendingKey(dev: PgpRestoreDevice): PgpNewKey? {
        val armor = dev.pending.armorForMove() ?: return null
        val secret = NativePgp.parseSecret(String(armor, Charsets.UTF_8))
        val sub = secret?.let { NativePgpBackup.subkeyKeyId(it) }
        if (secret == null || sub == null) {
            armor.fill(0)
            return null
        }
        // The new key takes over the copy; it is zeroed when the flow no longer needs it.
        return PgpNewKey(armor, PgpIdentity(secret.fingerprint.uppercase(), sub))
    }

    /** Before a replacement, wraps the old backup when it decrypts (R3). Counted once per device. */
    private fun wrapOldBackupIfReadable(dev: PgpRestoreDevice) {
        val password = wallet.passwordString() ?: return
        val armorBytes = NativePgpBackup.decryptArmor(password, chain.backupText()) ?: return
        val armor = String(armorBytes, Charsets.UTF_8)
        armorBytes.fill(0)
        if (NativePgp.parseSecret(armor) == null) return
        if (dev.old.state() !is NativePgpVault.State.Ready) {
            if (dev.old.put(dev.account, armor, "") == NativePgpVault.Put.OK) counters.localWrites++
        }
    }

    /** True when the chain holds a record: an identity, or a backup text (a write then counts as a replacement). */
    private fun chainHoldsRecord(): Boolean = chain.identity() != null || chain.backupText().isNotEmpty()

    /** Writes [key] to the chain (CAS checked by the caller), then to the device's active slot. */
    private fun writeIdentity(dev: PgpRestoreDevice, key: PgpNewKey, crashAfterWrite: Boolean, idemKey: String) {
        // G2 (review): the active slot must be confirmed empty before anything is registered. Otherwise nothing is written to the chain.
        if (dev.active.state() !is NativePgpVault.State.NoKey) {
            dev.ui = PgpRestoreUi("undetermined", code = "pgp_locked")
            return
        }
        wrapOldBackupIfReadable(dev)
        val password = wallet.passwordString() ?: return
        val backup = NativePgpBackup.encryptArmor(password, key.privateArmor, ivFor(key.identity))
        if (chainHoldsRecord()) counters.replacements++
        // review r10: a marker that cannot be written is a controlled failure. Nothing reaches the chain; the pending key stays.
        try {
            dev.markRegistering(chain.headBlock())
        } catch (e: Exception) {
            dev.ui = PgpRestoreUi("undetermined", code = "write_failed")
            return
        }
        try {
            chain.write(key.identity, backup)
        } catch (e: Exception) {
            // The write threw (review): read the chain again. Landed: carry on. Not landed: a retryable failure, the marker goes, and the pending key
            // stays so the retry uses the same key. Unknown (the read fails too): the marker stays.
            val landed = runCatching { chain.reread().identityRead() }.getOrNull()
            when {
                landed is IdentityRead.Present && landed.identity.sameAs(key.identity) -> Unit
                landed == null || landed is IdentityRead.Unknown -> {
                    dev.ui = PgpRestoreUi("undetermined", code = "pgp_write_in_progress")
                    return
                }
                else -> {
                    dev.clearRegistering()
                    dev.ui = PgpRestoreUi("failed", "write_failed", offerEntry = true, observedVersion = chain.version(), code = "write_failed")
                    return
                }
            }
        }
        counters.onchainWrites++
        counters.backupWrites++
        counters.registrations++
        // B-B (review), order and limits: the read-back happens BEFORE the local overwrite and before the registering marker is cleared. A later
        // overwrite of the chain by another client is found only at the next evaluation (undetermined, pgp_locked), not here. The contract
        // _setPGPOnly has no create-only check, so a deployed version must be verified over RPC before this path is relied on.
        val back = chain.reread().identityRead()
        if (back !is IdentityRead.Present || !back.identity.sameAs(key.identity)) {
            // P2 (review 3): the write returned but the read-back does not show it. Absent (a lagging endpoint, or a write that did not land) keeps
            // the marker and the pending key, is reported as its own code, and is never cleared by absence here.
            // Interface (2026-11-20): the code is readback_failed; the Absent/Present split goes in failureClass only.
            dev.ui = PgpRestoreUi("undetermined", failureClass = if (back is IdentityRead.Absent) "readback_absent" else "readback_present", code = "readback_failed")
            return
        }
        if (crashAfterWrite) {
            crash(dev)
            return
        }
        // 5B 2(a): the local active write comes first. A failed write keeps the pending key and the marker, and no completed key is recorded.
        if (!activeHoldsKey(dev, key)) {
            dev.ui = PgpRestoreUi("undetermined", code = "write_failed")
            return
        }
        counters.localWrites++
        if (!resolveMarker(dev)) {
            dev.ui = PgpRestoreUi("undetermined", code = "pgp_write_in_progress")
            return
        }
        dev.setCompletedIdem(idemKey)
        dev.ui = PgpRestoreUi("ok")
    }

    /**
     * The local active slot holds [privateArmor] after the write: the put succeeded, or the slot already holds this identity. A failed put with an
     * empty or different slot is false (review r9): the caller keeps the pending key and the marker.
     */
    private fun activeHoldsKey(dev: PgpRestoreDevice, key: PgpNewKey): Boolean {
        if (dev.active.put(dev.account, key.armorText(), "") == NativePgpVault.Put.OK) return true
        return dev.active.state() is NativePgpVault.State.Ready && dev.active.identity()?.sameAs(key.identity) == true
    }

    /** The state of the registering marker (draft 5B). RESOLVED: no marker (or cleared). RETRY_READY: retry with the same key. */
    internal enum class Registering {
        RESOLVED, UNRESOLVED, RETRY_READY, FAILED,
        /** The chain holds the pending key's identity and the active slot is not yet written: the marker stays until the active write (5B 2(a)). */
        MATCH,
    }

    /**
     * Clears the marker after a completed registration (draft 5B 2(a)): the audit `pgp.restore.registering.resolved.<account>` is written first.
     * If the audit cannot be written the marker stays, so the next evaluation completes it again.
     */
    private fun resolveMarker(dev: PgpRestoreDevice): Boolean {
        val mark = dev.registeringMark()
        if (mark != null && !dev.appendAudit("pgp.restore.registering.resolved.${dev.account}", "writeBlock=${mark.writeBlock ?: "?"}")) return false
        // The audit is written first. Only then the pending key and the marker go, so a failed audit leaves both in place: the next evaluation
        // completes the registration again and never reads it as "no pending key" (which would write a superseded audit).
        if (!dev.clearPending()) return false
        dev.clearRegistering()
        return true
    }

    private fun unresolved(dev: PgpRestoreDevice, code: String): Registering {
        dev.ui = PgpRestoreUi("undetermined", code = code)
        return Registering.UNRESOLVED
    }

    /**
     * Resolves the registering marker (draft 5B). A pending key exists when its state is not NoKey (Locked included); a pending key is
     * "Ready" when it can be read.
     *  - The chain cannot answer: unresolved, pgp_write_in_progress.
     *  - A marker that is not v2 (the old "1"): cleared only when the chain holds the pending key and the active slot already holds that key;
     *    otherwise unresolved, pgp_registering_unknown_format.
     *  - The chain holds the pending key's identity: cleared (the write is done on the chain).
     *  - The chain holds another identity and a Ready pending key exists: FAILED (restore_failed), the marker stays, nothing is cleared (P-IMP-REPLACE).
     *  - The chain holds another identity and a pending key is Locked: unresolved (its identity is unknown).
     *  - The chain holds another identity and no pending key: superseded (audited), the marker goes; an active key that differs is pgp_locked.
     *  - The chain shows no identity and a Ready pending key exists: if the absence rule confirms absence after the marker's writeBlock, RETRY_READY
     *    (the marker stays, the same key retries); otherwise unresolved, pgp_write_in_progress.
     *  - Otherwise (no identity, no Ready pending key): unresolved, pgp_write_in_progress. Nothing clears the marker by absence alone.
     */
    private fun registeringState(dev: PgpRestoreDevice): Registering {
        if (!dev.registeringMarked()) return Registering.RESOLVED
        val mark = dev.registeringMark() ?: RegisteringMark(v2 = false, writeBlock = null)
        val read = runCatching { chain.reread().identityRead() }.getOrNull()
        if (read == null || read is IdentityRead.Unknown) return unresolved(dev, "pgp_write_in_progress")
        val onChain = (read as? IdentityRead.Present)?.identity
        val pendingState = dev.pending.state()
        // An orphan (Ready, no metadata) counts as no pending key here; an unknown state still counts as present.
        val pendingExists = pendingState !is NativePgpVault.State.NoKey && !(pendingState is NativePgpVault.State.Ready && dev.pendingMeta() == null)
        val pendingReady = pendingState is NativePgpVault.State.Ready
        val pendingId = if (pendingReady) dev.pending.identity() else null
        if (!mark.v2) {
            val activeHoldsPending = pendingId != null && dev.active.state() is NativePgpVault.State.Ready &&
                dev.active.identity()?.sameAs(pendingId) == true
            if (onChain != null && pendingId != null && onChain.sameAs(pendingId) && activeHoldsPending) {
                if (!resolveMarker(dev)) return unresolved(dev, "pgp_write_in_progress")
                return Registering.RESOLVED
            }
            return unresolved(dev, "pgp_registering_unknown_format")
        }
        if (onChain != null) {
            if (pendingId != null && onChain.sameAs(pendingId)) {
                // 5B 2(a): resolved only when the active slot holds the same key; otherwise the write of the active slot completes it.
                if (dev.active.state() is NativePgpVault.State.Ready && dev.active.identity()?.sameAs(onChain) == true) {
                    if (!resolveMarker(dev)) return unresolved(dev, "pgp_write_in_progress")
                    return Registering.RESOLVED
                }
                return Registering.MATCH
            }
            if (pendingReady) {
                dev.ui = PgpRestoreUi("failed", "pending_differs", offerEntry = true, observedVersion = chain.version(), code = "pgp_pending_differs")
                return Registering.FAILED
            }
            if (pendingExists) return unresolved(dev, "pgp_write_in_progress")
            return supersede(dev, onChain)
        }
        val block = mark.writeBlock
        // A Locked pending key is unreadable: it is never retried and never cleared by absence (draft 5B 3, 5): the rule is not asked.
        if (block != null && pendingReady && absence.confirmedAbsentAfter(block)) {
            dev.ui = PgpRestoreUi("retry_ready", observedVersion = chain.version())
            return Registering.RETRY_READY
        }
        // Draft 5B 2(c): no pending key, the chain absent on both endpoints after the write block: the write never landed. The marker goes,
        // with its audit, and the normal evaluation goes on (an empty slot then starts a first identity).
        if (block != null && !pendingExists && absence.confirmedAbsentAfter(block)) {
            if (!dev.appendAudit("pgp.restore.registering.cleared.${dev.account}", "writeBlock=$block")) {
                return unresolved(dev, "pgp_write_in_progress")
            }
            dev.clearRegistering()
            return Registering.RESOLVED
        }
        return unresolved(dev, "pgp_write_in_progress")
    }

    /** Another identity holds the record and no pending key exists: audit first; the marker goes only after the audit is written. */
    private fun supersede(dev: PgpRestoreDevice, onChain: PgpIdentity): Registering {
        val activeFp = if (dev.active.state() is NativePgpVault.State.Ready) dev.active.identity()?.fingerprint ?: "none" else "none"
        if (!dev.recordSuperseded(activeFp, onChain)) return unresolved(dev, "pgp_write_in_progress")
        dev.clearRegistering()
        val activeReady = dev.active.state() is NativePgpVault.State.Ready
        if (activeReady && dev.active.identity()?.sameAs(onChain) != true) {
            dev.ui = PgpRestoreUi("undetermined", code = "pgp_locked")
            return Registering.UNRESOLVED
        }
        return Registering.RESOLVED
    }

    /** Read-only evaluation of the chain against the device's wallet (§25.30.2). Returns the result code. */
    /** [write] false is the read-only evaluation (§25.35.2 `pgpRestoreEvaluate`): nothing is written locally. */
    /**
     * Any failure to read the vault or the chain during the evaluation is unknown (draft 第 3 节, LK-04): undetermined, nothing is written, and a
     * failed read is never taken as an empty slot.
     */
    private fun evalRestore(dev: PgpRestoreDevice, write: Boolean = true): String = try {
        // A disabled pending key (a failed erase) is a storage fault, not an absent account: retry_write, never first_identity or no_record.
        if (!disabledPendingCleared(dev)) {
            unresolved(dev, RETRY_WRITE)
            "undetermined"
        } else {
            evalRestoreUnchecked(dev, write)
        }
    } catch (e: Exception) {
        dev.ui = PgpRestoreUi("undetermined", code = "pgp_source_unavailable")
        "undetermined"
    }

    private fun evalRestoreUnchecked(dev: PgpRestoreDevice, write: Boolean): String {
        if (!wallet.ready()) {
            dev.ui = PgpRestoreUi("blocked", code = "wallet_not_ready")
            return "blocked"
        }
        // Registering state (draft 5B): resolved first. Nothing is written while it is unresolved.
        when (registeringState(dev)) {
            Registering.RESOLVED, Registering.MATCH -> Unit
            Registering.RETRY_READY -> return "retry_ready"
            Registering.FAILED -> return "failed:pending_differs"
            Registering.UNRESOLVED -> return "undetermined"
        }
        if (!chain.chainReadable() || !chain.backupReadable()) {
            dev.ui = PgpRestoreUi("undetermined", code = "pgp_source_unavailable")
            return "undetermined"
        }
        val v = chain.version()
        // G1: an unreadable identity is unknown: undetermined, nothing generated, nothing overwritten.
        val onChain = when (val read = chain.identityRead()) {
            is IdentityRead.Present -> read.identity
            IdentityRead.Absent -> null
            IdentityRead.Unknown -> {
                dev.ui = PgpRestoreUi("undetermined", code = "pgp_source_unavailable")
                return "undetermined"
            }
        }
        val text = chain.backupText()
        if (onChain == null) {
            if (text.isNotEmpty()) {
                // A backup with no registered identity is a state mismatch: the failure class, on the replacement path (r3o).
                dev.ui = PgpRestoreUi("failed", "registration_missing", offerEntry = true, observedVersion = v, code = "pgp_registration_missing")
                return "failed:registration_missing"
            }
            // G2 (review): a first identity is offered only into an empty active slot. An active key that is present, or not confirmed empty,
            // is never overwritten: undetermined, nothing generated.
            if (dev.active.state() !is NativePgpVault.State.NoKey) {
                dev.ui = PgpRestoreUi("undetermined", code = "pgp_locked")
                return "undetermined"
            }
            // No identity and no backup: a first identity. Generation needs the user's confirmation and a CAS check (r3o).
            dev.ui = PgpRestoreUi("first_identity", offerEntry = true, observedVersion = v)
            return "first_identity"
        }
        if (text.isEmpty()) {
            dev.ui = PgpRestoreUi("failed", "backup_missing", offerEntry = true, observedVersion = v, code = "pgp_backup_missing")
            return "failed:backup_missing"
        }
        val password = wallet.passwordString() ?: run {
            dev.ui = PgpRestoreUi("blocked", code = "wallet_not_ready")
            return "blocked"
        }
        val armorBytes = NativePgpBackup.decryptArmor(password, text)
        if (armorBytes == null) {
            dev.ui = PgpRestoreUi("failed", "decrypt_failed", offerEntry = true, observedVersion = v, code = "pgp_backup_undecryptable")
            return "failed:decrypt_failed"
        }
        val armor = String(armorBytes, Charsets.UTF_8)
        armorBytes.fill(0)
        val secret = NativePgp.parseSecret(armor)
        if (secret == null) {
            dev.ui = PgpRestoreUi("failed", "decrypt_failed", offerEntry = true, observedVersion = v, code = "pgp_backup_invalid")
            return "failed:decrypt_failed"
        }
        val restored = PgpIdentity(secret.fingerprint.uppercase(), NativePgpBackup.subkeyKeyId(secret) ?: "")
        if (restored != onChain) {
            dev.ui = PgpRestoreUi("failed", "fingerprint_mismatch", offerEntry = true, observedVersion = v, code = "pgp_fingerprint_mismatch")
            return "failed:fingerprint_mismatch"
        }
        if (write && !onChain.sameAs(identityOf(dev))) {
            // 2026-11-16 (keep the user's data): the automatic restore writes only into an empty slot. A locked record (marker or
            // record missing) is an unknown state, not an empty one, and a different readable key needs the user's replacement (P-IMP-REPLACE).
            if (dev.active.state() !is NativePgpVault.State.NoKey) {
                dev.ui = PgpRestoreUi("undetermined", code = "pgp_locked")
                return "undetermined"
            }
            if (dev.active.put(dev.account, armor, "") != NativePgpVault.Put.OK) {
                dev.ui = PgpRestoreUi("undetermined", code = "write_failed")
                return "undetermined"
            }
            counters.localWrites++
            // 5B 2(a): the active write completes a registration that is on the chain: the pending key goes and the marker is resolved.
            if (dev.registeringMarked() && usablePending(dev) && dev.pending.identity()?.sameAs(onChain) == true) {
                if (!resolveMarker(dev)) {
                    dev.ui = PgpRestoreUi("undetermined", code = "pgp_write_in_progress")
                    return "undetermined"
                }
            }
        }
        dev.ui = PgpRestoreUi("ok")
        return "ok"
    }

    /** `pgpRestoreEvaluate` (§25.35.2): the evaluation only. Writes nothing, generates nothing, registers nothing. */
    fun evaluate(devId: String): Step = synchronized(IN_FLIGHT) {
        val dev = devices.getValue(devId)
        retryPendingCleanup(dev)
        runCatching { orphanErased(dev) }
        return Step(evalRestore(dev, write = false))
    }

    fun restore(devId: String, crashAt: String? = null): Step = synchronized(IN_FLIGHT) {
        val dev = devices.getValue(devId)
        retryPendingCleanup(dev)
        runCatching { orphanErased(dev) }
        val r = evalRestore(dev)
        if (crashAt == "after_store" && identityOf(dev) != null && r == "ok") {
            crash(dev)
            return Step("crashed")
        }
        return Step(r)
    }

    /** The user taps the entry (a failure or a first identity). Only the confirmation screen opens; nothing is written. */
    fun tapEntry(devId: String): Step = synchronized(IN_FLIGHT) {
        val dev = devices.getValue(devId)
        val st = dev.ui.state
        if (st != "failed" && st != "first_identity") return rejected("not_available")
        dev.ui = dev.ui.copy(state = "awaiting_confirm", origin = if (st == "first_identity") "first" else "replace")
        return Step("ok")
    }

    /** The user cancels, or the confirmation times out (120 s). The state is evaluated again. */
    fun cancelOrTimeout(devId: String, timeout: Boolean): Step = synchronized(IN_FLIGHT) {
        val dev = devices.getValue(devId)
        if (dev.ui.state != "awaiting_confirm") return rejected("not_awaiting_confirm")
        val r = evalRestore(dev)
        return Step(if (timeout) "confirm_timeout" else "cancelled", reevaluated = r)
    }

    /** The user confirms on the native screen. Generates a pending key once per idempotency key, after a CAS check. */
    fun keygen(devId: String, idemKey: String, nativeConfirmed: Boolean, confirmSource: String = "native", crashAt: String? = null): Step = synchronized(IN_FLIGHT) {
        val dev = devices.getValue(devId)
        // Spec order (2026-11-20, step 1 before step 2): the native confirmation is checked before any idempotent short-circuit.
        if (confirmSource != "native") return rejected("confirmation_not_native")
        if (!nativeConfirmed) return rejected("native_confirmation_missing")
        if (dev.completedIdem() == idemKey) return Step("noop", code = "idempotent")
        if (dev.ui.state != "awaiting_confirm") return rejected("not_awaiting_confirm")
        // Spec order (2026-11-20): a repeat of the same idempotency key is idempotent before any CAS read; a pending key under another key is refused.
        // An orphan pending key is erased first; while it cannot be erased, nothing is generated and the answer is retry_write.
        if (!orphanErased(dev)) return eraseFailed()
        if (!disabledPendingCleared(dev)) return eraseFailed()
        if (dev.pending.state() is NativePgpVault.State.Ready) {
            return if (dev.pendingMeta()?.idemKey == idemKey) Step("noop", code = "idempotent") else rejected("pending_exists")
        }
        // Step 4 (spec 2026-11-20, pgpIdentityCreate): the identity is already restored on this device (its active slot holds a key).
        if (dev.active.state() !is NativePgpVault.State.NoKey) return rejected("already_exists")
        val observed = dev.ui.observedVersion ?: return rejected("cas_conflict")
        if (chain.version() != observed) {
            val r = evalRestore(dev)
            return Step("rejected", code = "cas_conflict", reevaluated = r)
        }
        // Confirmation-stage re-read (single RPC): before any key is generated, an unreadable chain is refused, and a first
        // identity needs a still-empty chain (no second identity over a registration made after the offer). A replacement keeps the version
        // check above: a backup with no registration (registration_missing, Q-03) is a valid replacement case, so it is not refused here.
        val nowRead = chain.reread().identityRead()
        val changed = when {
            nowRead == IdentityRead.Unknown -> true
            dev.ui.origin == "first" -> nowRead != IdentityRead.Absent
            else -> false
        }
        if (changed) {
            val r = evalRestore(dev)
            return Step("rejected", code = "cas_conflict", reevaluated = r)
        }
        counters.keygen++
        val key = keys.newKey(dev.id)
        if (dev.pending.put(dev.account, key.armorText(), "") != NativePgpVault.Put.OK) {
            //  (2026-11-20): a rolled-back chain write is write_reverted, retryable without a second chain write (spec 3938). Internal only.
            dev.ui = dev.ui.copy(code = "write_reverted")
            return rejected("write_reverted")
        }
        dev.writePendingMeta(PendingMeta(idemKey, observed, dev.ui.origin ?: "replace"))
        counters.localWrites++
        if (crashAt == "after_keygen") {
            crash(dev)
            return Step("crashed")
        }
        return Step("ok")
    }

    /**
     * A pending-key erase that fails inside a flow: the state and page code of a failed chain write (r2v): state
     * retry_write, code write_failed. The pending key is kept and nothing is reported as discarded.
     */
    private fun eraseFailed(): Step = rejected(RETRY_WRITE)

    /**
     * An orphan pending key: a pending key whose metadata is gone (a failed erase left it behind). : it is never used by
     * any operation. It is erased first; returns false while it cannot be erased, and the caller answers retry_write.
     */
    private fun orphanErased(dev: PgpRestoreDevice): Boolean = try {
        if (dev.pendingMeta() != null || !dev.pending.hasRecord()) true else dev.clearPending()
    } catch (_: Exception) {
        false
    }

    /** A disabled pending key is retried for erase; true when it is gone (or was never disabled). A failed retry keeps it disabled. */
    private fun disabledPendingCleared(dev: PgpRestoreDevice): Boolean = !dev.pendingDisabled() || dev.clearPending()

    /** A usable pending key: a Ready key WITH its metadata. An orphan (Ready, no metadata) is not a pending key for any operation. */
    private fun usablePending(dev: PgpRestoreDevice): Boolean =
        dev.pending.state() is NativePgpVault.State.Ready && dev.pendingMeta() != null && !dev.pendingDisabled()

    /** Name of the cleanup marker: a flag (no key material) that a completed pending key is still to be erased. */
    private fun cleanupName(dev: PgpRestoreDevice): String = "pgp.v1.cleanup.${dev.account.lowercase().removePrefix("0x")}.pending"

    /** Records the completed idempotency key (an idempotency key is not key material) for the erase retry. */
    private fun markPendingCleanup(dev: PgpRestoreDevice, idemKey: String) {
        runCatching { dev.files.write(cleanupName(dev), idemKey.toByteArray(Charsets.UTF_8)) }
    }

    /**
     * Retries an erase that failed after its idempotent completion. Only the pending key of the completed idempotency key is erased; a pending
     * key of another request is never touched. The marker goes once nothing is left to erase.
     */
    private fun retryPendingCleanup(dev: PgpRestoreDevice) {
        // Best effort: a read or erase problem here never changes the answer of the flow that called it (the marker stays for the next attempt).
        runCatching { retryPendingCleanupOrThrow(dev) }
    }

    private fun retryPendingCleanupOrThrow(dev: PgpRestoreDevice) {
        val marked = dev.files.read(cleanupName(dev))?.let { String(it, Charsets.UTF_8) } ?: return
        val meta = dev.pendingMeta()
        // Erase only the pending key of the marked idempotency key: its metadata must name that key; with no metadata, the marked key must be
        // the completed one. A pending key of a newer request is never erased here.
        val owned = if (meta != null) meta.idemKey == marked else dev.completedIdem() == marked
        if (!owned) return
        if (dev.clearPending()) runCatching { dev.files.delete(cleanupName(dev)) }
    }

    /** Writes the pending key to the chain, if the chain still matches what the user saw (CAS). */
    fun commit(devId: String, crashAt: String? = null, writeRevert: Boolean = false): Step = synchronized(IN_FLIGHT) {
        val dev = devices.getValue(devId)
        retryPendingCleanup(dev)
        if (!orphanErased(dev)) return eraseFailed()
        if (!disabledPendingCleared(dev)) return eraseFailed()
        if (dev.pending.state() !is NativePgpVault.State.Ready) return rejected("no_pending")
        val meta = dev.pendingMeta()
        if (meta == null) {
            if (!dev.clearPending()) return eraseFailed()
            counters.pendingDiscarded++
            return rejected("no_pending")
        }
        // B-B (review): the pre-write check reads the chain again (not the snapshot taken earlier); a commit already done under this key is not repeated.
        if (dev.completedIdem() == meta.idemKey) {
            // the chain write is already complete under this key. A failed erase of its pending key is still idempotent
            // (no rewrite of the chain); the erase is marked for retry on the next start or operation. Only codes are logged, never key material.
            if (!dev.clearPending()) markPendingCleanup(dev, meta.idemKey)
            return Step("noop", code = "idempotent", idemKey = meta.idemKey)
        }
        val now = chain.reread()
        val emptyNow = now.identity() == null && now.backupText().isEmpty()
        if (now.version() != meta.observedVersion || (meta.kind == "first" && !emptyNow)) {
            // Discard only the key this request generated (meta read above); an erase failure is not reported as a discard.
            if (!dev.clearPending()) return eraseFailed()
            counters.pendingDiscarded++
            val r = evalRestore(dev)
            return Step("rejected", code = "cas_conflict", reevaluated = r, idemKey = meta.idemKey)
        }
        if (writeRevert) {
            //  (2026-11-20): a rolled-back chain write is write_reverted, retryable without a second chain write (spec 3938). Internal only.
            dev.ui = dev.ui.copy(code = "write_reverted")
            return rejected("write_reverted")
        }
        val key = pendingKey(dev) ?: return rejected("no_pending")
        val crashAfter = crashAt == "after_write"
        writeIdentity(dev, key, crashAfter, meta.idemKey)
        // (b) review 4: the write's own result decides the answer; an undetermined state is never reported as ok.
        if (crashAfter) return Step("crashed")
        if (dev.ui.state != "ok") return Step("undetermined", code = dev.ui.code)
        return Step("ok")
    }

    /**
     * The entry after a failed write (review 2, item 4): the same pending key and the same idempotency key as the commit that failed. Refused
     * without a pending key. An unresolved registering marker refuses it (nothing is written). Otherwise it is the commit of the pending key.
     */
    fun retryWrite(devId: String): Step = synchronized(IN_FLIGHT) {
        val dev = devices.getValue(devId)
        if (dev.pending.state() is NativePgpVault.State.NoKey) return rejected("no_pending")
        if (dev.pending.state() !is NativePgpVault.State.Ready) return rejected("pending_locked")
        return when (registeringState(dev)) {
            Registering.RESOLVED, Registering.RETRY_READY -> commit(devId)
            Registering.MATCH -> Step(evalRestore(dev), code = dev.ui.code)
            Registering.FAILED -> Step("failed", code = dev.ui.code)
            Registering.UNRESOLVED -> Step("undetermined", code = dev.ui.code)
        }
    }

    /** The chain's identity now, for the chatInit status (draft 第 3 节): Unknown when the chain cannot answer. Read-only; nothing is written. */
    fun chainIdentityRead(): IdentityRead = synchronized(IN_FLIGHT) {
        runCatching { chain.reread().identityRead() }.getOrDefault(IdentityRead.Unknown)
    }

    /**
     * Registration through the native channel only (§25.30.5 第 4 条). The blob is the new identity's backup text.
     *
     * NON-PRODUCTION PATH: registerDirect is not in the v1 scope and has no production caller. The three codes
     * (native_confirmation_missing, already_registered_same_key, cas_conflict) stay valid for a future caller. The expected version is not
     * read from AddressPGP here: the read method is pending the owner's , so the version comes from the caller.
     */
    fun registerDirect(identity: PgpIdentity, backupText: String, expectedVersion: Long, nativeConfirmed: Boolean): Step = synchronized(IN_FLIGHT) {
        // Spec (2026-11-20, registerDirect path): 1 native confirmation, 2 same identity on the chain (noop, any key), 3 version. No pending_exists here.
        if (!nativeConfirmed) return rejected("native_confirmation_missing")
        if (identity.sameAs(chain.identity())) return Step("noop", code = "already_registered_same_key")
        if (expectedVersion != chain.version()) return rejected("cas_conflict")
        // G2 (2026-11-20): cas_conflict at the CAS step: a direct registration never overwrites an active key. Nothing is
        // written. Discard rule: a cas_conflict discards only a pending key this request generated; registerDirect
        // generates none, so no pending key is touched here.
        if (devices.values.any { it.active.state() !is NativePgpVault.State.NoKey }) return rejected("cas_conflict")
        if (chainHoldsRecord()) counters.replacements++
        chain.write(identity, backupText)
        counters.onchainWrites++
        counters.backupWrites++
        counters.registrations++
        return Step("ok")
    }

    /** A write by another device or another client. It is not a step of this device. */
    fun externalWrite(identity: PgpIdentity, backupText: String): Step = synchronized(IN_FLIGHT) {
        chain.write(identity, backupText)
        counters.externalWrites++
        return Step("external")
    }

    /** Reconciles after a restart (§25.30.6). A pending key is kept only while the chain still matches; the device never generates here. */
    fun resume(devId: String): Step = synchronized(IN_FLIGHT) {
        val dev = devices.getValue(devId)
        retryPendingCleanup(dev)
        runCatching { orphanErased(dev) }
        dev.crashed = false
        // A disabled pending key (a failed erase) is never continued: retry_write, and no account answer.
        if (!disabledPendingCleared(dev)) return Step("undetermined", code = RETRY_WRITE)
        if (usablePending(dev)) {
            val key = pendingKey(dev)
            val meta = dev.pendingMeta()
            if (key != null && meta != null) {
                if (chain.identity() == key.identity) {
                    if (!activeHoldsKey(dev, key)) {
                        dev.ui = PgpRestoreUi("undetermined", code = "write_failed")
                        return Step("undetermined", code = "write_failed")
                    }
                    counters.localWrites++
                    if (!resolveMarker(dev)) {
                        dev.ui = PgpRestoreUi("undetermined", code = "pgp_write_in_progress")
                        return Step("undetermined", code = "pgp_write_in_progress")
                    }
                    dev.setCompletedIdem(meta.idemKey)
                    dev.ui = PgpRestoreUi("ok")
                    return Step("reconciled_complete")
                }
                val emptyNow = chain.identity() == null && chain.backupText().isEmpty()
                if (meta.observedVersion == chain.version() && (meta.kind != "first" || emptyNow)) {
                    writeIdentity(dev, key, crashAfterWrite = false, idemKey = meta.idemKey)
                    return Step("reconciled_write")
                }
            }
            if (!dev.clearPending()) return eraseFailed()
            counters.pendingDiscarded++
            evalRestore(dev)
            return Step("reconciled_discarded")
        }
        return Step(evalRestore(dev))
    }
}
