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
internal data class PgpIdentity(val fingerprint: String, val subkeyKeyId: String) {
    fun sameAs(other: PgpIdentity?): Boolean = other != null && fingerprint == other.fingerprint && subkeyKeyId == other.subkeyKeyId
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

    /** The stored backup text. `""` when the record holds no backup. */
    fun backupText(): String

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
internal class PgpNewKey(val privateArmor: String, val identity: PgpIdentity)

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
        } catch (_: Exception) {
            null
        }
    }

    fun writePendingMeta(meta: PendingMeta) {
        val o = JSONObject()
            .put("idemKey", meta.idemKey)
            .put("observedVersion", meta.observedVersion)
            .put("kind", meta.kind)
        files.write(NativePgpVault.pendingMetaName(account), o.toString().toByteArray(Charsets.UTF_8))
    }

    /** Removes the pending key and its metadata. The active identity, the old wrap and the completed key are not touched. */
    fun clearPending() {
        pending.forget()
        runCatching { files.delete(NativePgpVault.pendingMetaName(account)) }
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
) {
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
        val secret = NativePgp.parseSecret(armor) ?: return null
        val sub = NativePgpBackup.subkeyKeyId(secret) ?: return null
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
        wrapOldBackupIfReadable(dev)
        val password = wallet.passwordString() ?: return
        val backup = NativePgpBackup.encryptArmor(password, key.privateArmor.toByteArray(Charsets.UTF_8), ivFor(key.identity))
        if (chainHoldsRecord()) counters.replacements++
        chain.write(key.identity, backup)
        counters.onchainWrites++
        counters.backupWrites++
        counters.registrations++
        if (crashAfterWrite) {
            crash(dev)
            return
        }
        if (dev.active.put(dev.account, key.privateArmor, "") == NativePgpVault.Put.OK) counters.localWrites++
        dev.clearPending()
        dev.setCompletedIdem(idemKey)
        dev.ui = PgpRestoreUi("ok")
    }

    /** Read-only evaluation of the chain against the device's wallet (§25.30.2). Returns the result code. */
    private fun evalRestore(dev: PgpRestoreDevice): String {
        if (!wallet.ready()) {
            dev.ui = PgpRestoreUi("blocked", code = "wallet_not_ready")
            return "blocked"
        }
        if (!chain.chainReadable() || !chain.backupReadable()) {
            dev.ui = PgpRestoreUi("undetermined", code = "pgp_source_unavailable")
            return "undetermined"
        }
        val v = chain.version()
        val onChain = chain.identity()
        val text = chain.backupText()
        if (onChain == null) {
            if (text.isNotEmpty()) {
                // A backup with no registered identity is a state mismatch: the failure class, on the replacement path (r3o).
                dev.ui = PgpRestoreUi("failed", "registration_missing", offerEntry = true, observedVersion = v, code = "pgp_registration_missing")
                return "failed:registration_missing"
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
        if (!onChain.sameAs(identityOf(dev))) {
            if (dev.active.put(dev.account, armor, "") != NativePgpVault.Put.OK) {
                dev.ui = PgpRestoreUi("undetermined", code = "write_failed")
                return "undetermined"
            }
            counters.localWrites++
        }
        dev.ui = PgpRestoreUi("ok")
        return "ok"
    }

    fun restore(devId: String, crashAt: String? = null): Step {
        val dev = devices.getValue(devId)
        val r = evalRestore(dev)
        if (crashAt == "after_store" && identityOf(dev) != null && r == "ok") {
            crash(dev)
            return Step("crashed")
        }
        return Step(r)
    }

    /** The user taps the entry (a failure or a first identity). Only the confirmation screen opens; nothing is written. */
    fun tapEntry(devId: String): Step {
        val dev = devices.getValue(devId)
        val st = dev.ui.state
        if (st != "failed" && st != "first_identity") return rejected("not_available")
        dev.ui = dev.ui.copy(state = "awaiting_confirm", origin = if (st == "first_identity") "first" else "replace")
        return Step("ok")
    }

    /** The user cancels, or the confirmation times out (120 s). The state is evaluated again. */
    fun cancelOrTimeout(devId: String, timeout: Boolean): Step {
        val dev = devices.getValue(devId)
        if (dev.ui.state != "awaiting_confirm") return rejected("not_awaiting_confirm")
        val r = evalRestore(dev)
        return Step(if (timeout) "confirm_timeout" else "cancelled", reevaluated = r)
    }

    /** The user confirms on the native screen. Generates a pending key once per idempotency key, after a CAS check. */
    fun keygen(devId: String, idemKey: String, nativeConfirmed: Boolean, confirmSource: String = "native", crashAt: String? = null): Step {
        val dev = devices.getValue(devId)
        if (dev.completedIdem() == idemKey) return Step("noop", code = "idempotent")
        if (dev.ui.state != "awaiting_confirm") return rejected("not_awaiting_confirm")
        if (confirmSource != "native") return rejected("confirmation_not_native")
        if (!nativeConfirmed) return rejected("native_confirmation_missing")
        val observed = dev.ui.observedVersion ?: return rejected("cas_conflict")
        if (chain.version() != observed) {
            val r = evalRestore(dev)
            return Step("rejected", code = "cas_conflict", reevaluated = r)
        }
        if (dev.pending.state() is NativePgpVault.State.Ready) {
            return if (dev.pendingMeta()?.idemKey == idemKey) Step("noop", code = "idempotent") else rejected("pending_exists")
        }
        counters.keygen++
        val key = keys.newKey(dev.id)
        if (dev.pending.put(dev.account, key.privateArmor, "") != NativePgpVault.Put.OK) {
            dev.ui = dev.ui.copy(state = "retry_write", code = "write_failed")
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

    /** Writes the pending key to the chain, if the chain still matches what the user saw (CAS). */
    fun commit(devId: String, crashAt: String? = null, writeRevert: Boolean = false): Step {
        val dev = devices.getValue(devId)
        if (dev.pending.state() !is NativePgpVault.State.Ready) return rejected("no_pending")
        val meta = dev.pendingMeta()
        if (meta == null) {
            dev.clearPending()
            counters.pendingDiscarded++
            return rejected("no_pending")
        }
        val emptyNow = chain.identity() == null && chain.backupText().isEmpty()
        if (chain.version() != meta.observedVersion || (meta.kind == "first" && !emptyNow)) {
            dev.clearPending()
            counters.pendingDiscarded++
            val r = evalRestore(dev)
            return Step("rejected", code = "cas_conflict", reevaluated = r, idemKey = meta.idemKey)
        }
        if (writeRevert) {
            dev.ui = dev.ui.copy(state = "retry_write", code = "write_failed")
            return rejected("write_reverted")
        }
        val key = pendingKey(dev) ?: return rejected("no_pending")
        val crashAfter = crashAt == "after_write"
        writeIdentity(dev, key, crashAfter, meta.idemKey)
        return Step(if (crashAfter) "crashed" else "ok")
    }

    /** Registration through the native channel only (§25.30.5 第 4 条). The blob is the new identity's backup text. */
    fun registerDirect(identity: PgpIdentity, backupText: String, expectedVersion: Long, nativeConfirmed: Boolean): Step {
        if (!nativeConfirmed) return rejected("native_confirmation_missing")
        if (identity.sameAs(chain.identity())) return Step("noop", code = "already_registered_same_key")
        if (expectedVersion != chain.version()) return rejected("cas_conflict")
        if (chainHoldsRecord()) counters.replacements++
        chain.write(identity, backupText)
        counters.onchainWrites++
        counters.backupWrites++
        counters.registrations++
        return Step("ok")
    }

    /** A write by another device or another client. It is not a step of this device. */
    fun externalWrite(identity: PgpIdentity, backupText: String): Step {
        chain.write(identity, backupText)
        counters.externalWrites++
        return Step("external")
    }

    /** Reconciles after a restart (§25.30.6). A pending key is kept only while the chain still matches; the device never generates here. */
    fun resume(devId: String): Step {
        val dev = devices.getValue(devId)
        dev.crashed = false
        if (dev.pending.state() is NativePgpVault.State.Ready) {
            val key = pendingKey(dev)
            val meta = dev.pendingMeta()
            if (key != null && meta != null) {
                if (chain.identity() == key.identity) {
                    if (dev.active.put(dev.account, key.privateArmor, "") == NativePgpVault.Put.OK) counters.localWrites++
                    dev.setCompletedIdem(meta.idemKey)
                    dev.clearPending()
                    dev.ui = PgpRestoreUi("ok")
                    return Step("reconciled_complete")
                }
                val emptyNow = chain.identity() == null && chain.backupText().isEmpty()
                if (meta.observedVersion == chain.version() && (meta.kind != "first" || emptyNow)) {
                    writeIdentity(dev, key, crashAfterWrite = false, idemKey = meta.idemKey)
                    return Step("reconciled_write")
                }
            }
            dev.clearPending()
            counters.pendingDiscarded++
            evalRestore(dev)
            return Step("reconciled_discarded")
        }
        return Step(evalRestore(dev))
    }
}
