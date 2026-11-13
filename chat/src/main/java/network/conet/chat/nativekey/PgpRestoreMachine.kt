package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The P-IMP-PGP option A state machine (spec r3l §25.30.2 to §25.30.6). Native only; nothing here returns key material.
 *
 * Read-only evaluation ([restore]); the explicit replacement path ([tapEntry], [keygen], [commit], [registerDirect]) with
 * compare-and-set on the chain version, a native confirmation and an idempotency key; and reconciliation after a restart
 * ([resume]). The chain is reached only through [PgpRestoreChain]. Each device has its own local vaults.
 *
 * The machine mirrors the reference simulator `gen-pgp-restore-acceptance-vectors.mjs` (spec §25.30.8). The acceptance
 * vectors check every step result and the final state against it.
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

/** The UI state the PWA shows (§25.30.3, §25.30.7). [uiKey] is the copy key; the copy itself is in the PWA. */
internal class PgpRestoreUi(
    val state: String = "not_evaluated",
    val failureClass: String? = null,
    val offerEntry: Boolean = false,
    val observedVersion: Long? = null,
) {
    fun uiKey(): String? = when (state) {
        "failed" -> "chat.restore_failed.body"
        "undetermined" -> "chat.restore_retry.body"
        "awaiting_confirm" -> "chat.new_identity.confirm.body"
        "retry_write" -> "chat.new_identity.retry.body"
        "blocked" -> "wallet.not_ready"
        else -> null
    }
}

internal data class PendingMeta(val idemKey: String, val expectedVersion: Long)

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
            PendingMeta(o.getString("idemKey"), o.getLong("expectedVersion"))
        } catch (_: Exception) {
            null
        }
    }

    fun writePendingMeta(meta: PendingMeta) {
        val o = JSONObject().put("idemKey", meta.idemKey).put("expectedVersion", meta.expectedVersion)
        files.write(NativePgpVault.pendingMetaName(account), o.toString().toByteArray(Charsets.UTF_8))
    }

    /** Removes the pending key and its metadata. The active identity and the old wrap are not touched. */
    fun clearPending() {
        pending.forget()
        runCatching { files.delete(NativePgpVault.pendingMetaName(account)) }
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
        var localWrites = 0
        var pendingDiscarded = 0
        var externalWrites = 0
        var walletWrites = 0
    }

    /** One step's answer: [result], and optionally a [code] or a [note]. */
    class Step(val result: String, val code: String? = null, val note: String? = null)

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

    /** Writes the device's pending key to the chain (CAS checked by the caller) and then to the device's active slot. */
    private fun writeIdentity(dev: PgpRestoreDevice, crashAfterWrite: Boolean) {
        val key = pendingKey(dev) ?: return
        wrapOldBackupIfReadable(dev)
        val password = wallet.passwordString() ?: return
        val backup = NativePgpBackup.encryptArmor(password, key.privateArmor.toByteArray(Charsets.UTF_8), ivFor(key.identity))
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
        dev.ui = PgpRestoreUi("ok")
    }

    /** Read-only evaluation of the chain against the device's wallet (§25.30.2). Returns the result code. */
    private fun evalRestore(dev: PgpRestoreDevice): String {
        if (!wallet.ready()) {
            dev.ui = PgpRestoreUi("blocked")
            return "blocked"
        }
        if (!chain.chainReadable()) {
            dev.ui = PgpRestoreUi("undetermined")
            return "undetermined"
        }
        val onChain = chain.identity()
        if (onChain == null) {
            dev.ui = PgpRestoreUi("no_identity_yet")
            return "no_identity_yet"
        }
        if (!chain.backupReadable()) {
            dev.ui = PgpRestoreUi("undetermined")
            return "undetermined"
        }
        val text = chain.backupText()
        if (text.isEmpty()) {
            dev.ui = PgpRestoreUi("failed", "backup_missing", offerEntry = true)
            return "failed:backup_missing"
        }
        val password = wallet.passwordString() ?: return "blocked"
        val armorBytes = NativePgpBackup.decryptArmor(password, text)
        val armor = armorBytes?.let { String(it, Charsets.UTF_8) }
        val secret = armor?.let { NativePgp.parseSecret(it) }
        if (armor == null || secret == null) {
            dev.ui = PgpRestoreUi("failed", "decrypt_failed", offerEntry = true)
            return "failed:decrypt_failed"
        }
        val restored = PgpIdentity(secret.fingerprint.uppercase(), NativePgpBackup.subkeyKeyId(secret) ?: "")
        if (restored != onChain) {
            dev.ui = PgpRestoreUi("failed", "fingerprint_mismatch", offerEntry = true)
            return "failed:fingerprint_mismatch"
        }
        if (!onChain.sameAs(identityOf(dev))) {
            if (dev.active.put(dev.account, armor, "") != NativePgpVault.Put.OK) {
                dev.ui = PgpRestoreUi("undetermined")
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

    fun tapEntry(devId: String): Step {
        val dev = devices.getValue(devId)
        if (dev.ui.state != "failed") return rejected("not_available")
        dev.ui = PgpRestoreUi("awaiting_confirm", dev.ui.failureClass, dev.ui.offerEntry, chain.version())
        return Step("ok")
    }

    fun keygen(devId: String, expectedVersion: Long, idemKey: String, nativeConfirmed: Boolean, crashAt: String? = null): Step {
        val dev = devices.getValue(devId)
        if (dev.ui.state != "awaiting_confirm") return rejected("not_awaiting_confirm")
        if (!nativeConfirmed) return rejected("native_confirmation_missing")
        if (expectedVersion != chain.version()) {
            evalRestore(dev)
            return rejected("precondition_failed")
        }
        if (dev.pending.state() is NativePgpVault.State.Ready) {
            return if (dev.pendingMeta()?.idemKey == idemKey) Step("ok", note = "idempotent") else rejected("pending_exists")
        }
        counters.keygen++
        val key = keys.newKey(dev.id)
        if (dev.pending.put(dev.account, key.privateArmor, "") != NativePgpVault.Put.OK) {
            dev.ui = PgpRestoreUi("retry_write", dev.ui.failureClass, dev.ui.offerEntry, dev.ui.observedVersion)
            return rejected("write_reverted")
        }
        dev.writePendingMeta(PendingMeta(idemKey, expectedVersion))
        counters.localWrites++
        if (crashAt == "after_keygen") {
            crash(dev)
            return Step("crashed")
        }
        return Step("ok")
    }

    fun commit(devId: String, crashAt: String? = null, writeRevert: Boolean = false): Step {
        val dev = devices.getValue(devId)
        if (dev.pending.state() !is NativePgpVault.State.Ready) return rejected("no_pending")
        val meta = dev.pendingMeta()
        if (meta == null || meta.expectedVersion != chain.version()) {
            dev.clearPending()
            counters.pendingDiscarded++
            evalRestore(dev)
            return rejected("precondition_failed")
        }
        if (writeRevert) {
            dev.ui = PgpRestoreUi("retry_write", dev.ui.failureClass, dev.ui.offerEntry, dev.ui.observedVersion)
            return rejected("write_reverted")
        }
        val crashAfter = crashAt == "after_write"
        writeIdentity(dev, crashAfter)
        return Step(if (crashAfter) "crashed" else "ok")
    }

    /** Registration through the native channel only (§25.30.5 第 4 条). The blob is the new identity's backup text. */
    fun registerDirect(identity: PgpIdentity, backupText: String, expectedVersion: Long, nativeConfirmed: Boolean): Step {
        if (!nativeConfirmed) return rejected("native_confirmation_missing")
        if (identity.sameAs(chain.identity())) return Step("noop", code = "already_registered_same_key")
        if (expectedVersion != chain.version()) return rejected("precondition_failed")
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

    fun resume(devId: String): Step {
        val dev = devices.getValue(devId)
        dev.crashed = false
        if (dev.pending.state() is NativePgpVault.State.Ready) {
            val key = pendingKey(dev)
            val meta = dev.pendingMeta()
            if (key != null && chain.identity() == key.identity) {
                if (dev.active.put(dev.account, key.privateArmor, "") == NativePgpVault.Put.OK) counters.localWrites++
                dev.clearPending()
                dev.ui = PgpRestoreUi("ok")
                return Step("reconciled_complete")
            }
            if (key != null && meta != null && meta.expectedVersion == chain.version()) {
                writeIdentity(dev, crashAfterWrite = false)
                return Step("reconciled_write")
            }
            dev.clearPending()
            counters.pendingDiscarded++
            evalRestore(dev)
            return Step("reconciled_discarded")
        }
        return Step(evalRestore(dev))
    }
}
