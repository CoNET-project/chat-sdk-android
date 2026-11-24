package network.conet.chat.nativekey

import android.content.Context
import network.conet.chat.BeamioChatPgpStore
import org.json.JSONObject

/**
 * The P-IMP-PGP restore commands (spec §25.35.2 to §25.35.3; plan A §25.30.2). `pgpRestoreEvaluate` is read-only.
 * `pgpRestore` evaluates and, when the fingerprint matches, writes the local vault and reads it back. Neither writes the
 * chain, generates a key, or registers. The machine decides everything; this object maps its result to the spec's fields.
 */
internal object PgpRestoreBridge {
    /** The device id the production wiring uses for the account's vault. */
    const val DEVICE = "A"

    private fun stateOf(ui: PgpRestoreUi): String = if (ui.state == "blocked") "undetermined" else ui.state

    /**
     * The `pgpRestoreEvaluate` result: `{state, failureClass, code, offerEntry, uiKey, legacy, chain}` (§25.35.2; §13 for legacy and chain).
     * `legacy` (ABSENT | PRESENT | UNREADABLE | unknown) and `chain` (unregistered | registered | unknown) come from the caller (FirstIdentityRule);
     * anything not supplied is unknown (fail closed). Writes nothing.
     */
    fun evaluate(machine: PgpRestoreMachine, devId: String = DEVICE, legacy: String = "unknown", chain: String = "unknown"): JSONObject {
        machine.evaluate(devId)
        val ui = machine.devices.getValue(devId).ui
        return JSONObject()
            .put("state", stateOf(ui))
            .put("failureClass", ui.failureClass ?: JSONObject.NULL)
            .put("code", ui.code ?: JSONObject.NULL)
            .put("offerEntry", ui.offerEntry)
            .put("uiKey", ui.uiKey() ?: JSONObject.NULL)
            .put("legacy", legacy)
            .put("chain", chain)
    }

    /**
     * The fields of the `pgpRestoreResult` event (§25.35.3): `{code, state, failureClass?, uiKey?}`. The caller adds `type` and
     * `reqId`. `code` is `ok` on success, the failure code otherwise, and `pgp_source_unavailable` when the machine gives no code.
     */
    fun restore(machine: PgpRestoreMachine, devId: String = DEVICE): JSONObject {
        machine.restore(devId)
        val ui = machine.devices.getValue(devId).ui
        // The request was accepted and the material it needs became unavailable before any write (the passcode package is not provided, or the storage
        // cannot be read): one `cancelled`, no data, nothing written (vector C-28). Nothing here reads a UI lock.
        if (ui.state == "blocked" && ui.code == "wallet_not_ready") return JSONObject().put("code", "cancelled")
        val state = stateOf(ui)
        val code = when (state) {
            "ok" -> "ok"
            "first_identity" -> "first_identity"
            else -> ui.code ?: "pgp_source_unavailable"
        }
        val out = JSONObject().put("code", code).put("state", state)
        ui.failureClass?.let { out.put("failureClass", it) }
        ui.uiKey()?.let { out.put("uiKey", it) }
        return out
    }

    /** The production machine for [eoa]: the chain read from AddressPGP, the wallet's key, and the account's PGP vault. */
    /**
     * The chain transport of the restore (Android's counterpart of the iOS chain transport, 25.52BT.1). The production value is the HTTP
     * RPC. A test target may replace it to keep a command in flight; production code never sets it.
     */
    internal var chainRpc: (RegistryEndpoint) -> AddressPgpRead.Rpc = { ep -> AddressPgpRead.HttpRpc(ep.url, ep.timeoutMs) }

    /** The chain read of one restore request: the primary endpoint only (single-RPC caliber, no second endpoint). */
    fun productionChain(eoa: String): AddressPgpChain = AddressPgpChain.readSingle(eoa, rpcFor = chainRpc)

    fun productionMachine(
        context: Context,
        eoa: String,
        chain: AddressPgpChain = productionChain(eoa),
        /** The store account of a vault with no record (0.2.30); null keeps the vault wallet. */
        storeAccount: StoreAwareAccount.Resolution.Account? = null,
    ): PgpRestoreMachine {
        val vault = NativeWallet.vault(context)
        // The absence rule is the chain's own confirmation (single read; a registration check is made again at the confirmation).
        return PgpRestoreMachine(
            chain = chain,
            wallet = if (storeAccount == null) VaultPgpWallet(vault) else StorePgpWallet(context.applicationContext, storeAccount),
            keys = RefusedKeys,
            ivFor = { throw IllegalStateException("key generation is not available in this build") },
            devices = mapOf(DEVICE to NativeWallet.pgpRestoreDevice(context, eoa, DEVICE)),
            absence = RegisteringAbsenceRule { writeBlock -> chain.confirmedAbsentAfter(writeBlock) },
            shippedArmor = { shippedKeyOf(context.applicationContext, eoa) },
            recoveryGate = PageRecoveryGate(),
        )
    }

    /**
     * The account's own key an older build left in the SDK's store, read only (0.2.30): null when there is none, when it belongs to another account,
     * or when the store cannot be read. The machine uses it only when it is the identity registered on the chain; the file is never changed.
     */
    private fun shippedKeyOf(context: Context, eoa: String): String? {
        val owner = BeamioChatPgpStore.legacyOwnerEoa(context)
        if (owner != null && !owner.equals(eoa, ignoreCase = true)) return null
        return BeamioChatPgpStore.legacyPrivateArmorStrict(context)
    }

    /** The wallet's private-key string for the backup password ("0x" + 64 lower-case hex). The key is cleared after use. */
    private class VaultPgpWallet(private val vault: NativeWalletVault) : PgpRestoreWallet {
        override fun ready(): Boolean = vault.state() is NativeWalletVault.State.Ready

        override fun passwordString(): String? {
            val key = vault.unlock() ?: return null
            try {
                return "0x" + key.joinToString("") { "%02x".format(it) }
            } finally {
                key.fill(0)
            }
        }

        override fun passwordForms(): List<String>? {
            val key = vault.unlock() ?: return null
            try {
                return NativePgpBackup.passwordForms(key)
            } finally {
                key.fill(0)
            }
        }
    }

    /**
     * The wallet of a store account (0.2.30): the key is re-derived from the store for each call and zeroed after it. A plain set derives it from
     * the stored phrase; a v3 set gives it only while this session holds its key. Nothing is written, and the key never leaves native code.
     */
    private class StorePgpWallet(private val app: Context, private val account: StoreAwareAccount.Resolution.Account) : PgpRestoreWallet {
        override fun ready(): Boolean {
            val key = StoreAwareAccount.keyOf(app, account) ?: return false
            key.fill(0)
            return true
        }

        override fun passwordString(): String? = withKey { NativePgpBackup.passwordString(it) }

        override fun passwordForms(): List<String>? = withKey { NativePgpBackup.passwordForms(it) }

        private fun <T> withKey(block: (ByteArray) -> T): T? {
            val key = StoreAwareAccount.keyOf(app, account) ?: return null
            try {
                return block(key)
            } finally {
                key.fill(0)
            }
        }
    }

    /** Key generation is not part of restore. Any call is a bug, so it fails loudly. */
    private object RefusedKeys : PgpRestoreKeys {
        override fun newKey(deviceId: String): PgpNewKey =
            throw IllegalStateException("key generation is not available in this build")
    }
}
