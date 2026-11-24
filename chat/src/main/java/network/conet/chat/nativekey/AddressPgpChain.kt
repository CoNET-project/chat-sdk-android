package network.conet.chat.nativekey

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import java.io.ByteArrayInputStream
import org.json.JSONArray
import org.json.JSONObject

/** AddressPGP for the restore (spec §25.36.5): the contract, and its endpoints in the order they are tried. */
internal class AddressPgpConfig(val contract: String, val endpoints: List<RegistryEndpoint>) {
    companion object {
        /**
         * §25.36.5: `0x684b0ac760cEE9c9b85de36d69746420648Cf9e2` on CoNET L1 (224422). `rpc1` is primary and `publicrpc`
         * is the backup, both official. Timeouts match the registry reads (12 s each).
         */
        val default: AddressPgpConfig = AddressPgpConfig(
            contract = "0x684b0ac760cEE9c9b85de36d69746420648Cf9e2",
            endpoints = listOf(
                RegistryEndpoint("https://rpc1.conet.network", 12_000),
                RegistryEndpoint("https://publicrpc.conet.network", 12_000),
            ),
        )
    }
}

/**
 * The identity of an OpenPGP public armor, in the same form the backup side uses (`NativePgpBackup.subkeyKeyId`): the master
 * fingerprint in upper case, and the first subkey's key ID as 16 upper-case hex digits. `null` when the armor does not parse.
 */
internal object PgpPublicIdentity {
    fun parse(armor: String): PgpIdentity? = try {
        val ring = PGPPublicKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(armor.toByteArray(Charsets.UTF_8))),
            BcKeyFingerprintCalculator(),
        )
        val keys = ring.publicKeys.asSequence().toList()
        val master = keys.firstOrNull { it.isMasterKey } ?: return null
        val sub = keys.drop(1).firstOrNull() ?: return null
        PgpIdentity(
            master.fingerprint.joinToString("") { "%02X".format(it) },
            "%016X".format(sub.keyID),
        )
    } catch (_: Exception) {
        null
    }
}

/**
 * The registered public key as the chain stores it. The registration writes the armor as strict base64 text (`ChatRouteRegister`), so a
 * real record holds `LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBC…`, not `-----BEGIN PGP PUBLIC KEY BLOCK-----`. Every reader of a registered armor goes through
 * [normalize]: a text that starts with the public-key BEGIN header (and holds no other BEGIN header) is used as it is; any other text is decoded
 * with the strict base64 and the result must be such a text; anything else, a private-key header, any other BEGIN header, a text that holds a second
 * armor block, is null (the read is then unknown, never absent). A registry field never holds a private key, so none is let through.
 */
internal object RegisteredArmor {
    private const val BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK"
    private val ANY_BEGIN = Regex("-----BEGIN ")

    fun normalize(stored: String): String? {
        val text = stored.trim()
        if (text.isEmpty()) return null
        if (isPublicArmor(text)) return stored
        val bytes = NativePgpBackup.strictBase64(text) ?: return null
        val decoded = try {
            String(bytes, Charsets.UTF_8)
        } catch (_: Exception) {
            return null
        }
        return if (isPublicArmor(decoded.trim())) decoded else null
    }

    /** The text starts with the public-key header and has no other armor header anywhere in it. */
    private fun isPublicArmor(text: String): Boolean = text.startsWith(BEGIN) && ANY_BEGIN.findAll(text).count() == 1

    /** The identity of a stored registered armor (raw or base64); null when it cannot be read as a public armor. */
    fun identityOf(stored: String): PgpIdentity? = normalize(stored)?.let { PgpPublicIdentity.parse(it) }
}

/**
 * The restore's view of the chain (§25.30.2 steps 2 and 3, §25.36.2): one read of the public record and the backup, at one
 * block, from the first endpoint that answers. Read-only. A read that fails is "unreadable", never "no record" or "no backup".
 * It has no version counter: AddressPGP does not expose one, and the CAS version belongs to the replacement path, which is not
 * implemented. [write] is therefore refused.
 */
internal class AddressPgpChain internal constructor(
    private val chainOk: Boolean,
    private val backupOk: Boolean,
    private val record: AddressPgpRead.Record?,
    private val backup: String,
    private val reread: (() -> PgpRestoreChain)? = null,
    private val block: Long? = null,
    /** The account this snapshot was read for (lower case); empty for a chain that was not read for one. */
    private val account: String = "",
    /** The contract the snapshot was read from. */
    private val contract: String = "",
    /** How the snapshot was read: both endpoints agreeing, one endpoint, or neither (not readable, or a first-answer read). */
    private val source: RegisteredPgpKey.Source? = null,
    /** Why the read gave no usable chain (a fixed word, for the SDK log only); null for a chain that was read. */
    private val failure: String? = null,
) : PgpRestoreChain {
    /**
     * Draft 第 3 节 / T-3, the absence confirmation for a registering marker (5B.2, 5B.7): the record is absent on both endpoints at this chain's block,
     * and that block is later than [writeBlock]. Only a chain from [readAgreed] can say so; any other chain answers false.
     */
    fun confirmedAbsentAfter(writeBlock: Long): Boolean {
        val b = block ?: return false
        val r = record ?: return false
        return chainOk && !r.exists && b > writeBlock
    }

    /** P2 (review 3): the block this record was read at (the snapshot's block). Null when no endpoint answered. */
    override fun headBlock(): Long? = block

    override fun chainReadable(): Boolean = chainOk

    /** True when a record was read from an endpoint, even if it does not parse. False when no endpoint answered (§25.52I.7). */
    fun recordKnown(): Boolean = record != null

    override fun backupReadable(): Boolean = backupOk

    override fun version(): Long = 0L

    override fun identity(): PgpIdentity? {
        val r = record ?: return null
        return if (r.exists) RegisteredArmor.identityOf(r.publicKeyArmored) else null
    }

    /**
     * G1 (review): a record that exists but does not parse is Unknown, never Absent. A chain that was not read is Unknown too.
     */
    override fun identityRead(): IdentityRead {
        if (!chainOk) return IdentityRead.Unknown
        val r = record ?: return IdentityRead.Unknown
        if (!r.exists) return IdentityRead.Absent
        val parsed = RegisteredArmor.identityOf(r.publicKeyArmored) ?: return IdentityRead.Unknown
        return IdentityRead.Present(parsed)
    }

    /**
     * The registered key of the account as a typed value: only a snapshot that was read for an account, from the CoNET L1
     * chain id, by [readAgreed] or [readSingle], gives one. The armor is the one stored in the record, never one derived from a private key; the
     * `pgpKeyId` field of the record is not used. Unreadable or not parseable is [RegisteredKeyRead.Unknown], never absent.
     */
    override fun registeredKey(): RegisteredKeyRead {
        val src = source ?: return RegisteredKeyRead.Unknown
        if (!chainOk || account.isEmpty() || contract.isEmpty()) return RegisteredKeyRead.Unknown
        val r = record ?: return RegisteredKeyRead.Unknown
        if (!r.exists) return RegisteredKeyRead.Absent
        val armor = RegisteredArmor.normalize(r.publicKeyArmored) ?: return RegisteredKeyRead.Unknown
        val id = PgpPublicIdentity.parse(armor) ?: return RegisteredKeyRead.Unknown
        // The key holds the decoded armor: it is the one the gate verifies with.
        return RegisteredKeyRead.Present(
            RegisteredPgpKey(account, id.fingerprint, id.subkeyKeyId, armor, block, src, CONET_CHAIN_ID, contract),
        )
    }

    override fun registeredKeyFailure(): String? = when {
        source == null -> failure ?: "not_a_gate_read"
        !chainOk -> failure ?: "unreadable"
        record == null -> "record_missing"
        else -> null
    }

    override fun backupText(): String = backup

    /** B-B (review): a new read of the same endpoints for the pre-write re-read and the post-write read-back. */
    override fun reread(): PgpRestoreChain = reread?.invoke() ?: this

    override fun write(identity: PgpIdentity, backupText: String) {
        throw IllegalStateException("registration write is not implemented (pending approval, §25.44)")
    }

    companion object {
        /**
         * Draft r2.5.20 第 6 版 T-3: the record and the backup are read from the two endpoints A and B at one block N (N is A's block number).
         * An error on either endpoint, a disagreement on the record or the backup, or fewer than two endpoints is unknown (unreadable), never absence.
         * Used by the production restore path; [read] keeps its first-answer behaviour for the other callers.
         */
        fun readAgreed(
            eoa: String,
            config: AddressPgpConfig = AddressPgpConfig.default,
            rpcFor: (RegistryEndpoint) -> AddressPgpRead.Rpc,
        ): AddressPgpChain {
            if (config.endpoints.size < 2) return unknownChain("endpoints")
            val rpcA = try { rpcFor(config.endpoints[0]) } catch (e: Exception) { return unknownChain("rpc_a") }
            val rpcB = try { rpcFor(config.endpoints[1]) } catch (e: Exception) { return unknownChain("rpc_b") }
            // Both endpoints must answer the CoNET L1 chain id before anything else is read from them (a recovery gate input).
            if (chainIdOf(rpcA) != CONET_CHAIN_ID) return unknownChain("chainid_a")
            if (chainIdOf(rpcB) != CONET_CHAIN_ID) return unknownChain("chainid_b")
            val tag = try { rpcA.call("eth_blockNumber", JSONArray()) as? String } catch (e: Exception) { null } ?: return unknownChain("blocknumber")
            val n = tag.removePrefix("0x").toLongOrNull(16) ?: return unknownChain("blocknumber")
            // RP-05, RP-08 (rpc-state-vectors): each endpoint must return block N itself, with the same hash; a different block is unknown.
            val ha = hashAt(rpcA, tag, n) ?: return unknownChain("hash_a")
            val hb = hashAt(rpcB, tag, n) ?: return unknownChain("hash_b")
            if (ha != hb) return unknownChain("hash_differ")
            val sa = AddressPgpRead.snapshotAt(rpcA, config.contract, eoa, tag).getOrNull() ?: return unknownChain("snapshot_a")
            val sb = AddressPgpRead.snapshotAt(rpcB, config.contract, eoa, tag).getOrNull() ?: return unknownChain("snapshot_b")
            if (sa.record != sb.record || sa.backupText != sb.backupText) return unknownChain("record_differ")
            val parsed = !sa.record.exists || RegisteredArmor.identityOf(sa.record.publicKeyArmored) != null
            return AddressPgpChain(parsed, backupOk = true, record = sa.record, backup = sa.backupText,
                reread = { readAgreed(eoa, config, rpcFor) }, block = sa.block,
                account = eoa.lowercase(), contract = config.contract.lowercase(), source = RegisteredPgpKey.Source.AGREED,
                failure = if (parsed) null else "armor_parse")
        }

        /** The chain id an endpoint answers, or null when the call fails or the answer is not a number. */
        private fun chainIdOf(rpc: AddressPgpRead.Rpc): Long? = try {
            (rpc.call("eth_chainId", JSONArray()) as? String)?.removePrefix("0x")?.toLongOrNull(16)
        } catch (e: Exception) {
            null
        }

        private fun unknownChain(reason: String): AddressPgpChain = AddressPgpChain(chainOk = false, backupOk = false, record = null, backup = "", failure = reason)

        /** The hash of block [n] as the endpoint returns it for [tag]; null when the call fails or the endpoint answers another block. */
        private fun hashAt(rpc: AddressPgpRead.Rpc, tag: String, n: Long): String? = AddressPgpRead.blockHashAt(rpc, tag, n)

        /**
         * Reads the record and the backup of [eoa]. A public record that does not parse makes the chain unreadable
         * (§25.30.2 step 2, the parse failure case). When no endpoint answers, both reads are unreadable.
         */
        fun read(
            eoa: String,
            config: AddressPgpConfig = AddressPgpConfig.default,
            rpcFor: (RegistryEndpoint) -> AddressPgpRead.Rpc,
        ): AddressPgpChain {
            for (ep in config.endpoints) {
                // diag5 (logging only): the endpoint, the milliseconds and the exception class of a failed read (no content, no message).
                val t0 = DiagTiming.now()
                val res: Result<AddressPgpRead.Snapshot> = try {
                    AddressPgpRead.snapshot(rpcFor(ep), config.contract, eoa)
                } catch (e: Exception) {
                    Result.failure(e)
                }
                val snap = res.getOrNull()
                if (snap == null) {
                    DiagTiming.log("chain:" + ep.url.substringAfter("//"), t0, "fail:" + (res.exceptionOrNull()?.javaClass?.simpleName ?: "null"))
                    continue
                }
                val parsed = !snap.record.exists || RegisteredArmor.identityOf(snap.record.publicKeyArmored) != null
                return AddressPgpChain(parsed, backupOk = true, record = snap.record, backup = snap.backupText,
                    reread = { read(eoa, config, rpcFor) }, block = snap.block)
            }
            return AddressPgpChain(chainOk = false, backupOk = false, record = null, backup = "")
        }

        /** CoNET L1 (§25.36.5). Any other chain id answered by the endpoint is a read failure. */
        internal const val CONET_CHAIN_ID = 224422L

        /**
         * Single-RPC read (frozen protocol §13): the primary endpoint only, with no second endpoint and no block cross-check.
         * The endpoint must answer the CoNET L1 chain id, and the record must be readable. Any failure, timeout, malformed answer or wrong
         * chain id is unknown (fail closed). It never falls back to the second endpoint.
         */
        fun readSingle(
            eoa: String,
            config: AddressPgpConfig = AddressPgpConfig.default,
            rpcFor: (RegistryEndpoint) -> AddressPgpRead.Rpc,
        ): AddressPgpChain {
            val ep = config.endpoints.firstOrNull() ?: return unknownChain("endpoints")
            val rpc = try { rpcFor(ep) } catch (e: Exception) { return unknownChain("rpc_a") }
            if (chainIdOf(rpc) != CONET_CHAIN_ID) return unknownChain("chainid_a")
            val snap = try { AddressPgpRead.snapshot(rpc, config.contract, eoa).getOrNull() } catch (e: Exception) { null } ?: return unknownChain("snapshot_a")
            val parsed = !snap.record.exists || RegisteredArmor.identityOf(snap.record.publicKeyArmored) != null
            return AddressPgpChain(parsed, backupOk = true, record = snap.record, backup = snap.backupText,
                reread = { readSingle(eoa, config, rpcFor) }, block = snap.block,
                account = eoa.lowercase(), contract = config.contract.lowercase(), source = RegisteredPgpKey.Source.SINGLE,
                failure = if (parsed) null else "armor_parse")
        }
    }
}

/**
 * The registered public key of an account, as the recovery gate needs it: the record's own public armor and its identity, the account it
 * was read for, the chain and contract, the block, and how it was read. Built only by [AddressPgpChain.registeredKey]; a guard test keeps every
 * other file from constructing it. Nothing in it is derived from a private key.
 */
internal class RegisteredPgpKey internal constructor(
    val account: String,
    val fingerprint: String,
    val subkeyKeyId: String,
    val publicArmor: String,
    val block: Long?,
    val source: Source,
    val chainId: Long,
    val contract: String,
) {
    /** Both endpoints at one block ([AGREED]) or the primary endpoint alone ([SINGLE]). */
    enum class Source { AGREED, SINGLE }
}

/** The registered key read: not readable (never "absent"), confirmed absent, or the key. */
internal sealed class RegisteredKeyRead {
    object Unknown : RegisteredKeyRead()
    object Absent : RegisteredKeyRead()
    class Present(val key: RegisteredPgpKey) : RegisteredKeyRead()
}
