package network.conet.chat.nativekey

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import java.io.ByteArrayInputStream

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
 * The restore's view of the chain (§25.30.2 steps 2 and 3, §25.36.2): one read of the public record and the backup, at one
 * block, from the first endpoint that answers. Read-only. A read that fails is "unreadable", never "no record" or "no backup".
 * It has no version counter: AddressPGP does not expose one, and the CAS version belongs to the replacement path, which is not
 * implemented. [write] is therefore refused.
 */
internal class AddressPgpChain private constructor(
    private val chainOk: Boolean,
    private val backupOk: Boolean,
    private val record: AddressPgpRead.Record?,
    private val backup: String,
) : PgpRestoreChain {
    override fun chainReadable(): Boolean = chainOk

    /** True when a record was read from an endpoint, even if it does not parse. False when no endpoint answered (§25.52I.7). */
    fun recordKnown(): Boolean = record != null

    override fun backupReadable(): Boolean = backupOk

    override fun version(): Long = 0L

    override fun identity(): PgpIdentity? {
        val r = record ?: return null
        return if (r.exists) PgpPublicIdentity.parse(r.publicKeyArmored) else null
    }

    override fun backupText(): String = backup

    override fun write(identity: PgpIdentity, backupText: String) {
        throw IllegalStateException("registration write is not implemented (pending approval, §25.44)")
    }

    companion object {
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
                val snap = try {
                    AddressPgpRead.snapshot(rpcFor(ep), config.contract, eoa).getOrNull()
                } catch (_: Exception) {
                    null
                } ?: continue
                val parsed = !snap.record.exists || PgpPublicIdentity.parse(snap.record.publicKeyArmored) != null
                return AddressPgpChain(parsed, backupOk = true, record = snap.record, backup = snap.backupText)
            }
            return AddressPgpChain(chainOk = false, backupOk = false, record = null, backup = "")
        }
    }
}
