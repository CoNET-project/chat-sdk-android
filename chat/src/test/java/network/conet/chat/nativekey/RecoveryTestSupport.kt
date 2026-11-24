package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

/** A real OpenPGP key of a synthetic account, with the identity the registry would hold for it. */
internal class RecPgp(val privateArmor: String, val publicArmor: String, val identity: PgpIdentity)

internal object RecKeys {
    fun generate(account: String, random: SecureRandom = SecureRandom()): RecPgp {
        val gen = NativePgpKeyGen.generate(account, random)
        val secret = NativePgp.parseSecret(gen.privateArmor)!!
        return RecPgp(gen.privateArmor, gen.publicArmor, PgpIdentity(secret.fingerprint.uppercase(), NativePgpBackup.subkeyKeyId(secret)!!))
    }
}

/**
 * Two keys with the SAME master key (same fingerprint) and different encryption subkeys (different first-subkey key ids), as one master can carry
 * after a subkey change. The first is the one a registry would hold; the second is an older or newer ring of the same master.
 */
@Suppress("DEPRECATION")
internal fun sameMasterKeys(account: String, random: SecureRandom = SecureRandom()): Pair<RecPgp, RecPgp> {
    val date = Date()
    val ed = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(random)) }.generateKeyPair()
    val master = BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, ed, date)
    fun ring(): RecPgp {
        val x = X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(random)) }.generateKeyPair()
        val sub = BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, x, date)
        val masterHashed = PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA) }.generate()
        val subHashed = PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE) }.generate()
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, master, account, BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            masterHashed, null, BcPGPContentSignerBuilder(master.publicKey.algorithm, HashAlgorithmTags.SHA256), null,
        )
        gen.addSubKey(sub, subHashed, null)
        val priv = ByteArrayOutputStream().also { out -> ArmoredOutputStream.builder().clearHeaders().build(out).use { gen.generateSecretKeyRing().encode(it) } }
        val pub = ByteArrayOutputStream().also { out -> ArmoredOutputStream.builder().clearHeaders().build(out).use { gen.generatePublicKeyRing().encode(it) } }
        val privateArmor = priv.toString(Charsets.UTF_8.name())
        val secret = NativePgp.parseSecret(privateArmor)!!
        return RecPgp(privateArmor, pub.toString(Charsets.UTF_8.name()), PgpIdentity(secret.fingerprint.uppercase(), NativePgpBackup.subkeyKeyId(secret)!!))
    }
    return ring() to ring()
}

/** The registry read of [pgp]'s public key, as [AddressPgpChain.registeredKey] would give it (the test builds it directly). */
internal fun registeredOf(
    pgp: RecPgp,
    account: String,
    source: RegisteredPgpKey.Source = RegisteredPgpKey.Source.AGREED,
    chainId: Long = AddressPgpChain.CONET_CHAIN_ID,
    contract: String = AddressPgpConfig.default.contract.lowercase(),
    block: Long? = 100L,
    publicArmor: String = pgp.publicArmor,
    fingerprint: String = pgp.identity.fingerprint,
    subkey: String = pgp.identity.subkeyKeyId,
): RegisteredKeyRead =
    RegisteredKeyRead.Present(RegisteredPgpKey(account, fingerprint, subkey, publicArmor, block, source, chainId, contract))

/** A chain that is what a case describes: readable or not, with a registered key read and a backup text. The identity comes from the registered key. */
internal class RecChain(
    private val readable: Boolean = true,
    private val registered: RegisteredKeyRead,
    private val backup: String = "",
) : PgpRestoreChain {
    override fun chainReadable(): Boolean = readable
    override fun backupReadable(): Boolean = readable
    override fun version(): Long = 0L
    override fun identity(): PgpIdentity? = (registered as? RegisteredKeyRead.Present)?.key?.let { PgpIdentity(it.fingerprint, it.subkeyKeyId) }
    override fun registeredKey(): RegisteredKeyRead = registered
    override fun backupText(): String = backup
    override fun write(identity: PgpIdentity, backupText: String) = error("the recovery never writes the chain")
}

/** Vault files that count every write, delete and rename, keep one ordered log, and can refuse writes. */
internal class CountingFiles(val inner: NativeTestFiles, val log: MutableList<String>) : VaultFiles {
    var writes = 0
    var deletes = 0
    var renames = 0
    var refuseWrites = false

    override fun read(name: String): ByteArray? = inner.read(name)
    override fun names(): List<String> = inner.names()

    override fun write(name: String, bytes: ByteArray) {
        if (refuseWrites) throw java.io.IOException("disk full")
        writes++
        log += "vault.write"
        inner.write(name, bytes)
    }

    override fun delete(name: String) {
        deletes++
        log += "vault.delete"
        inner.delete(name)
    }

    override fun rename(from: String, to: String) {
        renames++
        log += "vault.rename"
        inner.rename(from, to)
    }

    /** True when nothing was written, deleted or renamed through this double. */
    val untouched: Boolean get() = writes == 0 && deletes == 0 && renames == 0
}

/** A K_pgp backend that counts writes and logs them in the shared order log. */
internal class CountingKBackend(val log: MutableList<String>) : AccountPgpKBackend {
    val inner = MemoryAccountPgpKBackend()
    var puts = 0
    var removes = 0
    var refusePut = false
    override fun get(name: String): String? = inner.get(name)
    override fun put(name: String, value: String): Boolean {
        if (refusePut) return false
        puts++
        log += "k.put"
        return inner.put(name, value)
    }
    override fun names(): Set<String> = inner.names()
    override fun remove(name: String): Boolean {
        removes++
        return inner.remove(name)
    }
}

/** Records and endpoints as the chain serves them (ABI of `_pgpKeys(address)` and `getEncryptedPrivateKey()`), for the real readers. */
internal object ChainFixture {
    private fun word(v: Long): ByteArray = ByteArray(32).also { w -> for (i in 0 until 8) w[31 - i] = ((v shr (8 * i)) and 0xFF).toByte() }
    private fun string(s: String): ByteArray {
        val b = s.toByteArray(Charsets.UTF_8)
        return word(b.size.toLong()) + b + ByteArray((32 - b.size % 32) % 32)
    }
    private fun hex(b: ByteArray) = "0x" + b.joinToString("") { "%02x".format(it) }

    /** The `_pgpKeys` answer: [stored] is exactly what the chain holds in `publicKeyArmored` (a base64 text for a real record); null is "no record". */
    fun recordHex(stored: String?): String {
        val a = string("")
        val p = string(stored ?: "")
        val c = string("")
        val head = word(128) + word(128L + a.size) + word(128L + a.size + p.size) + word(if (stored != null) 1 else 0)
        return hex(head + a + p + c)
    }

    fun backupHex(text: String): String = hex(word(32) + string(text))

    /** The way a registration stores an armor: the strict base64 of its UTF-8 text. */
    fun base64Of(armor: String): String = java.util.Base64.getEncoder().encodeToString(armor.toByteArray(Charsets.UTF_8))

    val urlA = "https://a.test"
    val urlB = "https://b.test"
    val config = AddressPgpConfig(AddressPgpConfig.default.contract, listOf(RegistryEndpoint(urlA, 1000), RegistryEndpoint(urlB, 1000)))

    class Endpoint(
        val chainId: String? = "0x36ca6",
        val blockNumber: String? = "0x2a",
        val hash: String = "0x" + "ab".repeat(32),
        val record: String,
        val backup: String,
        val callFails: Boolean = false,
    ) : AddressPgpRead.Rpc {
        override fun call(method: String, params: JSONArray): Any? = when (method) {
            "eth_chainId" -> chainId ?: error("down")
            "eth_blockNumber" -> blockNumber ?: error("down")
            "eth_getBlockByNumber" -> JSONObject().put("number", blockNumber ?: error("down")).put("hash", hash)
            "eth_call" -> {
                if (callFails) error("down")
                val data = params.getJSONObject(0).getString("data").substring(0, 10)
                if (data == AddressPgpRead.selector(AddressPgpRead.SIG_PGP_KEYS)) record else backup
            }
            else -> error("unexpected $method")
        }
    }

    fun agreed(account: String, a: Endpoint, b: Endpoint = a, cfg: AddressPgpConfig = config) =
        AddressPgpChain.readAgreed(account, cfg) { ep -> if (ep.url == urlA) a else b }

    fun single(account: String, a: Endpoint) = AddressPgpChain.readSingle(account, config) { a }
}
