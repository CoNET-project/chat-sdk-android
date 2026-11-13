package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Drives [PgpRestoreMachine] from the acceptance vectors (spec r3l §25.30.8) and renders its step results and final state in
 * the vector's shape. The chain, the wallet, the new keys and the IVs are this harness's; the vector's own keys (P-3, P-4)
 * stand for the natively generated keys, and the IVs are the generator's, so the backup text is byte-identical to the
 * vector's. The device storage is supplied by the caller ([wrapFor], [filesFor]): JVM doubles in the unit tests, the Keystore
 * and app files on a device. Nothing here touches a network or a chain.
 */
internal class PgpRestoreHarness(
    private val doc: JSONObject,
    /** The wallet's private-key string for the backup password ("0x" + 64 lower-case hex). */
    private val password: String,
    private val wrapFor: (deviceId: String) -> KeyWrap,
    private val filesFor: (deviceId: String) -> VaultFiles,
) {
    private val identities = doc.getJSONObject("identities")
    private val backups = doc.getJSONObject("backups")
    private val syntheticKeys = doc.getJSONObject("syntheticKeys")
    val account: String = doc.getJSONObject("syntheticAccount").getString("address").lowercase()

    fun identity(name: String): PgpIdentity =
        PgpIdentity(identities.getJSONObject(name).getString("fingerprint"), identities.getJSONObject(name).getString("subkeyKeyID"))

    fun blobText(label: String): String = backups.getJSONObject(label).getString("base64")

    /** The newly generated key's name for a device: A gets P-3, B gets P-4. */
    fun newKeyName(deviceId: String): String = if (deviceId == "A") "P3" else "P4"

    private val labelOfNewKey = mapOf("P3" to "B_P3_UNDER_A", "P4" to "B_P4_UNDER_A")

    private fun sha256Hex(b: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    /** The vector generator's IV for a backup label: sha256("pgp-restore-acc|iv|" + label), first 24 hex digits. */
    private fun ivOf(label: String): ByteArray {
        val hex = sha256Hex("pgp-restore-acc|iv|$label".toByteArray(Charsets.UTF_8)).substring(0, 24)
        return ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    internal class ChainFake : PgpRestoreChain {
        var chainOk = true
        var backupOk = true
        var ver = 0L
        var id: PgpIdentity? = null
        var text = ""
        override fun chainReadable(): Boolean = chainOk
        override fun backupReadable(): Boolean = backupOk
        override fun version(): Long = ver
        override fun identity(): PgpIdentity? = id
        override fun backupText(): String = text
        override fun write(identity: PgpIdentity, backupText: String) {
            id = identity
            text = backupText
            ver++
        }
    }

    internal class WalletFake(private val pw: String) : PgpRestoreWallet {
        var ready = true
        override fun ready(): Boolean = ready
        override fun passwordString(): String? = pw
    }

    /** One fresh world: a chain, a wallet, two devices and a machine over them. */
    inner class World {
        internal val chain = ChainFake()
        internal val wallet = WalletFake(password)
        val devices: Map<String, PgpRestoreDevice> = listOf("A", "B").associateWith { id ->
            PgpRestoreDevice(id, account, wrapFor(id), filesFor(id))
        }
        private val keys = object : PgpRestoreKeys {
            override fun newKey(deviceId: String): PgpNewKey {
                val name = newKeyName(deviceId)
                return PgpNewKey(syntheticKeys.getJSONObject(name).getString("privateArmor"), identity(name))
            }
        }
        val machine = PgpRestoreMachine(
            chain,
            wallet,
            keys,
            { id -> ivOf(labelOfNewKey.getValue(nameOfFingerprint(id.fingerprint))) },
            devices,
        )

        fun setWalletReady(value: Boolean) {
            wallet.ready = value
        }

        /** Sets the on-chain record: an identity at version 1 with [label]'s backup, or no record at version 0. */
        fun setChain(identityName: String?, label: String = "B_EMPTY") {
            if (identityName == null) {
                chain.ver = 0
                chain.id = null
            } else {
                chain.ver = 1
                chain.id = identity(identityName)
            }
            chain.text = blobText(label)
        }

        fun setReadable(chainOk: Boolean? = null, backupOk: Boolean? = null) {
            chainOk?.let { chain.chainOk = it }
            backupOk?.let { chain.backupOk = it }
        }

        fun nameOfFingerprint(fp: String): String = listOf("P3", "P4").first { identity(it).fingerprint == fp }
    }

    private fun stepJson(step: PgpRestoreMachine.Step): JSONObject {
        val o = JSONObject().put("result", step.result)
        step.code?.let { o.put("code", it) }
        step.reevaluated?.let { o.put("reevaluated", it) }
        step.idemKey?.let { o.put("idemKey", it) }
        return o
    }

    private fun digest(text: String): String = if (text.isEmpty()) "empty" else sha256Hex(text.toByteArray(Charsets.UTF_8))

    /** The final state in the vector's shape. */
    fun snapshot(w: World): JSONObject {
        val c = w.chain
        val chainObj = JSONObject()
            .put("version", c.ver.toInt())
            .put("identityFingerprint", c.id?.fingerprint ?: JSONObject.NULL)
            .put("subkeyKeyID", c.id?.subkeyKeyId ?: JSONObject.NULL)
            .put("backupSha256", digest(c.text))
        val devs = JSONObject()
        for (name in listOf("A", "B")) {
            val d = w.devices.getValue(name)
            val local = d.active.identity()
            val pendingIdentity = d.pending.identity()
            val pendingJson: Any = if (d.pending.state() is NativePgpVault.State.Ready && pendingIdentity != null) {
                JSONObject()
                    .put("label", w.nameOfFingerprint(pendingIdentity.fingerprint))
                    .put("idemKey", d.pendingMeta()?.idemKey ?: "")
            } else {
                JSONObject.NULL
            }
            val ui = d.ui
            devs.put(
                name,
                JSONObject()
                    .put("localIdentity", local?.fingerprint ?: JSONObject.NULL)
                    .put("localSubkeyKeyID", local?.subkeyKeyId ?: JSONObject.NULL)
                    .put("pending", pendingJson)
                    .put("oldArmorWrapped", d.old.state() is NativePgpVault.State.Ready)
                    .put("crashed", d.crashed)
                    .put("completedIdem", d.completedIdem() ?: JSONObject.NULL)
                    .put(
                        "ui",
                        JSONObject()
                            .put("state", ui.state)
                            .put("failureClass", ui.failureClass ?: JSONObject.NULL)
                            .put("offerEntry", ui.offerEntry)
                            .put("observedVersion", ui.observedVersion ?: JSONObject.NULL)
                            .put("code", ui.code ?: JSONObject.NULL)
                            .put("uiKey", ui.uiKey() ?: JSONObject.NULL),
                    ),
            )
        }
        val k = w.machine.counters
        val counters = JSONObject()
            .put("keygen", k.keygen)
            .put("onchainWrites", k.onchainWrites)
            .put("backupWrites", k.backupWrites)
            .put("registrations", k.registrations)
            .put("replacements", k.replacements)
            .put("localWrites", k.localWrites)
            .put("pendingDiscarded", k.pendingDiscarded)
            .put("externalWrites", k.externalWrites)
            .put("walletWrites", k.walletWrites)
        return JSONObject().put("chain", chainObj).put("devices", devs).put("counters", counters)
    }

    /** Runs the steps of one case on [w] and returns the step results in the vector's shape. */
    fun runOn(w: World, steps: JSONArray): JSONArray {
        val results = JSONArray()
        for (i in 0 until steps.length()) {
            val s = steps.getJSONObject(i)
            val op = s.getString("op")
            val dev: Any = if (s.has("dev")) s.getString("dev") else JSONObject.NULL
            val devId = if (s.has("dev")) s.getString("dev") else ""
            val crashAt = if (s.has("crashAt")) s.getString("crashAt") else null
            val body: JSONObject = when (op) {
                "setWalletReady" -> {
                    w.setWalletReady(s.getBoolean("value"))
                    JSONObject().put("result", "ok")
                }
                "setReadable" -> {
                    val v = s.getJSONObject("value")
                    w.setReadable(
                        chainOk = if (v.has("chain")) v.getBoolean("chain") else null,
                        backupOk = if (v.has("backup")) v.getBoolean("backup") else null,
                    )
                    JSONObject().put("result", "ok")
                }
                "setChain" -> {
                    val label = if (s.has("blob") && !s.isNull("blob")) s.getString("blob") else "B_EMPTY"
                    w.setChain(if (s.isNull("identity")) null else s.getString("identity"), label)
                    JSONObject().put("result", "ok")
                }
                "externalWrite" -> stepJson(
                    w.machine.externalWrite(identity(s.getString("identity")), blobText(s.getString("blob"))),
                )
                "restore" -> stepJson(w.machine.restore(devId, crashAt))
                "tapEntry" -> stepJson(w.machine.tapEntry(devId))
                "keygen" -> stepJson(
                    w.machine.keygen(
                        devId,
                        s.getString("idemKey"),
                        s.getBoolean("nativeConfirmed"),
                        if (s.has("confirmSource")) s.getString("confirmSource") else "native",
                        crashAt,
                    ),
                )
                "cancelConfirm" -> stepJson(w.machine.cancelOrTimeout(devId, timeout = false))
                "confirmTimeout" -> stepJson(w.machine.cancelOrTimeout(devId, timeout = true))
                "commit" -> stepJson(w.machine.commit(devId, crashAt, s.has("writeRevert") && s.getBoolean("writeRevert")))
                "registerDirect" -> {
                    val name = s.getString("identity")
                    stepJson(
                        w.machine.registerDirect(
                            identity(name),
                            blobText("B_${name}_UNDER_A"),
                            s.getLong("expectedVersion"),
                            s.getBoolean("nativeConfirmed"),
                        ),
                    )
                }
                "resume" -> stepJson(w.machine.resume(devId))
                else -> error("unknown op $op")
            }
            val out = JSONObject().put("op", op).put("dev", dev)
            val keys = body.keys()
            while (keys.hasNext()) {
                val key = keys.next().toString()
                out.put(key, body.get(key))
            }
            results.put(out)
        }
        return results
    }

    /** Runs one case from a fresh world. */
    fun run(steps: JSONArray): Pair<JSONArray, JSONObject> {
        val w = World()
        val results = runOn(w, steps)
        return results to snapshot(w)
    }

    companion object {
        /** Deep equality of JSON values (null and JSONObject.NULL are equal; numbers compare by value). */
        fun jsonEq(a: Any?, b: Any?): Boolean {
            if (a == null || a == JSONObject.NULL) return b == null || b == JSONObject.NULL
            if (b == null || b == JSONObject.NULL) return false
            return when (a) {
                is JSONObject -> {
                    val ka = a.keys().asSequence().map { it.toString() }.toSet()
                    b is JSONObject && ka == b.keys().asSequence().map { it.toString() }.toSet() && ka.all { jsonEq(a.get(it), b.get(it)) }
                }
                is JSONArray -> b is JSONArray && a.length() == b.length() && (0 until a.length()).all { jsonEq(a.get(it), b.get(it)) }
                is Number -> b is Number && a.toDouble() == b.toDouble()
                else -> a == b
            }
        }
    }
}
