package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import network.conet.chat.localread.LocalChatIds
import org.junit.Test
import java.io.File
import java.util.regex.Pattern

/**
 * C-5 at the JVM layer (review): the Android log-scan patterns of `spec/log-scan-patterns.v1.json` run over
 * (1) a positive fixture of logcat-style lines with synthetic key and phrase forms (the canary: each class must be hit), and
 * (2) the real output of the three paths (sync, pre-read, discard), with the logcat prefix, and the artifacts those paths write (the audit and
 * the intent). The negative run must have zero hits. LS-F1 needs each platform's numbers, which the spec does not list: it is not run here.
 * The device logcat scan (C-5 on the phone) is not run here.
 */
class LogScanFixtureTest {
    private data class Hit(val id: String)

    private val patterns: JSONObject = JSONObject(File("../spec/log-scan-patterns.v1.json").readText(Charsets.UTF_8))
    private val allowlist: Set<String> = (0 until patterns.getJSONObject("digestAllowlist").getJSONArray("entries").length()).map {
        patterns.getJSONObject("digestAllowlist").getJSONArray("entries").getJSONObject(it).getString("sha256").lowercase()
    }.toSet()
    private val wordlist: Set<String> = File("../spec/bip39-english.txt").readLines().map { it.trim() }.filter { it.isNotEmpty() }.toSet()

    /** Every pattern except LS-F1 (numbers from each platform's fixture), over [text]. */
    private fun scan(text: String): List<Hit> {
        val hits = mutableListOf<Hit>()
        val list = patterns.getJSONArray("patterns")
        for (i in 0 until list.length()) {
            val p = list.getJSONObject(i)
            val id = p.getString("id")
            val ci = p.optBoolean("caseInsensitive", false)
            when (p.getString("kind")) {
                "literal" -> {
                    val needle = p.getString("value")
                    val found = if (ci) text.lowercase().contains(needle.lowercase()) else text.contains(needle)
                    if (found) hits += Hit(id)
                }
                "regex" -> {
                    val re = Pattern.compile(p.getString("value"), if (ci) Pattern.CASE_INSENSITIVE else 0)
                    val m = re.matcher(text)
                    while (m.find()) {
                        if (id == "LS-G1") {
                            // Allowlisted only when the whole 64-digit string equals a listed literal (exact, never a looser match).
                            val digits = m.group().removePrefix("0x").removePrefix("0X").lowercase()
                            if (digits in allowlist) continue
                        }
                        hits += Hit(id)
                        break
                    }
                }
                "wordlist-run" -> {
                    // A run of at least minRun BIP-39 words is a suspected phrase: manual review, which this test treats as a hit.
                    val min = p.getInt("minRun")
                    var run = 0
                    for (tok in Regex("[a-zA-Z]+").findAll(text).map { it.value.lowercase() }) {
                        run = if (tok in wordlist) run + 1 else 0
                        if (run >= min) {
                            hits += Hit(id)
                            break
                        }
                    }
                }
                // "fixture" (LS-F1): the numbers are per platform and are not in the spec file; not run here.
            }
        }
        return hits
    }

    private fun ids(hits: List<Hit>): Set<String> = hits.map { it.id }.toSet()

    /** Positive: the canary fixture is hit for each class (private key forms, phrase forms, the generic hex, and the wordlist run). */
    @Test
    fun thePositiveFixtureIsHitForEachClass() {
        val text = File("src/test/resources/log-scan/android-ls-f1-positive.txt").readText(Charsets.UTF_8)
        val hit = ids(scan(text))
        for (id in listOf("LS-K1", "LS-K2", "LS-M1", "LS-M4", "LS-G1")) {
            assertTrue("$id is hit by the positive fixture: $hit", id in hit)
        }
    }

    /** Negative: the real output of the three paths, as logcat prints it, and the artifacts they write, have no hits. */
    @Test
    fun theRealSyncPreReadAndDiscardOutputHasNoHits() {
        val hit = scan(realPathLogcat())
        assertEquals("no hits in the real output of sync, pre-read and discard: ${ids(hit)}", emptySet<String>(), ids(hit))
    }

    // LS-F1 (spec 55(3)): the names of the list, with the synthetic values of this Android SDK's own fixtures (see Ls1Values).

    /** Positive: the LS-F1 scan hits every present value in the canary (each in its own form, the hex, 0x hex and base64 forms). */
    @Test
    fun ls1PositiveFixtureIsHitForEveryPresentValue() {
        val values = Ls1Values.collect()
        val canary = File("src/test/resources/log-scan/android-ls-f1-positive.txt").readText(Charsets.UTF_8) +
            values.present.joinToString("\n") { v -> "01-01 00:00:00.009  1234  1234 D BeamioConetChat: ${v.name} " + v.forms().joinToString(" ") } + "\n"
        val hit = Ls1Values.scan(canary, values.present)
        assertEquals("every present LS-F1 value is hit", values.present.map { it.name }.toSet(), hit)
    }

    /** Negative: the real output of the three paths has no LS-F1 hit. */
    @Test
    fun ls1RealPathOutputHasNoHits() {
        val hit = Ls1Values.scan(realPathLogcat(), Ls1Values.collect().present)
        assertEquals("no LS-F1 hit in the real output", emptySet<String>(), hit)
    }

    /** The values that the Android SDK's own fixtures hold, and the names that do not apply to this end (LS-F1 list, spec 55(3)). */
    private object Ls1Values {
        class Value(val name: String, val text: String, val hex: Boolean) {
            /** The forms the spec names: hex, 0x hex, base64 (for text values, the text, its base64 and its hex as well). */
            fun forms(): List<String> {
                val bytes = if (hex) hexBytes(text) else text.toByteArray(Charsets.UTF_8)
                val h = bytes.joinToString("") { "%02x".format(it) }
                val b64 = java.util.Base64.getEncoder().encodeToString(bytes)
                return if (hex) listOf(h, "0x$h", b64) else listOf(text, h, "0x$h", b64)
            }
        }
        class Collected(val present: List<Value>, val absent: List<String>)

        private fun hexBytes(s: String): ByteArray {
            val clean = s.removePrefix("0x").removePrefix("0X")
            return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }

        private fun readJson(path: String): JSONObject = JSONObject(File(path).readText(Charsets.UTF_8))

        fun collect(): Collected {
            val present = mutableListOf<Value>()
            val absent = mutableListOf<String>()
            val d = readJson("../spec/derivation-vectors.v1.json")
            val inputs = d.getJSONObject("inputs")
            val d07 = d.getJSONArray("cases").let { arr -> (0 until arr.length()).map { arr.getJSONObject(it) }.first { it.getString("id") == "D-07" } }
            val d02 = d.getJSONArray("cases").let { arr -> (0 until arr.length()).map { arr.getJSONObject(it) }.first { it.getString("id") == "D-02" } }
            // DEK, K_idx, K_id: the D-07 expectation (the native derivation of the SDK's own vectors).
            val dek = d07.getJSONObject("expect").getString("dek")
            present += Value("DEK", dek, hex = true)
            present += Value("K_idx", d07.getJSONObject("expect").getString("kIdx"), hex = true)
            present += Value("K_id", d07.getJSONObject("expect").getString("kId"), hex = true)
            present += Value("indexEncKey", d02.getJSONObject("expect").getString("indexEncKey"), hex = true)
            // R_db: derived from the synthetic P with the SDK's own root derivation (LocalChatIds), never from a real account.
            val p = hexBytes(inputs.getString("P"))
            val rDb = LocalChatIds.rootDbFromPrivateKey(p, inputs.getString("eoa"), inputs.getString("workspace"))
            present += Value("R_db", rDb.joinToString("") { "%02x".format(it) }, hex = true)
            // channel.tk: the synthetic channel token of the derivation inputs (this end's name for it is inputs.tk).
            present += Value("channel.tk", inputs.getString("tk"), hex = true)
            // PGP synthetic passphrase of the PGP vectors (ECC key, with passphrase).
            present += Value("PGP 合成口令", readJson("../spec/pgp-native-vectors.v1.json").getJSONObject("keys").getJSONObject("ecc-pass").getString("passphrase"), hex = false)
            // Recovery code (the test value of the recovery vectors, base62 form).
            val rec = readJson("../spec/native-recovery-vectors.v1.json").getJSONArray("cases").getJSONObject(0).getJSONArray("steps").getJSONObject(0).getJSONObject("a")
            present += Value("恢复码测试值", rec.getString("code"), hex = false)
            // Not on this end: R_proto (the protocol root; its value is in the external sendkey fixture only) and S (no synthetic value in the SDK).
            // S and R_proto (spec 55(3)): S is the protocol root (the EIP-191 signature over "beamio.chat.history.v1|224422|" + eoa) and
            // R_proto = keccak256(utf8(S)). Both values are in the SDK's own synthetic vector D-01 (expect.S, expect.RPROTO).
            val d01 = d.getJSONArray("cases").let { arr -> (0 until arr.length()).map { arr.getJSONObject(it) }.first { it.getString("id") == "D-01" } }
            present += Value("S", d01.getJSONObject("expect").getString("S"), hex = true)
            present += Value("R_proto", d01.getJSONObject("expect").getString("RPROTO"), hex = true)
            return Collected(present, absent)
        }

        /** The names whose forms are in [text] (LS-F1: a hit is any form, hex forms case-insensitive). */
        fun scan(text: String, values: List<Value>): Set<String> {
            val hit = mutableSetOf<String>()
            val lower = text.lowercase()
            for (v in values) {
                for (form in v.forms()) {
                    val found = if (form.startsWith("0x") || v.hex) lower.contains(form.lowercase()) else text.contains(form)
                    if (found) {
                        hit += v.name
                        break
                    }
                }
            }
            return hit
        }
    }

    /**
     * The logcat-style output of the three paths and the artifacts of a real run. The log lines are the strings the production formatting
     * functions return (the same functions the module's Log.i calls use). What is not run on the JVM is the Log.i call and the logcat buffer:
     * those are device-only (C-5). The lines are not hand-written here.
     */
    private fun realPathLogcat(): String {
        val lines = mutableListOf<String>()
        lines += NativeSyncAck.refusedLogLine("untrusted_source")
        lines += NativeSyncAck.staleLogLine()
        for (o in NativeWalletVault.SyncOutcome.values()) lines += NativeSyncAck.logLine(o)
        lines += NativeSyncAck.prereadLogLine(true)
        lines += NativeSyncAck.prereadLogLine(false)
        for (o in NativeWalletVault.DiscardOutcome.values()) lines += PwaEmptySignal.discardLogLine(o)
        // The vault artifacts of a real run: a sync that writes, then a discard of a key-only record.
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
        val key = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(key))
        NativeWalletVault(wrap, files).syncPhrase(eoa, key, phrase)
        val other = checkNotNull(MnemonicDerivation.deriveKey("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
        val otherEoa = checkNotNull(WalletAddress.fromPrivateKey(other))
        NativeWalletVault(wrap, files).importKey(otherEoa, other)
        NativeWalletVault(wrap, files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = "explicit_empty")
        lines += "artifact audit=" + (files.read(NativeWalletVault.DISCARD_AUDIT)?.let { String(it, Charsets.UTF_8) } ?: "")
        lines += "artifact intent=" + (files.read(NativeWalletVault.DISCARD_INTENT)?.let { String(it, Charsets.UTF_8) } ?: "")
        // logcat prints each line with the tag and a timestamp prefix.
        return lines.mapIndexed { i, l -> "01-01 00:00:%02d.%03d  1234  1234 I BeamioConetChat: %s".format(i % 60, i, l) }.joinToString("\n")
    }

}
