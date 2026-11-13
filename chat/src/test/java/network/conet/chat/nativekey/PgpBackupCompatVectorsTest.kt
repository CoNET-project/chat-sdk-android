package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * P-IMP-PGP option A: the PWA's encrypted PGP backup, restored natively (`pgp-backup-compat-vectors.v1.json`, spec copy,
 * sha256 pinned to SHA256-CURRENT). All material is synthetic (public test mnemonics, synthetic PGP keys, no passphrase).
 * The vectors are not edited to suit the implementation; the divergence D-2 is recorded, not changed.
 */
class PgpBackupCompatVectorsTest {
    private val raw = File(System.getenv("PGP_BACKUP_VECTORS") ?: "../spec/pgp-backup-compat-vectors.v1.json").readBytes()
    private val vectors = JSONObject(String(raw, Charsets.UTF_8))

    private fun sha256Hex(b: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun positive(id: String): JSONObject {
        val arr = vectors.getJSONArray("positives")
        return (0 until arr.length()).map { arr.getJSONObject(it) }.first { it.getString("id") == id }
    }

    private fun negative(id: String): JSONObject {
        val arr = vectors.getJSONArray("negatives")
        return (0 until arr.length()).map { arr.getJSONObject(it) }.first { it.getString("id") == id }
    }

    /** The mnemonic each positive's account is derived from (the public BIP-39 test vectors named in the file). */
    private fun mnemonicFor(id: String): String = when (id) {
        "P-1" -> "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        "P-2" -> "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        else -> error("no mnemonic for $id")
    }

    @Test
    fun theVectorFileIsTheCurrentCopy() {
        assertEquals("7c1515fc8f7468386db8195348f5e784caa77d1462dd33f997b865c2d3b8850c", sha256Hex(raw))  // r3l: D-1, D-2 strict
    }

    @Test
    fun theMnemonicAccountsMatchThePwaPasswordStrings() {
        for (id in listOf("P-1", "P-2")) {
            val p = positive(id)
            val key = MnemonicDerivation.deriveKey(mnemonicFor(id))
            assertNotNull("$id: mnemonic", key)
            try {
                assertEquals("$id: password string", p.getString("passwordString"), NativePgpBackup.passwordString(key!!))
                assertTrue("$id: address", WalletAddress.fromPrivateKey(key)!!.equals(p.getString("eoa"), ignoreCase = true))
            } finally {
                key?.fill(0)
            }
        }
    }

    @Test
    fun thePositivesDecryptToTheExactArmorAndTheExpectedIdentity() {
        for (id in listOf("P-1", "P-2")) {
            val p = positive(id)
            val backup = p.getJSONObject("backup")
            val pgp = p.getJSONObject("pgp")
            val armor = NativePgpBackup.decryptArmor(p.getString("passwordString"), backup.getString("base64"))
            assertNotNull("$id: decrypt", armor)
            assertEquals("$id: armor bytes", pgp.getString("privateArmorSha256"), sha256Hex(armor!!))
            assertEquals("$id: armor text", pgp.getString("privateArmor"), String(armor, Charsets.UTF_8))
            assertEquals("$id: base64 text sha", backup.getString("base64TextSha256"), sha256Hex(backup.getString("base64").toByteArray(Charsets.US_ASCII)))
            val secret = NativePgp.parseSecret(String(armor, Charsets.UTF_8))
            assertNotNull("$id: parse", secret)
            assertEquals("$id: primary fingerprint", p.getJSONObject("expect").getString("primaryFingerprint"), secret!!.fingerprint.uppercase())
            assertEquals("$id: subkey key id", p.getJSONObject("expect").getString("subkeyKeyID"), NativePgpBackup.subkeyKeyId(secret))
        }
    }

    @Test
    fun theNegativesAllFailToDecrypt() {
        val arr = vectors.getJSONArray("negatives")
        for (i in 0 until arr.length()) {
            val n = arr.getJSONObject(i)
            val id = n.getString("id")
            val result = NativePgpBackup.decryptArmor(n.getString("passwordString"), n.getJSONObject("backup").getString("base64"))
            assertNull("$id must fail", result)
        }
    }

    /**
     * Divergence D-2 (recorded, not changed). The vector's native expectation is `decrypt_failed`; this implementation
     * refuses the whitespace. The PWA's own result is `ok_lenient` per the vector (P-IMP-PGP decision pending). The check
     * below confirms the strict refusal and that the same blob without the newline decrypts.
     */
    @Test
    fun divergenceD2IsStrictRefusalAndTheSameBlobWithoutWhitespaceDecrypts() {
        val d2 = (0 until vectors.getJSONArray("divergences").length())
            .map { vectors.getJSONArray("divergences").getJSONObject(it) }
            .first { it.getString("id") == "D-2" }
        val expectNative = d2.getJSONObject("expect").getString("native")
        assertEquals("decrypt_failed", expectNative)
        val withNewline = d2.getJSONObject("backup").getString("base64")
        val pw = d2.getString("passwordString")
        assertTrue(withNewline.contains('\n'))
        assertNull("native strict decode", NativePgpBackup.decryptArmor(pw, withNewline))
        val stripped = withNewline.filter { !it.isWhitespace() }
        assertNotNull("the same blob without whitespace", NativePgpBackup.decryptArmor(pw, stripped))
    }
}
