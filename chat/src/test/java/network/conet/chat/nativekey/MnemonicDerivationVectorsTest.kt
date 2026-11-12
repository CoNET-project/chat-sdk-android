package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * Spec §25.26.1 and §25.26.2: the BIP-39 derivation against `spec/mnemonic-derivation-vectors.v1.json`
 * (sha256 ec646d4d…4230), 14 cases, MD-1 to MD-14. Every valid case must give its `eoa`; every invalid case
 * must return no key. Only public BIP-39 test vectors are used.
 */
class MnemonicDerivationVectorsTest {
    private val bytes = File(System.getenv("MNEMONIC_VECTORS") ?: "../spec/mnemonic-derivation-vectors.v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    @Test
    fun vectorFileIsTheCanonicalOne() {
        assertEquals("ec646d4d63201059582d93620e0e7ef2bee8bbe44d5822570c2d7ce40d274230", sha256Hex(bytes))
    }

    @Test
    fun wordlistIsTheBip39EnglishList() {
        val file = File("../spec/bip39-english.txt").readBytes()
        assertEquals("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", sha256Hex(file))
        assertEquals(2048, Bip39English.WORDS.size)
        assertEquals(Bip39English.WORDS.joinToString("\n") + "\n", String(file, Charsets.UTF_8))
    }

    @Test
    fun fourteenDerivationCasesMatch() {
        val cases = v.getJSONArray("derivation")
        assertEquals(14, cases.length())
        var valid = 0
        var invalid = 0
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val expect = c.getJSONObject("expect")
            val key = MnemonicDerivation.deriveKey(c.getString("input"))
            if (expect.getString("code") == "ok") {
                valid++
                assertNotNull("$id should derive a key", key)
                try {
                    assertEquals("$id eoa", expect.getString("eoa"), WalletAddress.fromPrivateKey(key!!))
                } finally {
                    key?.fill(0)
                }
            } else {
                invalid++
                // Invalid input yields no key at all (MD-13 included: the hex key is refused, nothing is echoed).
                assertNull("$id must not derive", key)
            }
        }
        assertEquals(6, valid)
        assertEquals(8, invalid)
    }
}
