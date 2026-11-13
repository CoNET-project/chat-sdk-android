package network.conet.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * Keeps the licence notice in step with the bundled JavaScript (LGPL-3.0+ for OpenPGP.js, MIT for ethers). If a bundled file
 * changes, this test fails until THIRD_PARTY_NOTICES.txt and the pinned hashes are updated together.
 */
class ThirdPartyNoticesTest {
    private val assets = File("src/main/assets/ChatCrypto")

    private fun sha256(f: File): String =
        MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }

    @Test
    fun bundledLibrariesAreTheUpstreamVersionsTheNoticeNames() {
        assertEquals("46d3e5b6bfe4f0d19b44fd3aa826ac1c67174e95a97be082a3982160b6caae4e", sha256(File(assets, "openpgp.min.js")))
        assertEquals("9a85a5aa81305f85e6546452fd2093a8a68932bed3cec4f6491e4d031a90bc95", sha256(File(assets, "ethers.umd.min.js")))
    }

    @Test
    fun licenceTextsArePresentAndUnmodified() {
        val lic = File(assets, "licenses")
        assertEquals("e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118", sha256(File(lic, "LGPL-3.0-openpgpjs-6.3.0-LICENSE.txt")))
        assertEquals("8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903", sha256(File(lic, "GPL-3.0-COPYING.txt")))
        assertEquals("44eea86637405118248327fbe9d9fa95d04c7a57221c7e8c155f736db9f1b612", sha256(File(lic, "MIT-ethers-6.16.0-LICENSE.txt")))
    }

    @Test
    fun theNoticeNamesEveryFileAndItsHash() {
        val notice = File(assets, "licenses/THIRD_PARTY_NOTICES.txt").readText(Charsets.UTF_8)
        for (sum in listOf(
            "46d3e5b6bfe4f0d19b44fd3aa826ac1c67174e95a97be082a3982160b6caae4e",
            "9a85a5aa81305f85e6546452fd2093a8a68932bed3cec4f6491e4d031a90bc95",
            "e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118",
            "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903",
            "44eea86637405118248327fbe9d9fa95d04c7a57221c7e8c155f736db9f1b612",
        )) {
            assertTrue("notice must state $sum", notice.contains(sum))
        }
        assertTrue(notice.contains("LGPL-3.0+"))
        assertTrue(notice.contains("MIT"))
    }
}
