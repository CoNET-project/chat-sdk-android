package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * The pinned vector files (Y.111, 2026-11-16): the full 64-digit sha256 of each file in `spec/`. A changed file fails here before any
 * vector test runs. The Y.100 pins 77af6eef… (v1) and 5f9952f3… (v2) are withdrawn.
 */
class VectorPinTest {
    private fun sha256(path: String): String =
        MessageDigest.getInstance("SHA-256").digest(File(path).readBytes()).joinToString("") { "%02x".format(it) }

    @Test
    fun pgpMigrationVectorsV1IsPinned() {
        assertEquals(
            "caa2f9b681600a2df75e403b203f235fe73836e8c3145ab74c77c2bc27455b37",
            sha256("../spec/pgp-migration-vectors.v1.json"),
        )
    }

    @Test
    fun pgpMigrationVectorsV2IsPinned() {
        assertEquals(
            "533b8087d55cd3751529432693e26395ccadaefda470e4002689be08431646fe",
            sha256("../spec/pgp-migration-vectors.v2.json"),
        )
    }
}
