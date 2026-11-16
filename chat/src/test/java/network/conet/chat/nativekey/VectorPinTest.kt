package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * The pinned vector files (Y.100 ruling, 2026-11-16): the full 64-digit sha256 of each file in `spec/`. A changed file fails here before any
 * vector test runs. v1 06199263… and v2 26655ea3… are withdrawn.
 */
class VectorPinTest {
    private fun sha256(path: String): String =
        MessageDigest.getInstance("SHA-256").digest(File(path).readBytes()).joinToString("") { "%02x".format(it) }

    @Test
    fun pgpMigrationVectorsV1IsPinned() {
        assertEquals(
            "77af6eefbc4faa719cc82a7d19073da7aa30011ad2f69af70e3f730c1f61d8d3",
            sha256("../spec/pgp-migration-vectors.v1.json"),
        )
    }

    @Test
    fun pgpMigrationVectorsV2IsPinned() {
        assertEquals(
            "5f9952f32e7cac079e1d4fd146a41b6f0a1e8eff417d852d23babdc963e1dc75",
            sha256("../spec/pgp-migration-vectors.v2.json"),
        )
    }
}
