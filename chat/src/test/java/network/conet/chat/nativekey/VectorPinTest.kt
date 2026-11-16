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
            "abf914cf524fa9ea9c6af7262376269713964b93a9e654a0fe9368de8be6b36b",
            sha256("../spec/pgp-migration-vectors.v1.json"),
        )
    }

    @Test
    fun pgpMigrationVectorsV2IsPinned() {
        assertEquals(
            "cce7b834404dd8423e78d3c2770bf964c630b1627394664eeab42121fcff55b7",
            sha256("../spec/pgp-migration-vectors.v2.json"),
        )
    }
}
