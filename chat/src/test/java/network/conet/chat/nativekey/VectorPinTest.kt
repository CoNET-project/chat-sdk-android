package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * The pinned vector files (Y.111, 2026-11-16): the full 64-digit sha256 of each file in `spec/`. A changed file fails here before any
 * vector test runs. r2.5.12 (AK-60 expect migrating -> account_record_missing): v1 b4f62c4a…, v2 b5ae750a…; earlier pins are withdrawn.
 */
class VectorPinTest {
    private fun sha256(path: String): String =
        MessageDigest.getInstance("SHA-256").digest(File(path).readBytes()).joinToString("") { "%02x".format(it) }

    @Test
    fun pgpMigrationVectorsV1IsPinned() {
        assertEquals(
            "b4f62c4adb40eea4d1bcff40e2d389f39f1201e46d5ba023bb4c8911a268d313",
            sha256("../spec/pgp-migration-vectors.v1.json"),
        )
    }

    @Test
    fun pgpMigrationVectorsV2IsPinned() {
        assertEquals(
            "b5ae750a9f110b23ee29f254cf6f6ca9dfd3a4087833a10bbf8853a2c324af44",
            sha256("../spec/pgp-migration-vectors.v2.json"),
        )
    }

    /** r2.5.19 (60): the NP vectors (13 cases), pinned with the spec bdd451c5…. */
    @Test
    fun mnemonicPrereadVectorsArePinned() {
        assertEquals(
            "c90b54897827d303d0b9566595b498685d024cefe3ae062ba39e2bec4e4039f9",
            sha256("../spec/mnemonic-preread-vectors.v1.json"),
        )
    }

    /** r2.5.19 (59(5)): native-open vectors, nativeImportOpen answers unknown_command. */
    @Test
    fun nativeOpenVectorsArePinned() {
        assertEquals(
            "49ceb083343b028bdf1d7d5e5316ce716a60ef4459441ce50ec14d251a22079f",
            sha256("../spec/native-open-vectors.v1.json"),
        )
    }
}
